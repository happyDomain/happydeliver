// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package analyzer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

// DNSAnalyzer analyzes DNS records for email domains
type DNSAnalyzer struct {
	Timeout  time.Duration
	resolver *net.Resolver
}

// NewDNSAnalyzer creates a new DNS analyzer with configurable timeout
func NewDNSAnalyzer(timeout time.Duration) *DNSAnalyzer {
	if timeout == 0 {
		timeout = 10 * time.Second // Default timeout
	}
	return &DNSAnalyzer{
		Timeout: timeout,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// DNSResults represents DNS validation results for an email
type DNSResults struct {
	Domain      string
	MXRecords   []MXRecord
	SPFRecord   *SPFRecord
	DKIMRecords []DKIMRecord
	DMARCRecord *DMARCRecord
	BIMIRecord  *BIMIRecord
	Errors      []string
}

// MXRecord represents an MX record
type MXRecord struct {
	Host     string
	Priority uint16
	Valid    bool
	Error    string
}

// SPFRecord represents an SPF record
type SPFRecord struct {
	Record string
	Valid  bool
	Error  string
}

// DKIMRecord represents a DKIM record
type DKIMRecord struct {
	Selector string
	Domain   string
	Record   string
	Valid    bool
	Error    string
}

// DMARCRecord represents a DMARC record
type DMARCRecord struct {
	Record string
	Policy string // none, quarantine, reject
	Valid  bool
	Error  string
}

// BIMIRecord represents a BIMI record
type BIMIRecord struct {
	Selector string
	Domain   string
	Record   string
	LogoURL  string // URL to the brand logo (SVG)
	VMCURL   string // URL to Verified Mark Certificate (optional)
	Valid    bool
	Error    string
}

// AnalyzeDNS performs DNS validation for the email's domain
func (d *DNSAnalyzer) AnalyzeDNS(email *EmailMessage, authResults *api.AuthenticationResults) *DNSResults {
	// Extract domain from From address
	domain := d.extractDomain(email)
	if domain == "" {
		return &DNSResults{
			Errors: []string{"Unable to extract domain from email"},
		}
	}

	results := &DNSResults{
		Domain: domain,
	}

	// Check MX records
	results.MXRecords = d.checkMXRecords(domain)

	// Check SPF record
	results.SPFRecord = d.checkSPFRecord(domain)

	// Check DKIM records (from authentication results)
	if authResults != nil && authResults.Dkim != nil {
		for _, dkim := range *authResults.Dkim {
			if dkim.Domain != nil && dkim.Selector != nil {
				dkimRecord := d.checkDKIMRecord(*dkim.Domain, *dkim.Selector)
				if dkimRecord != nil {
					results.DKIMRecords = append(results.DKIMRecords, *dkimRecord)
				}
			}
		}
	}

	// Check DMARC record
	results.DMARCRecord = d.checkDMARCRecord(domain)

	// Check BIMI record (using default selector)
	results.BIMIRecord = d.checkBIMIRecord(domain, "default")

	return results
}

// extractDomain extracts the domain from the email's From address
func (d *DNSAnalyzer) extractDomain(email *EmailMessage) string {
	if email.From != nil && email.From.Address != "" {
		parts := strings.Split(email.From.Address, "@")
		if len(parts) == 2 {
			return strings.ToLower(strings.TrimSpace(parts[1]))
		}
	}
	return ""
}

// checkMXRecords looks up MX records for a domain
func (d *DNSAnalyzer) checkMXRecords(domain string) []MXRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	mxRecords, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		return []MXRecord{
			{
				Valid: false,
				Error: fmt.Sprintf("Failed to lookup MX records: %v", err),
			},
		}
	}

	if len(mxRecords) == 0 {
		return []MXRecord{
			{
				Valid: false,
				Error: "No MX records found",
			},
		}
	}

	var results []MXRecord
	for _, mx := range mxRecords {
		results = append(results, MXRecord{
			Host:     mx.Host,
			Priority: mx.Pref,
			Valid:    true,
		})
	}

	return results
}

// checkSPFRecord looks up and validates SPF record for a domain
func (d *DNSAnalyzer) checkSPFRecord(domain string) *SPFRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return &SPFRecord{
			Valid: false,
			Error: fmt.Sprintf("Failed to lookup TXT records: %v", err),
		}
	}

	// Find SPF record (starts with "v=spf1")
	var spfRecord string
	spfCount := 0
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecord = txt
			spfCount++
		}
	}

	if spfCount == 0 {
		return &SPFRecord{
			Valid: false,
			Error: "No SPF record found",
		}
	}

	if spfCount > 1 {
		return &SPFRecord{
			Record: spfRecord,
			Valid:  false,
			Error:  "Multiple SPF records found (RFC violation)",
		}
	}

	// Basic validation
	if !d.validateSPF(spfRecord) {
		return &SPFRecord{
			Record: spfRecord,
			Valid:  false,
			Error:  "SPF record appears malformed",
		}
	}

	return &SPFRecord{
		Record: spfRecord,
		Valid:  true,
	}
}

// validateSPF performs basic SPF record validation
func (d *DNSAnalyzer) validateSPF(record string) bool {
	// Must start with v=spf1
	if !strings.HasPrefix(record, "v=spf1") {
		return false
	}

	// Check for common syntax issues
	// Should have a final mechanism (all, +all, -all, ~all, ?all)
	validEndings := []string{" all", " +all", " -all", " ~all", " ?all"}
	hasValidEnding := false
	for _, ending := range validEndings {
		if strings.HasSuffix(record, ending) {
			hasValidEnding = true
			break
		}
	}

	return hasValidEnding
}

// checkDKIMRecord looks up and validates DKIM record for a domain and selector
func (d *DNSAnalyzer) checkDKIMRecord(domain, selector string) *DKIMRecord {
	// DKIM records are at: selector._domainkey.domain
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dkimDomain)
	if err != nil {
		return &DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    fmt.Sprintf("Failed to lookup DKIM record: %v", err),
		}
	}

	if len(txtRecords) == 0 {
		return &DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    "No DKIM record found",
		}
	}

	// Concatenate all TXT record parts (DKIM can be split)
	dkimRecord := strings.Join(txtRecords, "")

	// Basic validation - should contain "v=DKIM1" and "p=" (public key)
	if !d.validateDKIM(dkimRecord) {
		return &DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Record:   dkimRecord,
			Valid:    false,
			Error:    "DKIM record appears malformed",
		}
	}

	return &DKIMRecord{
		Selector: selector,
		Domain:   domain,
		Record:   dkimRecord,
		Valid:    true,
	}
}

// validateDKIM performs basic DKIM record validation
func (d *DNSAnalyzer) validateDKIM(record string) bool {
	// Should contain p= tag (public key)
	if !strings.Contains(record, "p=") {
		return false
	}

	// Often contains v=DKIM1 but not required
	// If v= is present, it should be DKIM1
	if strings.Contains(record, "v=") && !strings.Contains(record, "v=DKIM1") {
		return false
	}

	return true
}

// checkDMARCRecord looks up and validates DMARC record for a domain
func (d *DNSAnalyzer) checkDMARCRecord(domain string) *DMARCRecord {
	// DMARC records are at: _dmarc.domain
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return &DMARCRecord{
			Valid: false,
			Error: fmt.Sprintf("Failed to lookup DMARC record: %v", err),
		}
	}

	// Find DMARC record (starts with "v=DMARC1")
	var dmarcRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcRecord = txt
			break
		}
	}

	if dmarcRecord == "" {
		return &DMARCRecord{
			Valid: false,
			Error: "No DMARC record found",
		}
	}

	// Extract policy
	policy := d.extractDMARCPolicy(dmarcRecord)

	// Basic validation
	if !d.validateDMARC(dmarcRecord) {
		return &DMARCRecord{
			Record: dmarcRecord,
			Policy: policy,
			Valid:  false,
			Error:  "DMARC record appears malformed",
		}
	}

	return &DMARCRecord{
		Record: dmarcRecord,
		Policy: policy,
		Valid:  true,
	}
}

// extractDMARCPolicy extracts the policy from a DMARC record
func (d *DNSAnalyzer) extractDMARCPolicy(record string) string {
	// Look for p=none, p=quarantine, or p=reject
	re := regexp.MustCompile(`p=(none|quarantine|reject)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

// validateDMARC performs basic DMARC record validation
func (d *DNSAnalyzer) validateDMARC(record string) bool {
	// Must start with v=DMARC1
	if !strings.HasPrefix(record, "v=DMARC1") {
		return false
	}

	// Must have a policy tag
	if !strings.Contains(record, "p=") {
		return false
	}

	return true
}

// checkBIMIRecord looks up and validates BIMI record for a domain and selector
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector string) *BIMIRecord {
	// BIMI records are at: selector._bimi.domain
	bimiDomain := fmt.Sprintf("%s._bimi.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, bimiDomain)
	if err != nil {
		return &BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    fmt.Sprintf("Failed to lookup BIMI record: %v", err),
		}
	}

	if len(txtRecords) == 0 {
		return &BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    "No BIMI record found",
		}
	}

	// Concatenate all TXT record parts (BIMI can be split)
	bimiRecord := strings.Join(txtRecords, "")

	// Extract logo URL and VMC URL
	logoURL := d.extractBIMITag(bimiRecord, "l")
	vmcURL := d.extractBIMITag(bimiRecord, "a")

	// Basic validation - should contain "v=BIMI1" and "l=" (logo URL)
	if !d.validateBIMI(bimiRecord) {
		return &BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Record:   bimiRecord,
			LogoURL:  logoURL,
			VMCURL:   vmcURL,
			Valid:    false,
			Error:    "BIMI record appears malformed",
		}
	}

	return &BIMIRecord{
		Selector: selector,
		Domain:   domain,
		Record:   bimiRecord,
		LogoURL:  logoURL,
		VMCURL:   vmcURL,
		Valid:    true,
	}
}

// extractBIMITag extracts a tag value from a BIMI record
func (d *DNSAnalyzer) extractBIMITag(record, tag string) string {
	// Look for tag=value pattern
	re := regexp.MustCompile(tag + `=([^;]+)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// validateBIMI performs basic BIMI record validation
func (d *DNSAnalyzer) validateBIMI(record string) bool {
	// Must start with v=BIMI1
	if !strings.HasPrefix(record, "v=BIMI1") {
		return false
	}

	// Must have a logo URL tag (l=)
	if !strings.Contains(record, "l=") {
		return false
	}

	return true
}

// GenerateDNSChecks generates check results for DNS validation
func (d *DNSAnalyzer) GenerateDNSChecks(results *DNSResults) []api.Check {
	var checks []api.Check

	if results == nil {
		return checks
	}

	// MX record check
	checks = append(checks, d.generateMXCheck(results))

	// SPF record check
	if results.SPFRecord != nil {
		checks = append(checks, d.generateSPFCheck(results.SPFRecord))
	}

	// DKIM record checks
	for _, dkim := range results.DKIMRecords {
		checks = append(checks, d.generateDKIMCheck(&dkim))
	}

	// DMARC record check
	if results.DMARCRecord != nil {
		checks = append(checks, d.generateDMARCCheck(results.DMARCRecord))
	}

	// BIMI record check (optional)
	if results.BIMIRecord != nil {
		checks = append(checks, d.generateBIMICheck(results.BIMIRecord))
	}

	return checks
}

// generateMXCheck creates a check for MX records
func (d *DNSAnalyzer) generateMXCheck(results *DNSResults) api.Check {
	check := api.Check{
		Category: api.Dns,
		Name:     "MX Records",
	}

	if len(results.MXRecords) == 0 || !results.MXRecords[0].Valid {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Critical)

		if len(results.MXRecords) > 0 && results.MXRecords[0].Error != "" {
			check.Message = results.MXRecords[0].Error
		} else {
			check.Message = "No valid MX records found"
		}
		check.Advice = api.PtrTo("Configure MX records for your domain to receive email")
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Severity = api.PtrTo(api.Info)
		check.Message = fmt.Sprintf("Found %d valid MX record(s)", len(results.MXRecords))

		// Add details about MX records
		var mxList []string
		for _, mx := range results.MXRecords {
			mxList = append(mxList, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Priority))
		}
		details := strings.Join(mxList, ", ")
		check.Details = &details
		check.Advice = api.PtrTo("Your MX records are properly configured")
	}

	return check
}

// generateSPFCheck creates a check for SPF records
func (d *DNSAnalyzer) generateSPFCheck(spf *SPFRecord) api.Check {
	check := api.Check{
		Category: api.Dns,
		Name:     "SPF Record",
	}

	if !spf.Valid {
		// If no record exists at all, it's a failure
		if spf.Record == "" {
			check.Status = api.CheckStatusFail
			check.Score = 0.0
			check.Message = spf.Error
			check.Severity = api.PtrTo(api.High)
			check.Advice = api.PtrTo("Configure an SPF record for your domain to improve deliverability")
		} else {
			// If record exists but is invalid, it's a warning
			check.Status = api.CheckStatusWarn
			check.Score = 0.5
			check.Message = "SPF record found but appears invalid"
			check.Severity = api.PtrTo(api.Medium)
			check.Advice = api.PtrTo("Review and fix your SPF record syntax")
			check.Details = &spf.Record
		}
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "Valid SPF record found"
		check.Severity = api.PtrTo(api.Info)
		check.Details = &spf.Record
		check.Advice = api.PtrTo("Your SPF record is properly configured")
	}

	return check
}

// generateDKIMCheck creates a check for DKIM records
func (d *DNSAnalyzer) generateDKIMCheck(dkim *DKIMRecord) api.Check {
	check := api.Check{
		Category: api.Dns,
		Name:     fmt.Sprintf("DKIM Record (%s)", dkim.Selector),
	}

	if !dkim.Valid {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = fmt.Sprintf("DKIM record not found or invalid: %s", dkim.Error)
		check.Severity = api.PtrTo(api.High)
		check.Advice = api.PtrTo("Ensure DKIM record is published in DNS for the selector used")
		details := fmt.Sprintf("Selector: %s, Domain: %s", dkim.Selector, dkim.Domain)
		check.Details = &details
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "Valid DKIM record found"
		check.Severity = api.PtrTo(api.Info)
		details := fmt.Sprintf("Selector: %s, Domain: %s", dkim.Selector, dkim.Domain)
		check.Details = &details
		check.Advice = api.PtrTo("Your DKIM record is properly published")
	}

	return check
}

// generateDMARCCheck creates a check for DMARC records
func (d *DNSAnalyzer) generateDMARCCheck(dmarc *DMARCRecord) api.Check {
	check := api.Check{
		Category: api.Dns,
		Name:     "DMARC Record",
	}

	if !dmarc.Valid {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = dmarc.Error
		check.Severity = api.PtrTo(api.High)
		check.Advice = api.PtrTo("Configure a DMARC record for your domain to improve deliverability and prevent spoofing")
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = fmt.Sprintf("Valid DMARC record found with policy: %s", dmarc.Policy)
		check.Severity = api.PtrTo(api.Info)
		check.Details = &dmarc.Record

		// Provide advice based on policy
		switch dmarc.Policy {
		case "none":
			advice := "DMARC policy is set to 'none' (monitoring only). Consider upgrading to 'quarantine' or 'reject' for better protection"
			check.Advice = &advice
		case "quarantine":
			advice := "DMARC policy is set to 'quarantine'. This provides good protection"
			check.Advice = &advice
		case "reject":
			advice := "DMARC policy is set to 'reject'. This provides the strongest protection"
			check.Advice = &advice
		default:
			advice := "Your DMARC record is properly configured"
			check.Advice = &advice
		}
	}

	return check
}

// generateBIMICheck creates a check for BIMI records
func (d *DNSAnalyzer) generateBIMICheck(bimi *BIMIRecord) api.Check {
	check := api.Check{
		Category: api.Dns,
		Name:     "BIMI Record",
	}

	if !bimi.Valid {
		// BIMI is optional, so missing record is just informational
		if bimi.Record == "" {
			check.Status = api.CheckStatusInfo
			check.Score = 0.0
			check.Message = "No BIMI record found (optional)"
			check.Severity = api.PtrTo(api.Low)
			check.Advice = api.PtrTo("BIMI is optional. Consider implementing it to display your brand logo in supported email clients. Requires enforced DMARC policy (p=quarantine or p=reject)")
		} else {
			// If record exists but is invalid
			check.Status = api.CheckStatusWarn
			check.Score = 0.0
			check.Message = fmt.Sprintf("BIMI record found but invalid: %s", bimi.Error)
			check.Severity = api.PtrTo(api.Low)
			check.Advice = api.PtrTo("Review and fix your BIMI record syntax. Ensure it contains v=BIMI1 and a valid logo URL (l=)")
			check.Details = &bimi.Record
		}
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.0 // BIMI doesn't contribute to score (branding feature)
		check.Message = "Valid BIMI record found"
		check.Severity = api.PtrTo(api.Info)

		// Build details with logo and VMC URLs
		var detailsParts []string
		detailsParts = append(detailsParts, fmt.Sprintf("Selector: %s", bimi.Selector))
		if bimi.LogoURL != "" {
			detailsParts = append(detailsParts, fmt.Sprintf("Logo URL: %s", bimi.LogoURL))
		}
		if bimi.VMCURL != "" {
			detailsParts = append(detailsParts, fmt.Sprintf("VMC URL: %s", bimi.VMCURL))
			check.Advice = api.PtrTo("Your BIMI record is properly configured with a Verified Mark Certificate")
		} else {
			check.Advice = api.PtrTo("Your BIMI record is properly configured. Consider adding a Verified Mark Certificate (VMC) for enhanced trust")
		}

		details := strings.Join(detailsParts, ", ")
		check.Details = &details
	}

	return check
}
