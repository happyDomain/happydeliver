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

// AnalyzeDNS performs DNS validation for the email's domain
func (d *DNSAnalyzer) AnalyzeDNS(email *EmailMessage, authResults *api.AuthenticationResults) *api.DNSResults {
	// Extract domain from From address
	domain := d.extractDomain(email)
	if domain == "" {
		return &api.DNSResults{
			Errors: &[]string{"Unable to extract domain from email"},
		}
	}

	results := &api.DNSResults{
		Domain: domain,
	}

	// Check MX records
	results.MxRecords = d.checkMXRecords(domain)

	// Check SPF records (including includes)
	results.SpfRecords = d.checkSPFRecords(domain)

	// Check DKIM records (from authentication results)
	if authResults != nil && authResults.Dkim != nil {
		for _, dkim := range *authResults.Dkim {
			if dkim.Domain != nil && dkim.Selector != nil {
				dkimRecord := d.checkDKIMRecord(*dkim.Domain, *dkim.Selector)
				if dkimRecord != nil {
					if results.DkimRecords == nil {
						results.DkimRecords = new([]api.DKIMRecord)
					}
					*results.DkimRecords = append(*results.DkimRecords, *dkimRecord)
				}
			}
		}
	}

	// Check DMARC record
	results.DmarcRecord = d.checkDMARCRecord(domain)

	// Check BIMI record (using default selector)
	results.BimiRecord = d.checkBIMIRecord(domain, "default")

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
func (d *DNSAnalyzer) checkMXRecords(domain string) *[]api.MXRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	mxRecords, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		return &[]api.MXRecord{
			{
				Valid: false,
				Error: api.PtrTo(fmt.Sprintf("Failed to lookup MX records: %v", err)),
			},
		}
	}

	if len(mxRecords) == 0 {
		return &[]api.MXRecord{
			{
				Valid: false,
				Error: api.PtrTo("No MX records found"),
			},
		}
	}

	var results []api.MXRecord
	for _, mx := range mxRecords {
		results = append(results, api.MXRecord{
			Host:     mx.Host,
			Priority: mx.Pref,
			Valid:    true,
		})
	}

	return &results
}

// checkSPFRecords looks up and validates SPF records for a domain, including resolving include: directives
func (d *DNSAnalyzer) checkSPFRecords(domain string) *[]api.SPFRecord {
	visited := make(map[string]bool)
	return d.resolveSPFRecords(domain, visited, 0)
}

// resolveSPFRecords recursively resolves SPF records including include: directives
func (d *DNSAnalyzer) resolveSPFRecords(domain string, visited map[string]bool, depth int) *[]api.SPFRecord {
	const maxDepth = 10 // Prevent infinite recursion

	if depth > maxDepth {
		return &[]api.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  api.PtrTo("Maximum SPF include depth exceeded"),
			},
		}
	}

	// Prevent circular references
	if visited[domain] {
		return &[]api.SPFRecord{}
	}
	visited[domain] = true

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return &[]api.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  api.PtrTo(fmt.Sprintf("Failed to lookup TXT records: %v", err)),
			},
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
		return &[]api.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  api.PtrTo("No SPF record found"),
			},
		}
	}

	var results []api.SPFRecord

	if spfCount > 1 {
		results = append(results, api.SPFRecord{
			Domain: &domain,
			Record: &spfRecord,
			Valid:  false,
			Error:  api.PtrTo("Multiple SPF records found (RFC violation)"),
		})
		return &results
	}

	// Basic validation
	valid := d.validateSPF(spfRecord)

	// Check for strict -all mechanism
	var errMsg *string
	if !valid {
		errMsg = api.PtrTo("SPF record appears malformed")
	} else if !d.hasSPFStrictFail(spfRecord) {
		// Check what mechanism is used
		if strings.HasSuffix(spfRecord, " ~all") {
			errMsg = api.PtrTo("SPF uses ~all (softfail) instead of -all (hardfail). This weakens email authentication and may reduce deliverability.")
		} else if strings.HasSuffix(spfRecord, " +all") || strings.HasSuffix(spfRecord, " ?all") {
			errMsg = api.PtrTo("SPF uses permissive 'all' mechanism. This severely weakens email authentication. Use -all for strict policy.")
		} else if strings.HasSuffix(spfRecord, " all") {
			errMsg = api.PtrTo("SPF uses neutral 'all' mechanism. Use -all for strict policy to improve deliverability.")
		} else {
			errMsg = api.PtrTo("SPF record should end with -all for strict policy to improve deliverability and prevent spoofing.")
		}
	}

	results = append(results, api.SPFRecord{
		Domain: &domain,
		Record: &spfRecord,
		Valid:  valid,
		Error:  errMsg,
	})

	// Extract and resolve include: directives
	includes := d.extractSPFIncludes(spfRecord)
	for _, includeDomain := range includes {
		includedRecords := d.resolveSPFRecords(includeDomain, visited, depth+1)
		if includedRecords != nil {
			results = append(results, *includedRecords...)
		}
	}

	return &results
}

// extractSPFIncludes extracts all include: domains from an SPF record
func (d *DNSAnalyzer) extractSPFIncludes(record string) []string {
	var includes []string
	re := regexp.MustCompile(`include:([^\s]+)`)
	matches := re.FindAllStringSubmatch(record, -1)
	for _, match := range matches {
		if len(match) > 1 {
			includes = append(includes, match[1])
		}
	}
	return includes
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

// hasSPFStrictFail checks if SPF record has strict -all mechanism
func (d *DNSAnalyzer) hasSPFStrictFail(record string) bool {
	return strings.HasSuffix(record, " -all")
}

// checkapi.DKIMRecord looks up and validates DKIM record for a domain and selector
func (d *DNSAnalyzer) checkDKIMRecord(domain, selector string) *api.DKIMRecord {
	// DKIM records are at: selector._domainkey.domain
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dkimDomain)
	if err != nil {
		return &api.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    api.PtrTo(fmt.Sprintf("Failed to lookup DKIM record: %v", err)),
		}
	}

	if len(txtRecords) == 0 {
		return &api.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    api.PtrTo("No DKIM record found"),
		}
	}

	// Concatenate all TXT record parts (DKIM can be split)
	dkimRecord := strings.Join(txtRecords, "")

	// Basic validation - should contain "v=DKIM1" and "p=" (public key)
	if !d.validateDKIM(dkimRecord) {
		return &api.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Record:   api.PtrTo(dkimRecord),
			Valid:    false,
			Error:    api.PtrTo("DKIM record appears malformed"),
		}
	}

	return &api.DKIMRecord{
		Selector: selector,
		Domain:   domain,
		Record:   &dkimRecord,
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

// checkapi.DMARCRecord looks up and validates DMARC record for a domain
func (d *DNSAnalyzer) checkDMARCRecord(domain string) *api.DMARCRecord {
	// DMARC records are at: _dmarc.domain
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return &api.DMARCRecord{
			Valid: false,
			Error: api.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %v", err)),
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
		return &api.DMARCRecord{
			Valid: false,
			Error: api.PtrTo("No DMARC record found"),
		}
	}

	// Extract policy
	policy := d.extractDMARCPolicy(dmarcRecord)

	// Basic validation
	if !d.validateDMARC(dmarcRecord) {
		return &api.DMARCRecord{
			Record: &dmarcRecord,
			Policy: api.PtrTo(api.DMARCRecordPolicy(policy)),
			Valid:  false,
			Error:  api.PtrTo("DMARC record appears malformed"),
		}
	}

	return &api.DMARCRecord{
		Record: &dmarcRecord,
		Policy: api.PtrTo(api.DMARCRecordPolicy(policy)),
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
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector string) *api.BIMIRecord {
	// BIMI records are at: selector._bimi.domain
	bimiDomain := fmt.Sprintf("%s._bimi.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, bimiDomain)
	if err != nil {
		return &api.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    api.PtrTo(fmt.Sprintf("Failed to lookup BIMI record: %v", err)),
		}
	}

	if len(txtRecords) == 0 {
		return &api.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    api.PtrTo("No BIMI record found"),
		}
	}

	// Concatenate all TXT record parts (BIMI can be split)
	bimiRecord := strings.Join(txtRecords, "")

	// Extract logo URL and VMC URL
	logoURL := d.extractBIMITag(bimiRecord, "l")
	vmcURL := d.extractBIMITag(bimiRecord, "a")

	// Basic validation - should contain "v=BIMI1" and "l=" (logo URL)
	if !d.validateBIMI(bimiRecord) {
		return &api.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Record:   &bimiRecord,
			LogoUrl:  &logoURL,
			VmcUrl:   &vmcURL,
			Valid:    false,
			Error:    api.PtrTo("BIMI record appears malformed"),
		}
	}

	return &api.BIMIRecord{
		Selector: selector,
		Domain:   domain,
		Record:   &bimiRecord,
		LogoUrl:  &logoURL,
		VmcUrl:   &vmcURL,
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

// CalculateDNSScore calculates the DNS score from records results
// Returns a score from 0-100 where higher is better
func (d *DNSAnalyzer) CalculateDNSScore(results *api.DNSResults) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// TODO: 20 points for correct PTR and A/AAAA

	// MX Records: 20 points
	// Having valid MX records is critical for email deliverability
	if results.MxRecords != nil && len(*results.MxRecords) > 0 {
		hasValidMX := false
		for _, mx := range *results.MxRecords {
			if mx.Valid {
				hasValidMX = true
				break
			}
		}
		if hasValidMX {
			score += 20
		}
	}

	// SPF Records: 20 points
	// SPF is essential for email authentication
	if results.SpfRecords != nil && len(*results.SpfRecords) > 0 {
		// Check the main domain's SPF record (first in the list)
		mainSPF := (*results.SpfRecords)[0]
		if mainSPF.Valid {
			// Full points for valid SPF
			score += 20

			// Check for strict -all mechanism
			if mainSPF.Record != nil && !d.hasSPFStrictFail(*mainSPF.Record) {
				// Deduct points for weak SPF policy
				if strings.HasSuffix(*mainSPF.Record, " ~all") {
					// Softfail - moderate penalty
					score -= 5
				} else if strings.HasSuffix(*mainSPF.Record, " +all") ||
				          strings.HasSuffix(*mainSPF.Record, " ?all") ||
				          strings.HasSuffix(*mainSPF.Record, " all") {
					// Pass/neutral - severe penalty
					score -= 10
				} else {
					// No 'all' mechanism at all - severe penalty
					score -= 10
				}
			}
		} else if mainSPF.Record != nil {
			// Partial credit if SPF record exists but has issues
			score += 5
		}
	}

	// DKIM Records: 20 points
	// DKIM provides strong email authentication
	if results.DkimRecords != nil && len(*results.DkimRecords) > 0 {
		hasValidDKIM := false
		for _, dkim := range *results.DkimRecords {
			if dkim.Valid {
				hasValidDKIM = true
				break
			}
		}
		if hasValidDKIM {
			score += 20
		} else {
			// Partial credit if DKIM record exists but has issues
			score += 5
		}
	}

	// DMARC Record: 20 points
	// DMARC ties SPF and DKIM together and provides policy
	if results.DmarcRecord != nil {
		if results.DmarcRecord.Valid {
			score += 15
			// Bonus points for stricter policies
			if results.DmarcRecord.Policy != nil {
				switch *results.DmarcRecord.Policy {
				case "reject":
					// Strictest policy - full points already awarded
					score += 5
				case "quarantine":
					// Good policy - no deduction
				case "none":
					// Weakest policy - deduct 5 points
					score -= 5
				}
			}
		} else if results.DmarcRecord.Record != nil {
			// Partial credit if DMARC record exists but has issues
			score += 5
		}
	}

	// BIMI Record: 5 bonus points
	// BIMI is optional but indicates advanced email branding
	if results.BimiRecord != nil && results.BimiRecord.Valid {
		if score >= 100 {
			return 100, "A+"
		}
	}

	// Ensure score doesn't exceed maximum
	if score > 100 {
		score = 100
	}

	// Ensure score is non-negative
	if score < 0 {
		score = 0
	}

	return score, ScoreToGrade(score)
}
