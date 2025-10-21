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

	// Check SPF record
	results.SpfRecord = d.checkSPFRecord(domain)

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

// checkSPFRecord looks up and validates SPF record for a domain
func (d *DNSAnalyzer) checkSPFRecord(domain string) *api.SPFRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return &api.SPFRecord{
			Valid: false,
			Error: api.PtrTo(fmt.Sprintf("Failed to lookup TXT records: %v", err)),
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
		return &api.SPFRecord{
			Valid: false,
			Error: api.PtrTo("No SPF record found"),
		}
	}

	if spfCount > 1 {
		return &api.SPFRecord{
			Record: &spfRecord,
			Valid:  false,
			Error:  api.PtrTo("Multiple SPF records found (RFC violation)"),
		}
	}

	// Basic validation
	if !d.validateSPF(spfRecord) {
		return &api.SPFRecord{
			Record: &spfRecord,
			Valid:  false,
			Error:  api.PtrTo("SPF record appears malformed"),
		}
	}

	return &api.SPFRecord{
		Record: &spfRecord,
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
