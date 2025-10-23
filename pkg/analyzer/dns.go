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
func (d *DNSAnalyzer) AnalyzeDNS(email *EmailMessage, authResults *api.AuthenticationResults, headersResults *api.HeaderAnalysis) *api.DNSResults {
	// Extract domain from From address
	if headersResults.DomainAlignment.FromDomain == nil || *headersResults.DomainAlignment.FromDomain == "" {
		return &api.DNSResults{
			Errors: &[]string{"Unable to extract domain from email"},
		}
	}
	fromDomain := *headersResults.DomainAlignment.FromDomain

	results := &api.DNSResults{
		FromDomain: fromDomain,
		RpDomain:   headersResults.DomainAlignment.ReturnPathDomain,
	}

	// Determine which domain to check SPF for (Return-Path domain)
	// SPF validates the envelope sender (Return-Path), not the From header
	spfDomain := fromDomain
	if results.RpDomain != nil {
		spfDomain = *results.RpDomain
	}

	// Store sender IP for later use in scoring
	var senderIP string
	if headersResults.ReceivedChain != nil && len(*headersResults.ReceivedChain) > 0 {
		firstHop := (*headersResults.ReceivedChain)[0]
		if firstHop.Ip != nil && *firstHop.Ip != "" {
			senderIP = *firstHop.Ip
			ptrRecords, forwardRecords := d.checkPTRAndForward(senderIP)
			if len(ptrRecords) > 0 {
				results.PtrRecords = &ptrRecords
			}
			if len(forwardRecords) > 0 {
				results.PtrForwardRecords = &forwardRecords
			}
		}
	}

	// Check MX records for From domain (where replies would go)
	results.FromMxRecords = d.checkMXRecords(fromDomain)

	// Check MX records for Return-Path domain (where bounces would go)
	// Only check if Return-Path domain is different from From domain
	if results.RpDomain != nil && *results.RpDomain != fromDomain {
		results.RpMxRecords = d.checkMXRecords(*results.RpDomain)
	}

	// Check SPF records (for Return-Path domain - this is the envelope sender)
	// SPF validates the MAIL FROM command, which corresponds to Return-Path
	results.SpfRecords = d.checkSPFRecords(spfDomain)

	// Check DKIM records (from authentication results)
	// DKIM can be for any domain, but typically the From domain
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

	// Check DMARC record (for From domain - DMARC protects the visible sender)
	// DMARC validates alignment between SPF/DKIM and the From domain
	results.DmarcRecord = d.checkDMARCRecord(fromDomain)

	// Check BIMI record (for From domain - branding is based on visible sender)
	results.BimiRecord = d.checkBIMIRecord(fromDomain, "default")

	return results
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

	// Extract the "all" mechanism qualifier
	var allQualifier *api.SPFRecordAllQualifier
	var errMsg *string

	if !valid {
		errMsg = api.PtrTo("SPF record appears malformed")
	} else {
		// Extract qualifier from the "all" mechanism
		if strings.HasSuffix(spfRecord, " -all") {
			allQualifier = api.PtrTo(api.SPFRecordAllQualifier("-"))
		} else if strings.HasSuffix(spfRecord, " ~all") {
			allQualifier = api.PtrTo(api.SPFRecordAllQualifier("~"))
		} else if strings.HasSuffix(spfRecord, " +all") {
			allQualifier = api.PtrTo(api.SPFRecordAllQualifier("+"))
		} else if strings.HasSuffix(spfRecord, " ?all") {
			allQualifier = api.PtrTo(api.SPFRecordAllQualifier("?"))
		} else if strings.HasSuffix(spfRecord, " all") {
			// Implicit + qualifier (default)
			allQualifier = api.PtrTo(api.SPFRecordAllQualifier("+"))
		}
	}

	results = append(results, api.SPFRecord{
		Domain:       &domain,
		Record:       &spfRecord,
		Valid:        valid,
		AllQualifier: allQualifier,
		Error:        errMsg,
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

	// Extract subdomain policy
	subdomainPolicy := d.extractDMARCSubdomainPolicy(dmarcRecord)

	// Extract percentage
	percentage := d.extractDMARCPercentage(dmarcRecord)

	// Extract alignment modes
	spfAlignment := d.extractDMARCSPFAlignment(dmarcRecord)
	dkimAlignment := d.extractDMARCDKIMAlignment(dmarcRecord)

	// Basic validation
	if !d.validateDMARC(dmarcRecord) {
		return &api.DMARCRecord{
			Record:          &dmarcRecord,
			Policy:          api.PtrTo(api.DMARCRecordPolicy(policy)),
			SubdomainPolicy: subdomainPolicy,
			Percentage:      percentage,
			SpfAlignment:    spfAlignment,
			DkimAlignment:   dkimAlignment,
			Valid:           false,
			Error:           api.PtrTo("DMARC record appears malformed"),
		}
	}

	return &api.DMARCRecord{
		Record:          &dmarcRecord,
		Policy:          api.PtrTo(api.DMARCRecordPolicy(policy)),
		SubdomainPolicy: subdomainPolicy,
		Percentage:      percentage,
		SpfAlignment:    spfAlignment,
		DkimAlignment:   dkimAlignment,
		Valid:           true,
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

// extractDMARCSPFAlignment extracts SPF alignment mode from a DMARC record
// Returns "relaxed" (default) or "strict"
func (d *DNSAnalyzer) extractDMARCSPFAlignment(record string) *api.DMARCRecordSpfAlignment {
	// Look for aspf=s (strict) or aspf=r (relaxed)
	re := regexp.MustCompile(`aspf=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return api.PtrTo(api.DMARCRecordSpfAlignmentStrict)
		}
		return api.PtrTo(api.DMARCRecordSpfAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return api.PtrTo(api.DMARCRecordSpfAlignmentRelaxed)
}

// extractDMARCDKIMAlignment extracts DKIM alignment mode from a DMARC record
// Returns "relaxed" (default) or "strict"
func (d *DNSAnalyzer) extractDMARCDKIMAlignment(record string) *api.DMARCRecordDkimAlignment {
	// Look for adkim=s (strict) or adkim=r (relaxed)
	re := regexp.MustCompile(`adkim=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return api.PtrTo(api.DMARCRecordDkimAlignmentStrict)
		}
		return api.PtrTo(api.DMARCRecordDkimAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return api.PtrTo(api.DMARCRecordDkimAlignmentRelaxed)
}

// extractDMARCSubdomainPolicy extracts subdomain policy from a DMARC record
// Returns the sp tag value or nil if not specified (defaults to main policy)
func (d *DNSAnalyzer) extractDMARCSubdomainPolicy(record string) *api.DMARCRecordSubdomainPolicy {
	// Look for sp=none, sp=quarantine, or sp=reject
	re := regexp.MustCompile(`sp=(none|quarantine|reject)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return api.PtrTo(api.DMARCRecordSubdomainPolicy(matches[1]))
	}
	// If sp is not specified, it defaults to the main policy (p tag)
	// Return nil to indicate it's using the default
	return nil
}

// extractDMARCPercentage extracts the percentage from a DMARC record
// Returns the pct tag value or nil if not specified (defaults to 100)
func (d *DNSAnalyzer) extractDMARCPercentage(record string) *int {
	// Look for pct=<number>
	re := regexp.MustCompile(`pct=(\d+)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		// Convert string to int
		var pct int
		fmt.Sscanf(matches[1], "%d", &pct)
		// Validate range (0-100)
		if pct >= 0 && pct <= 100 {
			return &pct
		}
	}
	// Default is 100 if not specified
	return nil
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

// checkPTRAndForward performs reverse DNS lookup (PTR) and forward confirmation (A/AAAA)
// Returns PTR hostnames and their corresponding forward-resolved IPs
func (d *DNSAnalyzer) checkPTRAndForward(ip string) ([]string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	// Perform reverse DNS lookup (PTR)
	ptrNames, err := d.resolver.LookupAddr(ctx, ip)
	if err != nil || len(ptrNames) == 0 {
		return nil, nil
	}

	var forwardIPs []string
	seenIPs := make(map[string]bool)

	// For each PTR record, perform forward DNS lookup (A/AAAA)
	for _, ptrName := range ptrNames {
		// Look up A records
		ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
		aRecords, err := d.resolver.LookupHost(ctx, ptrName)
		cancel()

		if err == nil {
			for _, forwardIP := range aRecords {
				if !seenIPs[forwardIP] {
					forwardIPs = append(forwardIPs, forwardIP)
					seenIPs[forwardIP] = true
				}
			}
		}
	}

	return ptrNames, forwardIPs
}

// CalculateDNSScore calculates the DNS score from records results
// Returns a score from 0-100 where higher is better
// senderIP is the original sender IP address used for FCrDNS verification
func (d *DNSAnalyzer) CalculateDNSScore(results *api.DNSResults, senderIP string) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// PTR and Forward DNS: 20 points
	// Proper reverse DNS (PTR) and forward-confirmed reverse DNS (FCrDNS) is important for deliverability
	if results.PtrRecords != nil && len(*results.PtrRecords) > 0 {
		// 10 points for having PTR records
		score += 10

		if len(*results.PtrRecords) > 1 {
			// Penalty has it's bad to have multiple PTR records
			score -= 3
		}

		// Additional 10 points for forward-confirmed reverse DNS (FCrDNS)
		// This means the PTR hostname resolves back to IPs that include the original sender IP
		if results.PtrForwardRecords != nil && len(*results.PtrForwardRecords) > 0 && senderIP != "" {
			// Verify that the sender IP is in the list of forward-resolved IPs
			fcrDnsValid := false
			for _, forwardIP := range *results.PtrForwardRecords {
				if forwardIP == senderIP {
					fcrDnsValid = true
					break
				}
			}
			if fcrDnsValid {
				score += 10
			}
		}
	}

	// MX Records: 20 points (10 for From domain, 10 for Return-Path domain)
	// Having valid MX records is critical for email deliverability
	// From domain MX records (10 points) - needed for replies
	if results.FromMxRecords != nil && len(*results.FromMxRecords) > 0 {
		hasValidFromMX := false
		for _, mx := range *results.FromMxRecords {
			if mx.Valid {
				hasValidFromMX = true
				break
			}
		}
		if hasValidFromMX {
			score += 10
		}
	}

	// Return-Path domain MX records (10 points) - needed for bounces
	if results.RpMxRecords != nil && len(*results.RpMxRecords) > 0 {
		hasValidRpMX := false
		for _, mx := range *results.RpMxRecords {
			if mx.Valid {
				hasValidRpMX = true
				break
			}
		}
		if hasValidRpMX {
			score += 10
		}
	} else if results.RpDomain != nil && *results.RpDomain != results.FromDomain {
		// If Return-Path domain is different but has no MX records, it's a problem
		// Don't deduct points if RP domain is same as From domain (already checked)
	} else {
		// If Return-Path is same as From domain, give full 10 points for RP MX
		if results.FromMxRecords != nil && len(*results.FromMxRecords) > 0 {
			hasValidFromMX := false
			for _, mx := range *results.FromMxRecords {
				if mx.Valid {
					hasValidFromMX = true
					break
				}
			}
			if hasValidFromMX {
				score += 10
			}
		}
	}

	// SPF Records: 20 points
	// SPF is essential for email authentication
	if results.SpfRecords != nil && len(*results.SpfRecords) > 0 {
		// Check the main domain's SPF record (first in the list)
		mainSPF := (*results.SpfRecords)[0]
		if mainSPF.Valid {
			// Full points for valid SPF
			score += 15

			// Deduct points based on the all mechanism qualifier
			if mainSPF.AllQualifier != nil {
				switch *mainSPF.AllQualifier {
				case "-":
					// Strict fail - no deduction, this is the recommended policy
					score += 5
				case "~":
					// Softfail - moderate penalty
				case "+", "?":
					// Pass/neutral - severe penalty
					score -= 5
				}
			} else {
				// No 'all' mechanism qualifier extracted - severe penalty
				score -= 5
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
			score += 10
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
			// Bonus points for strict alignment modes (2 points each)
			if results.DmarcRecord.SpfAlignment != nil && *results.DmarcRecord.SpfAlignment == api.DMARCRecordSpfAlignmentStrict {
				score += 1
			}
			if results.DmarcRecord.DkimAlignment != nil && *results.DmarcRecord.DkimAlignment == api.DMARCRecordDkimAlignmentStrict {
				score += 1
			}
			// Subdomain policy scoring (sp tag)
			// +3 for stricter or equal subdomain policy, -3 for weaker
			if results.DmarcRecord.SubdomainPolicy != nil {
				mainPolicy := string(*results.DmarcRecord.Policy)
				subPolicy := string(*results.DmarcRecord.SubdomainPolicy)

				// Policy strength: none < quarantine < reject
				policyStrength := map[string]int{"none": 0, "quarantine": 1, "reject": 2}

				mainStrength := policyStrength[mainPolicy]
				subStrength := policyStrength[subPolicy]

				if subStrength >= mainStrength {
					// Subdomain policy is equal or stricter
					score += 3
				} else {
					// Subdomain policy is weaker
					score -= 3
				}
			} else {
				// No sp tag means subdomains inherit main policy (good default)
				score += 3
			}
			// Percentage scoring (pct tag)
			// Apply the percentage on the current score
			if results.DmarcRecord.Percentage != nil {
				pct := *results.DmarcRecord.Percentage

				score = score * pct / 100
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
