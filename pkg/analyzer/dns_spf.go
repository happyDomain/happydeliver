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
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// checkSPFRecords looks up and validates SPF records for a domain, including resolving include: directives
func (d *DNSAnalyzer) checkSPFRecords(domain string) *[]api.SPFRecord {
	visited := make(map[string]bool)
	return d.resolveSPFRecords(domain, visited, 0, true)
}

// resolveSPFRecords recursively resolves SPF records including include: directives
// isMainRecord indicates if this is the primary domain's record (not an included one)
func (d *DNSAnalyzer) resolveSPFRecords(domain string, visited map[string]bool, depth int, isMainRecord bool) *[]api.SPFRecord {
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
	validationErr := d.validateSPF(spfRecord, isMainRecord)

	// Extract the "all" mechanism qualifier
	var allQualifier *api.SPFRecordAllQualifier
	var errMsg *string

	if validationErr != nil {
		errMsg = api.PtrTo(validationErr.Error())
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
		Valid:        validationErr == nil,
		AllQualifier: allQualifier,
		Error:        errMsg,
	})

	// Check for redirect= modifier first (it replaces the entire SPF policy)
	redirectDomain := d.extractSPFRedirect(spfRecord)
	if redirectDomain != "" {
		// redirect= replaces the current domain's policy entirely
		// Only follow if no other mechanisms matched (per RFC 7208)
		redirectRecords := d.resolveSPFRecords(redirectDomain, visited, depth+1, false)
		if redirectRecords != nil {
			results = append(results, *redirectRecords...)
		}
		return &results
	}

	// Extract and resolve include: directives
	includes := d.extractSPFIncludes(spfRecord)
	for _, includeDomain := range includes {
		includedRecords := d.resolveSPFRecords(includeDomain, visited, depth+1, false)
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

// extractSPFRedirect extracts the redirect= domain from an SPF record
// The redirect= modifier replaces the current domain's SPF policy with that of the target domain
func (d *DNSAnalyzer) extractSPFRedirect(record string) string {
	re := regexp.MustCompile(`redirect=([^\s]+)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// isValidSPFMechanism checks if a token is a valid SPF mechanism or modifier
func (d *DNSAnalyzer) isValidSPFMechanism(token string) error {
	// Remove qualifier prefix if present (+, -, ~, ?)
	mechanism := strings.TrimLeft(token, "+-~?")

	// Check if it's a modifier (contains =)
	if strings.Contains(mechanism, "=") {
		// Allow known modifiers: redirect=, exp=, and RFC 6652 modifiers (ra=, rp=, rr=)
		if strings.HasPrefix(mechanism, "redirect=") ||
			strings.HasPrefix(mechanism, "exp=") ||
			strings.HasPrefix(mechanism, "ra=") ||
			strings.HasPrefix(mechanism, "rp=") ||
			strings.HasPrefix(mechanism, "rr=") {
			return nil
		}

		// Check if it's a common mistake (using = instead of :)
		parts := strings.SplitN(mechanism, "=", 2)
		if len(parts) == 2 {
			mechanismName := parts[0]
			knownMechanisms := []string{"include", "a", "mx", "ptr", "exists"}
			for _, known := range knownMechanisms {
				if mechanismName == known {
					return fmt.Errorf("invalid syntax '%s': mechanism '%s' should use ':' not '='", token, mechanismName)
				}
			}
		}

		return fmt.Errorf("unknown modifier '%s'", token)
	}

	// Check standalone mechanisms (no domain/value required)
	if mechanism == "all" || mechanism == "a" || mechanism == "mx" || mechanism == "ptr" {
		return nil
	}

	// Check mechanisms with domain/value
	knownPrefixes := []string{
		"include:",
		"a:", "a/",
		"mx:", "mx/",
		"ptr:",
		"ip4:",
		"ip6:",
		"exists:",
	}

	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(mechanism, prefix) {
			return nil
		}
	}

	return fmt.Errorf("unknown mechanism '%s'", token)
}

// validateSPF performs basic SPF record validation
// isMainRecord indicates if this is the primary domain's record (not an included one)
func (d *DNSAnalyzer) validateSPF(record string, isMainRecord bool) error {
	// Must start with v=spf1
	if !strings.HasPrefix(record, "v=spf1") {
		return fmt.Errorf("SPF record must start with 'v=spf1'")
	}

	// Parse and validate each token in the SPF record
	tokens := strings.Fields(record)
	hasRedirect := false

	for i, token := range tokens {
		// Skip the version tag
		if i == 0 && token == "v=spf1" {
			continue
		}

		// Check if it's a valid mechanism
		if err := d.isValidSPFMechanism(token); err != nil {
			return err
		}

		// Track if we have a redirect modifier
		mechanism := strings.TrimLeft(token, "+-~?")
		if strings.HasPrefix(mechanism, "redirect=") {
			hasRedirect = true
		}
	}

	// Check for redirect= modifier (which replaces the need for an 'all' mechanism)
	if hasRedirect {
		return nil
	}

	// Only check for 'all' mechanism on the main record, not on included records
	if isMainRecord {
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

		if !hasValidEnding {
			return fmt.Errorf("SPF record should end with an 'all' mechanism (e.g., '-all', '~all') or have a 'redirect=' modifier")
		}
	}

	return nil
}

// hasSPFStrictFail checks if SPF record has strict -all mechanism
func (d *DNSAnalyzer) hasSPFStrictFail(record string) bool {
	return strings.HasSuffix(record, " -all")
}

func (d *DNSAnalyzer) calculateSPFScore(results *api.DNSResults) (score int) {
	// SPF is essential for email authentication
	if results.SpfRecords != nil && len(*results.SpfRecords) > 0 {
		// Find the main SPF record by skipping redirects
		// Loop through records to find the last redirect or the first non-redirect
		mainSPFIndex := 0
		for i := 0; i < len(*results.SpfRecords); i++ {
			spfRecord := (*results.SpfRecords)[i]
			if spfRecord.Record != nil && strings.Contains(*spfRecord.Record, "redirect=") {
				// This is a redirect, check if there's a next record
				if i+1 < len(*results.SpfRecords) {
					mainSPFIndex = i + 1
				} else {
					// Redirect exists but no target record found
					break
				}
			} else {
				// Found a non-redirect record
				mainSPFIndex = i
				break
			}
		}

		mainSPF := (*results.SpfRecords)[mainSPFIndex]
		if mainSPF.Valid {
			// Full points for valid SPF
			score += 75

			// Check if DMARC is configured with strict policy as all mechanism is less significant
			dmarcStrict := results.DmarcRecord != nil &&
				results.DmarcRecord.Valid && results.DmarcRecord.Policy != nil &&
				(*results.DmarcRecord.Policy == "quarantine" ||
					*results.DmarcRecord.Policy == "reject")

			// Deduct points based on the all mechanism qualifier
			if mainSPF.AllQualifier != nil {
				switch *mainSPF.AllQualifier {
				case "-":
					// Strict fail - no deduction, this is the recommended policy
					score += 25
				case "~":
					// Softfail - if DMARC is quarantine or reject, treat it mostly like strict fail
					if dmarcStrict {
						score += 20
					}
					// Otherwise, moderate penalty (no points added or deducted)
				case "+", "?":
					// Pass/neutral - severe penalty
					if !dmarcStrict {
						score -= 25
					}
				}
			} else {
				// No 'all' mechanism qualifier extracted - severe penalty
				score -= 25
			}
		} else if mainSPF.Record != nil {
			// Partial credit if SPF record exists but has issues
			score += 25
		}
	}

	return
}
