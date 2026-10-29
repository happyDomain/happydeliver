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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// checkSPFRecords looks up and validates SPF records for a domain, including resolving include: directives
func (d *DNSAnalyzer) checkSPFRecords(domain string) *[]model.SPFRecord {
	visited := make(map[string]bool)
	return d.resolveSPFRecords(domain, visited, 0, true)
}

// resolveSPFRecords recursively resolves SPF records including include: directives
// isMainRecord indicates if this is the primary domain's record (not an included one)
func (d *DNSAnalyzer) resolveSPFRecords(domain string, visited map[string]bool, depth int, isMainRecord bool) *[]model.SPFRecord {
	const maxDepth = 10 // Prevent infinite recursion

	if depth > maxDepth {
		return &[]model.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  utils.PtrTo("Maximum SPF include depth exceeded"),
			},
		}
	}

	// Prevent circular references
	if visited[domain] {
		return &[]model.SPFRecord{}
	}
	visited[domain] = true

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return &[]model.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  utils.PtrTo(fmt.Sprintf("Failed to lookup TXT records: %s", formatDNSError(err))),
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
		return &[]model.SPFRecord{
			{
				Domain: &domain,
				Valid:  false,
				Error:  utils.PtrTo(noSPFRecordError(txtRecords)),
			},
		}
	}

	var results []model.SPFRecord

	if spfCount > 1 {
		results = append(results, model.SPFRecord{
			Domain: &domain,
			Record: &spfRecord,
			Valid:  false,
			Error:  utils.PtrTo("Multiple SPF records found (RFC violation)"),
		})
		return &results
	}

	// Basic validation
	validationErr := d.validateSPF(spfRecord, isMainRecord)

	// Extract the "all" mechanism qualifier
	var allQualifier *model.SPFRecordAllQualifier
	var errMsg *string

	if validationErr != nil {
		errMsg = utils.PtrTo(validationErr.Error())
	} else {
		allQualifier = extractSPFAllQualifier(spfRecord)
	}

	results = append(results, model.SPFRecord{
		Domain:       &domain,
		Record:       &spfRecord,
		Valid:        validationErr == nil,
		AllQualifier: allQualifier,
		Error:        errMsg,
	})

	// redirect= only applies once every mechanism failed to match (RFC 7208
	// section 6.1), so the includes before it are evaluated all the same. Its
	// target still comes right after this record: the scoring reads it there.
	redirectDomain := d.extractSPFRedirect(spfRecord)
	if redirectDomain != "" {
		redirectRecords := d.resolveSPFRecords(redirectDomain, visited, depth+1, false)
		if redirectRecords != nil {
			results = append(results, *redirectRecords...)
		}
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

// extractSPFAllQualifier returns the qualifier of the record's "all" mechanism,
// or nil when the record ends with no such mechanism.
func extractSPFAllQualifier(record string) *model.SPFRecordAllQualifier {
	switch {
	case strings.HasSuffix(record, " -all"):
		return utils.PtrTo(model.SPFRecordAllQualifier("-"))
	case strings.HasSuffix(record, " ~all"):
		return utils.PtrTo(model.SPFRecordAllQualifier("~"))
	case strings.HasSuffix(record, " +all"):
		return utils.PtrTo(model.SPFRecordAllQualifier("+"))
	case strings.HasSuffix(record, " ?all"):
		return utils.PtrTo(model.SPFRecordAllQualifier("?"))
	case strings.HasSuffix(record, " all"):
		// Implicit + qualifier (default)
		return utils.PtrTo(model.SPFRecordAllQualifier("+"))
	default:
		return nil
	}
}

// isValidHostnameSyntax reports whether name has the shape of a domain name:
// dot-separated labels of 1 to 63 characters made of letters, digits and
// hyphens, none of them starting or ending with a hyphen (RFC 1123 section
// 2.1), for a total of at most 253 characters.
func isValidHostnameSyntax(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for i := 0; i < len(label); i++ {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}

	return true
}

// heloLookupName normalizes the hostname announced at HELO/EHLO into a name that
// could carry a policy of its own, or returns "" when the announcement is not
// one.
//
// That name is taken verbatim from the Received header and is not always a
// hostname: Postfix writes "unknown" when the reverse lookup fails, RFC 5321
// section 4.1.3 allows an address literal, a single label can never hold a
// policy, and what is left is not even always well formed. Recommending a record
// for any of those would be nonsense, and the announcement being bogus is
// already reported by the HELO/PTR check.
func heloLookupName(helo string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(helo)), ".")

	switch {
	case name == "" || name == "unknown":
		// Postfix's placeholder for a client it could not resolve
		return ""
	case strings.HasPrefix(name, "["):
		// Address literal: [192.0.2.1] or [IPv6:2001:db8::1]
		return ""
	case net.ParseIP(name) != nil:
		// Bare address, as announced by some clients
		return ""
	case !strings.Contains(name, "."):
		// Single label (localhost, a LAN name): nothing publishable under it
		return ""
	case !isValidHostnameSyntax(name):
		// Malformed announcement (an empty label, an underscore, a stray
		// character): no such name could be queried, let alone published
		return ""
	}

	return name
}

// checkHeloSPFRecord looks up the SPF policy published for the hostname the
// sending server announced at HELO/EHLO.
//
// This is purely informational and never feeds a score: most relays publish no
// policy for their own hostname, which is not a misconfiguration. Publishing one
// simply lets receivers authenticate the HELO identity too, which matters for
// bounces, where the envelope sender is empty and HELO is all SPF can check.
// Unlike the envelope sender policy, include: directives are not resolved here.
func (d *DNSAnalyzer) checkHeloSPFRecord(helo string) *model.SPFRecord {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	result := &model.SPFRecord{Domain: &helo}

	txtRecords, err := d.resolver.LookupTXT(ctx, helo)
	if err != nil {
		result.Error = utils.PtrTo(fmt.Sprintf("Failed to lookup TXT records: %s", formatDNSError(err)))
		return result
	}

	var spfRecords []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		result.Error = utils.PtrTo(noSPFRecordError(txtRecords))
		return result
	}

	result.Record = &spfRecords[0]

	if len(spfRecords) > 1 {
		result.Error = utils.PtrTo("Multiple SPF records found (RFC violation)")
		return result
	}

	if err := d.validateSPF(spfRecords[0], true); err != nil {
		result.Error = utils.PtrTo(err.Error())
		return result
	}

	result.Valid = true
	result.AllQualifier = extractSPFAllQualifier(spfRecords[0])

	return result
}

// noSPFRecordError explains the absence of an SPF record, hinting at the likely
// misconfiguration (or misbehaving resolver) when a record of another known
// type was served at the SPF location instead.
func noSPFRecordError(txtRecords []string) string {
	for _, txt := range txtRecords {
		if desc := describeMisplacedRecord(leadingVersion(txt), "SPF"); desc != "" {
			return fmt.Sprintf("No SPF record found (%s is published at this location instead; this is a misconfiguration)", desc)
		}
	}
	return "No SPF record found"
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

func (d *DNSAnalyzer) calculateSPFScore(results *model.DNSResults) (int, []model.Issue) {
	domain := results.FromDomain
	if results.RpDomain != nil && *results.RpDomain != "" {
		domain = *results.RpDomain
	}
	publish := fmt.Sprintf(`Publish a TXT record on %s listing your sending servers, ending with -all: for instance "v=spf1 include:<your provider> -all".`, domain)

	c := checkScore{score: 100}

	// SPF is essential for email authentication
	if results.SpfRecords == nil || len(*results.SpfRecords) == 0 {
		c.cap(0, newIssue(model.IssueTypeSpfMissing, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s publishes no SPF record, so receivers cannot tell which servers may send its mail.", domain),
			publish))
		return c.score, c.issues
	}

	// Find the main SPF record by skipping redirects
	// Loop through records to find the last redirect or the first non-redirect
	mainSPFIndex := 0
	for i := 0; i < len(*results.SpfRecords); i++ {
		spfRecord := (*results.SpfRecords)[i]
		if spfRecord.Record != nil && strings.Contains(*spfRecord.Record, "redirect=") {
			// The redirect target comes right after the record, unless it could
			// not be fetched or was already visited: the next record is then the
			// first include, which is no policy for the domain.
			next := i + 1
			if next < len(*results.SpfRecords) && (*results.SpfRecords)[next].Domain != nil &&
				strings.EqualFold(*(*results.SpfRecords)[next].Domain, d.extractSPFRedirect(*spfRecord.Record)) {
				mainSPFIndex = next
			} else {
				break
			}
		} else {
			// Found a non-redirect record
			mainSPFIndex = i
			break
		}
	}

	mainSPF := (*results.SpfRecords)[mainSPFIndex]
	if mainSPF.Domain != nil {
		domain = *mainSPF.Domain
	}

	if !mainSPF.Valid {
		reason := "invalid record"
		if mainSPF.Error != nil {
			reason = *mainSPF.Error
		}
		if mainSPF.Record == nil {
			message := fmt.Sprintf("%s publishes no SPF record, so receivers cannot tell which servers may send its mail.", domain)
			if mainSPF.Error != nil && !strings.HasPrefix(*mainSPF.Error, "No SPF record") {
				message = fmt.Sprintf("The SPF record of %s cannot be read: %s.", domain, reason)
			}
			c.cap(0, newIssue(model.IssueTypeSpfMissing, model.IssueSeverityHigh, domain, message, publish))
		} else {
			// Partial credit if SPF record exists but has issues
			c.cap(25, newIssue(model.IssueTypeSpfInvalid, model.IssueSeverityHigh, domain,
				fmt.Sprintf("The SPF record of %s is invalid: %s.", domain, reason),
				"Fix the record so that receivers can evaluate it; until then they treat it as a permanent error."))
		}
		return c.score, c.issues
	}

	// Check if DMARC is configured with strict policy as all mechanism is less significant
	dmarcStrict := results.DmarcRecord != nil &&
		results.DmarcRecord.Valid && results.DmarcRecord.Policy != nil &&
		(*results.DmarcRecord.Policy == "quarantine" ||
			*results.DmarcRecord.Policy == "reject")

	// Deduct points based on the all mechanism qualifier
	endStrict := "End the record with -all."
	if mainSPF.AllQualifier == nil {
		// No 'all' mechanism qualifier extracted - severe penalty
		c.cap(50, newIssue(model.IssueTypeSpfAllMissing, model.IssueSeverityMedium, domain,
			fmt.Sprintf("The SPF record of %s ends with no all mechanism, so unlisted servers are neither accepted nor rejected.", domain),
			endStrict))
	} else {
		switch *mainSPF.AllQualifier {
		case "-":
			// Strict fail - no deduction, this is the recommended policy
		case "~":
			// Softfail - if DMARC is quarantine or reject, treat it mostly like strict fail
			advice := "End the record with -all once you are sure it lists every server that sends your mail."
			if dmarcStrict {
				c.cap(95, newIssue(model.IssueTypeSpfAllSoftfail, model.IssueSeverityLow, domain,
					"Mail from unlisted servers only soft-fails; your enforced DMARC policy does most of the rejecting.", advice))
			} else {
				c.cap(75, newIssue(model.IssueTypeSpfAllSoftfail, model.IssueSeverityMedium, domain,
					"Mail from unlisted servers only soft-fails, and no enforcing DMARC policy backs it up.", advice))
			}
		case "+":
			// Pass - severe penalty, unless DMARC catches what it lets through
			message := fmt.Sprintf("The SPF record of %s ends with +all: anyone on the Internet may send mail in its name.", domain)
			advice := "End the record with -all, after listing the servers that actually send your mail."
			if dmarcStrict {
				c.cap(75, newIssue(model.IssueTypeSpfAllPass, model.IssueSeverityHigh, domain,
					message+" Your enforced DMARC policy limits the damage.", advice))
			} else {
				c.cap(50, newIssue(model.IssueTypeSpfAllPass, model.IssueSeverityHigh, domain, message, advice))
			}
		case "?":
			// Neutral - severe penalty, unless DMARC catches what it lets through
			message := fmt.Sprintf("The SPF record of %s ends with ?all, so unlisted servers are neither accepted nor rejected.", domain)
			if dmarcStrict {
				c.cap(75, newIssue(model.IssueTypeSpfAllNeutral, model.IssueSeverityLow, domain,
					message+" Your enforced DMARC policy does the rejecting instead.", endStrict))
			} else {
				c.cap(50, newIssue(model.IssueTypeSpfAllNeutral, model.IssueSeverityMedium, domain, message, endStrict))
			}
		}
	}

	// An included record that cannot be fetched or parsed makes receivers
	// fail the whole evaluation with a permerror. The score does not count
	// it yet; the issue says so rather than staying silent.
	for i, r := range *results.SpfRecords {
		if i == mainSPFIndex || r.Valid || (r.Record != nil && strings.Contains(*r.Record, "redirect=")) {
			continue
		}
		included := ""
		if r.Domain != nil {
			included = *r.Domain
		}
		reason := ""
		if r.Error != nil {
			reason = ": " + *r.Error
		}
		c.note(newIssue(model.IssueTypeSpfIncludeInvalid, model.IssueSeverityHigh, included,
			fmt.Sprintf("The SPF record included from %s cannot be evaluated%s. Receivers that cannot follow an include: treat the whole record as a permanent error.", included, reason),
			fmt.Sprintf("Fix the record of %s, or remove the include: pointing to it.", included)))
	}

	return c.score, c.issues
}
