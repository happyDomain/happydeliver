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

// lookupDMARCAt queries _dmarc.<domain> and returns the raw DMARC1 TXT record.
// notFound=true means no record exists (NXDOMAIN or empty); false means a real DNS error occurred.
func (d *DNSAnalyzer) lookupDMARCAt(domain string) (record string, notFound bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, lookupErr := d.resolver.LookupTXT(ctx, fmt.Sprintf("_dmarc.%s", domain))
	if lookupErr != nil {
		if dnsErr, ok := lookupErr.(*net.DNSError); ok && dnsErr.IsNotFound {
			return "", true, nil
		}
		return "", false, lookupErr
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return txt, false, nil
		}
	}
	return "", true, nil
}

// parseDMARCRecord parses a raw DMARC TXT record into a DMARCRecord model.
func (d *DNSAnalyzer) parseDMARCRecord(foundDomain, rawRecord string) *model.DMARCRecord {
	policy := d.extractDMARCPolicy(rawRecord)
	subdomainPolicy := d.extractDMARCSubdomainPolicy(rawRecord)
	nonexistentSubdomainPolicy := d.extractDMARCNonexistentSubdomainPolicy(rawRecord)
	percentage := d.extractDMARCPercentage(rawRecord)
	testMode := d.extractDMARCTestMode(rawRecord)
	psd := d.extractDMARCPSD(rawRecord)
	spfAlignment := d.extractDMARCSPFAlignment(rawRecord)
	dkimAlignment := d.extractDMARCDKIMAlignment(rawRecord)
	deprecatedPct := percentage != nil
	deprecatedRf := d.hasDMARCTag(rawRecord, "rf")
	deprecatedRi := d.hasDMARCTag(rawRecord, "ri")

	rec := &model.DMARCRecord{
		Domain:                     &foundDomain,
		Record:                     &rawRecord,
		Policy:                     utils.PtrTo(model.DMARCRecordPolicy(policy)),
		SubdomainPolicy:            subdomainPolicy,
		NonexistentSubdomainPolicy: nonexistentSubdomainPolicy,
		Percentage:                 percentage,
		TestMode:                   testMode,
		Psd:                        psd,
		SpfAlignment:               spfAlignment,
		DkimAlignment:              dkimAlignment,
	}
	if deprecatedPct {
		rec.DeprecatedPct = utils.PtrTo(true)
	}
	if deprecatedRf {
		rec.DeprecatedRf = utils.PtrTo(true)
	}
	if deprecatedRi {
		rec.DeprecatedRi = utils.PtrTo(true)
	}

	if !d.validateDMARC(rawRecord) {
		rec.Valid = false
		rec.Error = utils.PtrTo("DMARC record appears malformed")
		return rec
	}

	rec.Valid = true
	return rec
}

// walkDNSForDMARC implements the DMARCbis DNS Tree Walk algorithm (Section 4.10).
// It queries _dmarc.<domain> and walks up the label hierarchy until a valid DMARC
// record is found or all labels are exhausted. Maximum 8 DNS queries per message.
// For domains with ≥8 labels, after the initial miss the walk jumps to the 7-label
// suffix before resuming normally (to stay within the 8-query budget).
// Single-label (TLD) records are only accepted when they carry psd=y.
func (d *DNSAnalyzer) walkDNSForDMARC(domain string) (record, foundDomain string, err error) {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	n := len(labels)

	for i, queries := 0, 0; i < n && queries < 8; i, queries = i+1, queries+1 {
		current := strings.Join(labels[i:], ".")

		raw, notFound, lookupErr := d.lookupDMARCAt(current)
		if lookupErr != nil {
			return "", "", lookupErr
		}
		if !notFound {
			// Single-label (TLD) records are only used when the record explicitly opts in.
			if !strings.Contains(current, ".") {
				if d.extractDMARCPSDValue(raw) != "y" {
					break
				}
			}
			return raw, current, nil
		}

		// DMARCbis §4.10: after missing on a ≥8-label domain, shortcut to the
		// 7-label suffix for the next query rather than stepping one label at a time.
		if i == 0 && n >= 8 {
			i = n - 8 // the outer i++ will land at n-7 (7 labels from the right)
		}
	}

	return "", "", nil
}

// checkDMARCRecord looks up and validates the DMARC record for a domain using
// the DMARCbis DNS Tree Walk algorithm (Section 4.10), which supersedes the
// RFC 7489 PSL-based organizational domain lookup and the RFC 9091 PSD DMARC
// experimental fallback.
func (d *DNSAnalyzer) checkDMARCRecord(domain string) *model.DMARCRecord {
	raw, foundDomain, err := d.walkDNSForDMARC(domain)
	if err != nil {
		return &model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %v", err)),
		}
	}
	if foundDomain == "" {
		return &model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo("No DMARC record found"),
		}
	}
	return d.parseDMARCRecord(foundDomain, raw)
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
func (d *DNSAnalyzer) extractDMARCSPFAlignment(record string) *model.DMARCRecordSpfAlignment {
	// Look for aspf=s (strict) or aspf=r (relaxed)
	re := regexp.MustCompile(`aspf=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return utils.PtrTo(model.DMARCRecordSpfAlignmentStrict)
		}
		return utils.PtrTo(model.DMARCRecordSpfAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return utils.PtrTo(model.DMARCRecordSpfAlignmentRelaxed)
}

// extractDMARCDKIMAlignment extracts DKIM alignment mode from a DMARC record
// Returns "relaxed" (default) or "strict"
func (d *DNSAnalyzer) extractDMARCDKIMAlignment(record string) *model.DMARCRecordDkimAlignment {
	// Look for adkim=s (strict) or adkim=r (relaxed)
	re := regexp.MustCompile(`adkim=(r|s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		if matches[1] == "s" {
			return utils.PtrTo(model.DMARCRecordDkimAlignmentStrict)
		}
		return utils.PtrTo(model.DMARCRecordDkimAlignmentRelaxed)
	}
	// Default is relaxed if not specified
	return utils.PtrTo(model.DMARCRecordDkimAlignmentRelaxed)
}

// extractDMARCSubdomainPolicy extracts subdomain policy from a DMARC record
// Returns the sp tag value or nil if not specified (defaults to main policy)
func (d *DNSAnalyzer) extractDMARCSubdomainPolicy(record string) *model.DMARCRecordSubdomainPolicy {
	// Look for sp=none, sp=quarantine, or sp=reject
	re := regexp.MustCompile(`sp=(none|quarantine|reject)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return utils.PtrTo(model.DMARCRecordSubdomainPolicy(matches[1]))
	}
	// If sp is not specified, it defaults to the main policy (p tag)
	// Return nil to indicate it's using the default
	return nil
}

// extractDMARCNonexistentSubdomainPolicy extracts non-existent subdomain policy from a DMARC record.
// Returns the np tag value or nil if not specified (defaults to effective sp/p policy).
// The np= tag is introduced by DMARCbis (draft-ietf-dmarc-dmarcbis).
func (d *DNSAnalyzer) extractDMARCNonexistentSubdomainPolicy(record string) *model.DMARCRecordNonexistentSubdomainPolicy {
	re := regexp.MustCompile(`np=(none|quarantine|reject)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return utils.PtrTo(model.DMARCRecordNonexistentSubdomainPolicy(matches[1]))
	}
	return nil
}

// extractDMARCPercentage extracts the percentage from a DMARC record.
// Returns the pct tag value or nil if not specified (defaults to 100).
// Note: pct= is deprecated in DMARCbis; use t= (test_mode) instead.
func (d *DNSAnalyzer) extractDMARCPercentage(record string) *int {
	re := regexp.MustCompile(`pct=(\d+)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		var pct int
		fmt.Sscanf(matches[1], "%d", &pct)
		if pct >= 0 && pct <= 100 {
			return &pct
		}
	}
	return nil
}

// extractDMARCTestMode extracts the DMARCbis t= tag (test mode).
// Returns true for t=y, false for t=n, nil if absent (defaults to false / full enforcement).
func (d *DNSAnalyzer) extractDMARCTestMode(record string) *bool {
	re := regexp.MustCompile(`(?:^|;)\s*t=(y|n)(?:;|$|\s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		v := matches[1] == "y"
		return &v
	}
	return nil
}

// extractDMARCPSD extracts the DMARCbis psd= tag value as a typed enum.
// Returns nil if the tag is absent (defaults to "u" / unknown).
func (d *DNSAnalyzer) extractDMARCPSD(record string) *model.DMARCRecordPsd {
	v := d.extractDMARCPSDValue(record)
	if v == "" {
		return nil
	}
	return utils.PtrTo(model.DMARCRecordPsd(v))
}

// extractDMARCPSDValue returns the raw string value of psd= ("y", "n", "u") or "".
func (d *DNSAnalyzer) extractDMARCPSDValue(record string) string {
	re := regexp.MustCompile(`(?:^|;)\s*psd=(y|n|u)(?:;|$|\s)`)
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// hasDMARCTag reports whether the given tag name appears in the record.
func (d *DNSAnalyzer) hasDMARCTag(record, tag string) bool {
	re := regexp.MustCompile(`(?:^|;)\s*` + regexp.QuoteMeta(tag) + `=`)
	return re.MatchString(record)
}

// validateDMARC performs basic DMARC record validation.
// Per DMARCbis, p= is now RECOMMENDED (not required): a record with a valid
// rua= but no p= is treated as p=none and considered valid.
func (d *DNSAnalyzer) validateDMARC(record string) bool {
	if !strings.HasPrefix(record, "v=DMARC1") {
		return false
	}

	// p= absent is allowed in DMARCbis when rua= is present (treated as p=none).
	if !strings.Contains(record, "p=") {
		return strings.Contains(record, "rua=")
	}

	return true
}

func (d *DNSAnalyzer) calculateDMARCScore(results *model.DNSResults) (score int) {
	if results.DmarcRecord == nil {
		return
	}

	if !results.DmarcRecord.Valid {
		if results.DmarcRecord.Record != nil {
			// Partial credit if a DMARC record exists but has issues
			score += 20
		}
		return
	}

	score += 50

	// Determine effective policy: DMARCbis t=y downgrades policy one level.
	effectivePolicy := "none"
	if results.DmarcRecord.Policy != nil {
		effectivePolicy = string(*results.DmarcRecord.Policy)
	}
	testMode := results.DmarcRecord.TestMode != nil && *results.DmarcRecord.TestMode
	if testMode {
		switch effectivePolicy {
		case "reject":
			effectivePolicy = "quarantine"
		case "quarantine":
			effectivePolicy = "none"
		}
	}

	// Bonus/penalty for policy strength
	switch effectivePolicy {
	case "reject":
		score += 25
	case "none":
		score -= 25
	}

	// Bonus points for strict alignment modes
	if results.DmarcRecord.SpfAlignment != nil && *results.DmarcRecord.SpfAlignment == model.DMARCRecordSpfAlignmentStrict {
		score += 5
	}
	if results.DmarcRecord.DkimAlignment != nil && *results.DmarcRecord.DkimAlignment == model.DMARCRecordDkimAlignmentStrict {
		score += 5
	}

	policyStrength := map[string]int{"none": 0, "quarantine": 1, "reject": 2}

	// Subdomain policy scoring (sp tag): +15 for equal-or-stricter, -15 for weaker
	if results.DmarcRecord.SubdomainPolicy != nil {
		subPolicy := string(*results.DmarcRecord.SubdomainPolicy)
		if policyStrength[subPolicy] >= policyStrength[effectivePolicy] {
			score += 15
		} else {
			score -= 15
		}
	} else {
		score += 15 // inherits main policy — good default
	}

	// Non-existent subdomain policy scoring (np tag, DMARCbis)
	score -= 15
	effectiveSubPolicy := effectivePolicy
	if results.DmarcRecord.SubdomainPolicy != nil {
		effectiveSubPolicy = string(*results.DmarcRecord.SubdomainPolicy)
	}
	if results.DmarcRecord.NonexistentSubdomainPolicy == nil {
		score += 15 // inherits subdomain/main policy — good default
	} else {
		npStrength := policyStrength[string(*results.DmarcRecord.NonexistentSubdomainPolicy)]
		if npStrength >= policyStrength[effectiveSubPolicy] {
			score += 15
		}
	}

	// pct= scaling (deprecated in DMARCbis, kept for backward compatibility).
	// pct=0 is an anti-pattern: score it as zero enforcement.
	if results.DmarcRecord.Percentage != nil {
		pct := *results.DmarcRecord.Percentage
		score = score * pct / 100
	}

	return
}
