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
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

var dmarcPolicyStrength = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

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
	tags := parseDKIMTags(rawRecord)

	// Policy
	policy := "unknown"
	switch tags["p"] {
	case "none", "quarantine", "reject":
		policy = tags["p"]
	}

	// SPF alignment (default: relaxed)
	spfAlignment := utils.PtrTo(model.DMARCRecordSpfAlignmentRelaxed)
	if tags["aspf"] == "s" {
		spfAlignment = utils.PtrTo(model.DMARCRecordSpfAlignmentStrict)
	}

	// DKIM alignment (default: relaxed)
	dkimAlignment := utils.PtrTo(model.DMARCRecordDkimAlignmentRelaxed)
	if tags["adkim"] == "s" {
		dkimAlignment = utils.PtrTo(model.DMARCRecordDkimAlignmentStrict)
	}

	// Subdomain policy
	var subdomainPolicy *model.DMARCRecordSubdomainPolicy
	switch tags["sp"] {
	case "none", "quarantine", "reject":
		subdomainPolicy = utils.PtrTo(model.DMARCRecordSubdomainPolicy(tags["sp"]))
	}

	// Non-existent subdomain policy (DMARCbis np=)
	var nonexistentSubdomainPolicy *model.DMARCRecordNonexistentSubdomainPolicy
	switch tags["np"] {
	case "none", "quarantine", "reject":
		nonexistentSubdomainPolicy = utils.PtrTo(model.DMARCRecordNonexistentSubdomainPolicy(tags["np"]))
	}

	// Percentage (pct=, deprecated in DMARCbis)
	var percentage *int
	if pctStr, ok := tags["pct"]; ok {
		if pct, err := strconv.Atoi(pctStr); err == nil && pct >= 0 && pct <= 100 {
			percentage = &pct
		}
	}

	// Test mode (DMARCbis t=)
	var testMode *bool
	if t, ok := tags["t"]; ok {
		v := t == "y"
		testMode = &v
	}

	// PSD (DMARCbis psd=)
	var psd *model.DMARCRecordPsd
	switch tags["psd"] {
	case "y", "n", "u":
		psd = utils.PtrTo(model.DMARCRecordPsd(tags["psd"]))
	}

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
	if percentage != nil {
		rec.DeprecatedPct = utils.PtrTo(true)
	}
	if _, ok := tags["rf"]; ok {
		rec.DeprecatedRf = utils.PtrTo(true)
	}
	if _, ok := tags["ri"]; ok {
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
			Error: utils.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %s", formatDNSError(err))),
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

// extractDMARCPSDValue returns the raw psd= value ("y", "n", "u") or "" if absent.
// Used during DNS Tree Walk before full record parsing.
func (d *DNSAnalyzer) extractDMARCPSDValue(record string) string {
	v := parseDKIMTags(record)["psd"]
	switch v {
	case "y", "n", "u":
		return v
	}
	return ""
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

	// Subdomain policy scoring (sp tag): +15 for equal-or-stricter, -15 for weaker
	if results.DmarcRecord.SubdomainPolicy != nil {
		subPolicy := string(*results.DmarcRecord.SubdomainPolicy)
		if dmarcPolicyStrength[subPolicy] >= dmarcPolicyStrength[effectivePolicy] {
			score += 15
		} else {
			score -= 15
		}
	} else {
		score += 15 // inherits main policy — good default
	}

	// Non-existent subdomain policy scoring (np tag, DMARCbis): +15 for equal-or-stricter, -15 for weaker
	effectiveSubPolicy := effectivePolicy
	if results.DmarcRecord.SubdomainPolicy != nil {
		effectiveSubPolicy = string(*results.DmarcRecord.SubdomainPolicy)
	}
	if results.DmarcRecord.NonexistentSubdomainPolicy == nil {
		score += 15 // inherits subdomain/main policy — good default
	} else if dmarcPolicyStrength[string(*results.DmarcRecord.NonexistentSubdomainPolicy)] >= dmarcPolicyStrength[effectiveSubPolicy] {
		score += 15
	} else {
		score -= 15
	}

	// pct= scaling (deprecated in DMARCbis, kept for backward compatibility).
	// pct=0 is an anti-pattern: score it as zero enforcement.
	if results.DmarcRecord.Percentage != nil {
		pct := *results.DmarcRecord.Percentage
		score = score * pct / 100
	}

	return
}
