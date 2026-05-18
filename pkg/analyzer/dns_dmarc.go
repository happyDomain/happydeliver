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

	"golang.org/x/net/publicsuffix"

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
	spfAlignment := d.extractDMARCSPFAlignment(rawRecord)
	dkimAlignment := d.extractDMARCDKIMAlignment(rawRecord)

	if !d.validateDMARC(rawRecord) {
		return &model.DMARCRecord{
			Domain:                     &foundDomain,
			Record:                     &rawRecord,
			Policy:                     utils.PtrTo(model.DMARCRecordPolicy(policy)),
			SubdomainPolicy:            subdomainPolicy,
			NonexistentSubdomainPolicy: nonexistentSubdomainPolicy,
			Percentage:                 percentage,
			SpfAlignment:               spfAlignment,
			DkimAlignment:              dkimAlignment,
			Valid:                      false,
			Error:                      utils.PtrTo("DMARC record appears malformed"),
		}
	}

	return &model.DMARCRecord{
		Domain:                     &foundDomain,
		Record:                     &rawRecord,
		Policy:                     utils.PtrTo(model.DMARCRecordPolicy(policy)),
		SubdomainPolicy:            subdomainPolicy,
		NonexistentSubdomainPolicy: nonexistentSubdomainPolicy,
		Percentage:                 percentage,
		SpfAlignment:               spfAlignment,
		DkimAlignment:              dkimAlignment,
		Valid:                      true,
	}
}

// checkDMARCRecord looks up and validates the DMARC record for a domain.
// It follows RFC 7489 §6.6.3 fallback to the Organizational Domain and
// RFC 9091 optional fallback to the Public Suffix Domain (only when psd=y).
func (d *DNSAnalyzer) checkDMARCRecord(domain string) *model.DMARCRecord {
	// Step 1: try exact domain (_dmarc.<domain>)
	raw, notFound, err := d.lookupDMARCAt(domain)
	if err != nil {
		return &model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %v", err)),
		}
	}
	if !notFound {
		return d.parseDMARCRecord(domain, raw)
	}

	// Step 2: RFC 7489 — fall back to Organizational Domain (eTLD+1)
	orgDomain := getOrganizationalDomain(domain)
	if orgDomain != domain {
		raw, notFound, err = d.lookupDMARCAt(orgDomain)
		if err != nil {
			return &model.DMARCRecord{
				Valid: false,
				Error: utils.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %v", err)),
			}
		}
		if !notFound {
			return d.parseDMARCRecord(orgDomain, raw)
		}
	}

	// Step 3: RFC 9091 — fall back to Public Suffix Domain when psd=y
	psd, _ := publicsuffix.PublicSuffix(domain)
	if psd != "" && psd != orgDomain {
		raw, notFound, err = d.lookupDMARCAt(psd)
		if err == nil && !notFound {
			// Only apply PSD DMARC when the record explicitly opts in with psd=y
			if strings.Contains(raw, "psd=y") {
				return d.parseDMARCRecord(psd, raw)
			}
		}
	}

	return &model.DMARCRecord{
		Valid: false,
		Error: utils.PtrTo("No DMARC record found"),
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

func (d *DNSAnalyzer) calculateDMARCScore(results *model.DNSResults) (score int) {
	// DMARC ties SPF and DKIM together and provides policy
	if results.DmarcRecord != nil {
		if results.DmarcRecord.Valid {
			score += 50
			// Bonus points for stricter policies
			if results.DmarcRecord.Policy != nil {
				switch *results.DmarcRecord.Policy {
				case "reject":
					// Strictest policy - full points already awarded
					score += 25
				case "quarantine":
					// Good policy - no deduction
				case "none":
					// Weakest policy - deduct 25 points
					score -= 25
				}
			}
			// Bonus points for strict alignment modes (5 points each)
			if results.DmarcRecord.SpfAlignment != nil && *results.DmarcRecord.SpfAlignment == model.DMARCRecordSpfAlignmentStrict {
				score += 5
			}
			if results.DmarcRecord.DkimAlignment != nil && *results.DmarcRecord.DkimAlignment == model.DMARCRecordDkimAlignmentStrict {
				score += 5
			}
			// Policy strength: none < quarantine < reject
			policyStrength := map[string]int{"none": 0, "quarantine": 1, "reject": 2}
			mainPolicy := string(*results.DmarcRecord.Policy)

			// Subdomain policy scoring (sp tag)
			// +15 for stricter or equal subdomain policy, -15 for weaker
			if results.DmarcRecord.SubdomainPolicy != nil {
				subPolicy := string(*results.DmarcRecord.SubdomainPolicy)
				mainStrength := policyStrength[mainPolicy]
				subStrength := policyStrength[subPolicy]

				if subStrength >= mainStrength {
					// Subdomain policy is equal or stricter
					score += 15
				} else {
					// Subdomain policy is weaker
					score -= 15
				}
			} else {
				// No sp tag means subdomains inherit main policy (good default)
				score += 15
			}
			// Non-existent subdomain policy scoring (np tag, DMARCbis)
			// -15 from base; +15 back if absent (good default) or >= effective sp/p strength
			score -= 15
			effectiveSubPolicy := mainPolicy
			if results.DmarcRecord.SubdomainPolicy != nil {
				effectiveSubPolicy = string(*results.DmarcRecord.SubdomainPolicy)
			}
			if results.DmarcRecord.NonexistentSubdomainPolicy == nil {
				score += 15
			} else {
				npStrength := policyStrength[string(*results.DmarcRecord.NonexistentSubdomainPolicy)]
				effectiveStrength := policyStrength[effectiveSubPolicy]
				if npStrength >= effectiveStrength {
					score += 15
				}
			}
			// Percentage scoring (pct tag)
			// Apply the percentage on the current score
			if results.DmarcRecord.Percentage != nil {
				pct := *results.DmarcRecord.Percentage

				score = score * pct / 100
			}
		} else if results.DmarcRecord.Record != nil {
			// Partial credit if DMARC record exists but has issues
			score += 20
		}
	}

	return
}
