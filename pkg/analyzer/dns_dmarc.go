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

func (d *DNSAnalyzer) calculateDMARCScore(results *api.DNSResults) (score int) {
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
					// Weakest policy - deduct 5 points
					score -= 25
				}
			}
			// Bonus points for strict alignment modes (2 points each)
			if results.DmarcRecord.SpfAlignment != nil && *results.DmarcRecord.SpfAlignment == api.DMARCRecordSpfAlignmentStrict {
				score += 5
			}
			if results.DmarcRecord.DkimAlignment != nil && *results.DmarcRecord.DkimAlignment == api.DMARCRecordDkimAlignmentStrict {
				score += 5
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
					score += 15
				} else {
					// Subdomain policy is weaker
					score -= 15
				}
			} else {
				// No sp tag means subdomains inherit main policy (good default)
				score += 15
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
