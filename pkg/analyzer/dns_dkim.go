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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// DKIMHeader holds the domain and selector extracted from a DKIM-Signature header.
type DKIMHeader struct {
	Domain   string
	Selector string
}

// parseDKIMSignatures extracts domain and selector from DKIM-Signature header values.
func parseDKIMSignatures(signatures []string) []DKIMHeader {
	var results []DKIMHeader
	for _, sig := range signatures {
		var domain, selector string
		for _, part := range strings.Split(sig, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch key {
			case "d":
				domain = val
			case "s":
				selector = val
			}
		}
		if domain != "" && selector != "" {
			results = append(results, DKIMHeader{Domain: domain, Selector: selector})
		}
	}
	return results
}

// checkmodel.DKIMRecord looks up and validates DKIM record for a domain and selector
func (d *DNSAnalyzer) checkDKIMRecord(domain, selector string) *model.DKIMRecord {
	// DKIM records are at: selector._domainkey.domain
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dkimDomain)
	if err != nil {
		return &model.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo(fmt.Sprintf("Failed to lookup DKIM record: %v", err)),
		}
	}

	if len(txtRecords) == 0 {
		return &model.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo("No DKIM record found"),
		}
	}

	// Concatenate all TXT record parts (DKIM can be split)
	dkimRecord := strings.Join(txtRecords, "")

	// Basic validation - should contain "v=DKIM1" and "p=" (public key)
	if !d.validateDKIM(dkimRecord) {
		return &model.DKIMRecord{
			Selector: selector,
			Domain:   domain,
			Record:   utils.PtrTo(dkimRecord),
			Valid:    false,
			Error:    utils.PtrTo("DKIM record appears malformed"),
		}
	}

	return &model.DKIMRecord{
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

func (d *DNSAnalyzer) calculateDKIMScore(results *model.DNSResults) (score int) {
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
			score += 100
		} else {
			// Partial credit if DKIM record exists but has issues
			score += 25
		}
	}

	return
}
