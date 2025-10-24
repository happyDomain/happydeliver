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

	"git.happydns.org/happyDeliver/internal/api"
)

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

func (d *DNSAnalyzer) calculateDKIMScore(results *api.DNSResults) (score int) {
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
