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

	"git.happydns.org/happyDeliver/internal/api"
)

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

func (d *DNSAnalyzer) calculateMXScore(results *api.DNSResults) (score int) {
	// Having valid MX records is critical for email deliverability
	// From domain MX records (half points) - needed for replies
	if results.FromMxRecords != nil && len(*results.FromMxRecords) > 0 {
		hasValidFromMX := false
		for _, mx := range *results.FromMxRecords {
			if mx.Valid {
				hasValidFromMX = true
				break
			}
		}
		if hasValidFromMX {
			score += 50
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
			score += 50
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
				score += 50
			}
		}
	}

	return
}
