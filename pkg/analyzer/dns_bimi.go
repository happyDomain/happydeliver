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
