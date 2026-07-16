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

// checkBIMIRecord looks up and validates BIMI record for a domain and selector
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector string) *model.BIMIRecord {
	// BIMI records are at: selector._bimi.domain
	bimiDomain := fmt.Sprintf("%s._bimi.%s", selector, domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, bimiDomain)
	if err != nil {
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo(fmt.Sprintf("Failed to lookup BIMI record: %s", formatDNSError(err))),
		}
	}

	if len(txtRecords) == 0 {
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo("No BIMI record found"),
		}
	}

	// Concatenate all TXT record parts (BIMI can be split)
	bimiRecord := strings.Join(txtRecords, "")

	tags := parseBIMITags(bimiRecord)

	// The record at selector._bimi must begin with a "v=BIMI1" version tag.
	// Some domains (notably several Proofpoint-hosted ones) mistakenly publish
	// a DMARC record at the BIMI location. Such a record is not a malformed
	// BIMI record: it simply is not a BIMI record at all, so report it as
	// "no BIMI record found" rather than surfacing bogus logo/VMC URLs.
	if !isBIMIRecord(tags) {
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Record:   &bimiRecord,
			Valid:    false,
			Error:    utils.PtrTo(notABIMIRecordError(tags)),
		}
	}

	// Extract logo URL (l tag) and VMC URL (a tag)
	logoURL := tags["l"]
	vmcURL := tags["a"]

	// A valid BIMI record must carry a logo URL tag (l=)
	if _, ok := tags["l"]; !ok {
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Record:   &bimiRecord,
			LogoUrl:  &logoURL,
			VmcUrl:   &vmcURL,
			Valid:    false,
			Error:    utils.PtrTo("BIMI record is missing the required logo (l=) tag"),
		}
	}

	record := &model.BIMIRecord{
		Selector: selector,
		Domain:   domain,
		Record:   &bimiRecord,
		LogoUrl:  &logoURL,
		VmcUrl:   &vmcURL,
		Valid:    true,
	}

	// Run evidence checks (logo retrieval, SVG P/S profile, VMC): a BIMI
	// record only leads to a displayed logo if its assets are compliant.
	if !d.runBIMIChecks(record) {
		record.Valid = false
		record.Error = utils.PtrTo("BIMI assets failed validation, see detailed checks below")
	}

	return record
}

// parseBIMITags parses a BIMI record into its tag=value pairs. Pairs are
// separated by ';' and only the first occurrence of a tag is kept. Parsing on
// delimiters (rather than a substring regex) avoids matching a tag name inside
// another tag's value, e.g. "a" inside DMARC's "rua=".
func parseBIMITags(record string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		if key == "" {
			continue
		}
		if _, exists := tags[key]; !exists {
			tags[key] = strings.TrimSpace(kv[1])
		}
	}
	return tags
}

// isBIMIRecord reports whether the parsed tags describe a BIMI record, i.e.
// carry a version tag equal to "BIMI1".
func isBIMIRecord(tags map[string]string) bool {
	v, ok := tags["v"]
	return ok && strings.EqualFold(v, "BIMI1")
}

// notABIMIRecordError builds an explanatory error for a record found at the
// BIMI location that is not a BIMI record, hinting at the likely
// misconfiguration when a known record type is detected.
func notABIMIRecordError(tags map[string]string) string {
	if desc := describeMisplacedRecord(tags["v"], "BIMI"); desc != "" {
		return fmt.Sprintf("No BIMI record found (%s is published at the BIMI location; this is a misconfiguration)", desc)
	}
	return "No BIMI record found (the record at the BIMI location does not begin with v=BIMI1)"
}

// extractBIMITag extracts a tag value from a BIMI record.
func (d *DNSAnalyzer) extractBIMITag(record, tag string) string {
	return parseBIMITags(record)[tag]
}

// validateBIMI performs basic BIMI record validation
func (d *DNSAnalyzer) validateBIMI(record string) bool {
	tags := parseBIMITags(record)

	// Must carry a v=BIMI1 version tag
	if !isBIMIRecord(tags) {
		return false
	}

	// Must have a logo URL tag (l=)
	if _, ok := tags["l"]; !ok {
		return false
	}

	return true
}
