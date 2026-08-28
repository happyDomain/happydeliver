// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

package bimi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Lookup resolves and parses the BIMI record published at
// selector._bimi.domain. It returns ErrNoRecord when the name holds no TXT
// record at all, or the resolver error when the DNS query fails. Assets are
// not validated; call ValidateAssets or use Analyze for that.
//
// A name can hold several TXT records, of which only those starting with the
// BIMI version tag are BIMI records; publishing more than one of those is an
// error that leaves the domain without a usable record, and is reported as
// such on the returned Record.
func (v *Validator) Lookup(ctx context.Context, domain, selector string) (*Record, error) {
	if v.Resolver == nil {
		return nil, errors.New("bimi: Validator.Resolver is nil")
	}

	name := fmt.Sprintf("%s._bimi.%s", selector, domain)
	txtRecords, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(txtRecords) == 0 {
		return nil, ErrNoRecord
	}

	// Each element returned by the resolver is one whole TXT record: the
	// character-strings a single record is split into are concatenated by
	// the resolver itself. Several records therefore have to be selected
	// between, never joined together.
	var candidates []string
	for _, txt := range txtRecords {
		if hasBIMIVersionTag(txt) {
			candidates = append(candidates, txt)
		}
	}

	switch len(candidates) {
	case 0:
		// No BIMI record here, but something else is: report the record
		// most likely to explain the misconfiguration.
		return ParseRecord(domain, selector, mostTellingRecord(txtRecords)), nil

	case 1:
		return ParseRecord(domain, selector, candidates[0]), nil

	default:
		return &Record{
			Selector: selector,
			Domain:   domain,
			Record:   strings.Join(candidates, "\n"),
			Error: fmt.Sprintf("%d BIMI records are published at %s: a domain must publish exactly one, so none of them can be used",
				len(candidates), name),
		}, nil
	}
}

// mostTellingRecord picks, among the TXT records found at a BIMI location
// where none is a BIMI record, the one whose error message will help most:
// a record carrying a leading "v=" tag names the type published by mistake,
// where an unrelated TXT record (a verification token, say) says nothing.
func mostTellingRecord(txtRecords []string) string {
	for _, txt := range txtRecords {
		if leadingVersion(txt) != "" {
			return txt
		}
	}
	return txtRecords[0]
}
