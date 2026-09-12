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
	"net"
	"strings"
)

// bimiLocation is one BIMI DNS location visited during Assertion Record
// discovery, together with what was published there.
type bimiLocation struct {
	// name is the queried DNS name (<selector>._bimi.<domain>).
	name string
	// domain is the domain that name belongs to.
	domain string
	// txt holds every TXT record published at name.
	txt []string
	// bimi holds those of txt that are BIMI records.
	bimi []string
}

// isNameNotFound reports whether a resolver error means the queried name holds
// no record, as opposed to the query having failed to get an answer at all.
// Assertion Record discovery rests on that distinction: an empty location
// leads to the organizational domain, whereas a resolution failure must not,
// or a transient DNS error on a subdomain would silently hand it the
// Indicator of its parent.
func isNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// lookupLocation queries one BIMI location and sorts out what it holds,
// keeping the records that carry the BIMI version tag apart from the rest. A
// name that does not exist yields an empty location, not an error.
func (v *Validator) lookupLocation(ctx context.Context, domain, selector string) (bimiLocation, error) {
	loc := bimiLocation{
		name:   fmt.Sprintf("%s._bimi.%s", selector, domain),
		domain: domain,
	}

	// loc.name keeps the relative form the report displays, while the query
	// is issued on the absolute name: see absoluteName.
	txtRecords, err := v.Resolver.LookupTXT(ctx, absoluteName(loc.name))
	if err != nil {
		if isNameNotFound(err) {
			return loc, nil
		}
		return loc, err
	}

	// Each element returned by the resolver is one whole TXT record: the
	// character-strings a single record is split into are concatenated by
	// the resolver itself. Several records therefore have to be selected
	// between, never joined together.
	loc.txt = txtRecords
	for _, txt := range txtRecords {
		if hasBIMIVersionTag(txt) {
			loc.bimi = append(loc.bimi, txt)
		}
	}

	return loc, nil
}

// Lookup performs BIMI Assertion Record discovery for domain and selector: it
// resolves selector._bimi.domain and, when that name publishes no BIMI record,
// falls back to selector._bimi.<organizational domain>, the record a domain
// without one of its own inherits. The record's origin is reported by
// Record.RecordDomain and Record.Inherited.
//
// It returns ErrNoRecord when no visited location holds any TXT record, or the
// resolver error when a DNS query fails. Assets are not validated; call
// ValidateAssets or use Analyze for that.
//
// A name can hold several TXT records, of which only those starting with the
// BIMI version tag are BIMI records; publishing more than one of those is an
// error that leaves the domain without a usable record, and is reported as
// such on the returned Record.
//
// Discovery for a message whose sender is known should go through
// LookupForLocalPart instead, so that a record publishing an lps= tag can
// direct it to the Indicator it reserves for that mailbox.
func (v *Validator) Lookup(ctx context.Context, domain, selector string) (*Record, error) {
	return v.LookupForLocalPart(ctx, domain, selector, "")
}

// LookupForLocalPart performs Assertion Record discovery like Lookup, and
// additionally honours the Local-part Selector: when the record found carries
// an lps= tag whose prefix list matches localPart, the selector derived from
// that local-part is looked up at the same domain and its record used instead.
// A domain owner uses it to serve a distinct Indicator per mailbox, or to
// decline BIMI for some of them, without having to set a BIMI-Selector header
// on the outgoing mail.
//
// localPart is the local-part of the RFC5322.From address, unquoted and
// without the '@'. An empty localPart makes this exactly Lookup: with no
// sender to derive a selector from, an lps= tag cannot apply.
//
// The refinement never costs the caller the record it already has. A
// local-part no selector can be derived from, a prefix list that does not
// match, a derived location that is empty, that publishes several records or
// that publishes a malformed one all leave the record found at the requested
// selector in place, as the specification requires.
func (v *Validator) LookupForLocalPart(ctx context.Context, domain, selector, localPart string) (*Record, error) {
	if v.Resolver == nil {
		return nil, errors.New("bimi: Validator.Resolver is nil")
	}

	author, err := v.lookupLocation(ctx, domain, selector)
	if err != nil {
		return nil, err
	}
	locations := []bimiLocation{author}

	// A domain publishing no BIMI record inherits the one its organizational
	// domain publishes for the same selector. Only an empty location leads
	// there: a record found but unusable, malformed or one of several, is
	// the domain's own answer and is reported as such rather than papered
	// over with its parent's.
	if len(author.bimi) == 0 {
		if org := v.organizationalDomain(domain); org != "" && org != normalizeDomain(domain) {
			orgLocation, err := v.lookupLocation(ctx, org, selector)
			if err != nil {
				return nil, err
			}
			locations = append(locations, orgLocation)
		}
	}

	for _, loc := range locations {
		switch len(loc.bimi) {
		case 0:
			continue

		case 1:
			rec := ParseRecord(domain, selector, loc.bimi[0])
			rec.RecordDomain = loc.domain
			return v.applyLocalPartSelector(ctx, rec, loc, localPart), nil

		default:
			return &Record{
				Selector:          selector,
				RequestedSelector: selector,
				Domain:            domain,
				RecordDomain:      loc.domain,
				Record:            strings.Join(loc.bimi, "\n"),
				Error: fmt.Sprintf("%d BIMI records are published at %s: a domain must publish exactly one, so none of them can be used",
					len(loc.bimi), loc.name),
			}, nil
		}
	}

	// No BIMI record anywhere, but something else may be there: report the
	// record most likely to explain the misconfiguration, preferring the
	// queried domain's own location over the organizational domain's.
	for _, loc := range locations {
		if len(loc.txt) > 0 {
			rec := ParseRecord(domain, selector, mostTellingRecord(loc.txt))
			rec.RecordDomain = loc.domain
			return rec, nil
		}
	}

	return nil, ErrNoRecord
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
