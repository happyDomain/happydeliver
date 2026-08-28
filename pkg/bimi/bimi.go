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

// Package bimi validates Brand Indicators for Message Identification (BIMI)
// records.
//
// The package is self-contained and has no dependency on the rest of
// happyDeliver, so it can be reused as a standalone BIMI validation library.
//
// A minimal use looks like:
//
//	v := bimi.NewValidator()
//	rec, err := v.Lookup(ctx, "example.com", "default")
//
// The returned Record describes whether the record is syntactically valid
// (Valid, Error). Evidence checks on the assets it references (the logo and
// the Verified Mark Certificate) are added by later validators built on top
// of this package.
package bimi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ErrNoRecord is returned by Lookup when the domain publishes no BIMI record
// for the requested selector.
var ErrNoRecord = errors.New("no BIMI record found")

// Record is a parsed BIMI record.
type Record struct {
	// Selector is the BIMI selector queried (e.g. "default").
	Selector string
	// Domain is the domain the record belongs to.
	Domain string
	// Record is the raw TXT record content.
	Record string
	// LogoURL is the value of the l= tag (empty for a declination record).
	LogoURL string
	// VMCURL is the value of the a= tag (empty when no VMC is published).
	VMCURL string
	// Valid reports whether the record is syntactically compliant.
	Valid bool
	// Error, when set, explains why the record is invalid.
	Error string
}

// Resolver looks up DNS TXT records. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validator gathers the dependencies needed to look up and validate BIMI
// records. The zero value is not usable: Resolver is required for Lookup.
type Validator struct {
	// Resolver performs the DNS TXT lookup.
	Resolver Resolver
	// Now returns the reference time for time-sensitive checks. Defaults to
	// time.Now.
	Now func() time.Time
}

// NewValidator returns a Validator ready to use, backed by the system DNS
// resolver. Callers that need a custom resolver or reference time can set
// the corresponding fields on the returned Validator, or build the struct
// literal directly.
func NewValidator() *Validator {
	return &Validator{
		Resolver: &net.Resolver{},
	}
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// BIMI tag matchers. A tag must appear at the start of the record or right
// after a ';' separator so that a value which happens to contain "<tag>="
// (e.g. "html=1" for tag "l") is not misread as that tag. The tag set is
// fixed, so the regexps are compiled once at package load.
var (
	bimiLogoTag = regexp.MustCompile(`(?:^|;)\s*l=([^;]+)`)
	bimiVMCTag  = regexp.MustCompile(`(?:^|;)\s*a=([^;]+)`)
	bimiHasLogo = regexp.MustCompile(`(?:^|;)\s*l=`)
)

// bimiTag extracts a tag value from a BIMI record using the given precompiled
// matcher (whose first submatch is the value).
func bimiTag(record string, re *regexp.Regexp) string {
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// ParseRecord parses a raw BIMI TXT record into a Record. The Record's
// LogoURL and VMCURL are always populated from the l= and a= tags. When the
// record is syntactically valid, Valid is true and Error is empty; otherwise
// Valid is false and Error explains why. No asset is fetched.
func ParseRecord(domain, selector, txt string) *Record {
	rec := &Record{
		Selector: selector,
		Domain:   domain,
		Record:   txt,
		LogoURL:  bimiTag(txt, bimiLogoTag),
		VMCURL:   bimiTag(txt, bimiVMCTag),
	}

	switch {
	case !strings.HasPrefix(txt, "v=BIMI1"):
		rec.Error = notABIMIRecordError(txt)
	case !bimiHasLogo.MatchString(txt):
		rec.Error = "BIMI record is missing the l= (logo URL) tag"
	default:
		rec.Valid = true
	}

	return rec
}

// notABIMIRecordError builds an explanatory error for a record found at the
// BIMI location that is not a BIMI record, hinting at the likely
// misconfiguration when a known record type is detected (commonly a DMARC
// record placed there by mistake).
func notABIMIRecordError(txt string) string {
	if desc := describeMisplacedRecord(leadingVersion(txt), "BIMI"); desc != "" {
		return fmt.Sprintf("No BIMI record found (%s is published at the BIMI location; this is a misconfiguration)", desc)
	}
	return "No BIMI record found (the record at the BIMI location does not begin with v=BIMI1)"
}

// leadingVersion returns the value of a record's leading "v=" tag (up to the
// first ';' or whitespace), or "" if the record does not start with one. It
// handles both ';'-delimited records (BIMI/DKIM/DMARC) and space-delimited
// ones (SPF).
func leadingVersion(record string) string {
	r := strings.TrimSpace(record)
	if !strings.HasPrefix(r, "v=") {
		return ""
	}
	v := r[len("v="):]
	if i := strings.IndexAny(v, "; \t"); i >= 0 {
		v = v[:i]
	}
	return v
}

// describeMisplacedRecord returns a human-readable description ("a DMARC
// record", "an SPF record", …) of a record identified by its "v=" version
// value, or "" when the version is unknown. It is used to explain the common
// misconfiguration (or misbehaving resolver) where a record of the wrong type
// is served at a BIMI/DKIM/SPF location.
//
// ownFamily names the record type expected at the caller's location (e.g.
// "BIMI" for a BIMI lookup). A record whose version belongs to that family
// (an unsupported-version record of the location's own type) is not
// "misplaced", so "" is returned and the caller falls back to its generic
// message.
func describeMisplacedRecord(version, ownFamily string) string {
	v := strings.ToUpper(version)
	if ownFamily != "" && strings.HasPrefix(v, strings.ToUpper(ownFamily)) {
		return ""
	}
	switch {
	case strings.HasPrefix(v, "DMARC"):
		return "a DMARC record"
	case strings.HasPrefix(v, "SPF"):
		return "an SPF record"
	case strings.HasPrefix(v, "DKIM"):
		return "a DKIM record"
	case strings.HasPrefix(v, "BIMI"):
		return "a BIMI record"
	default:
		return ""
	}
}

// Lookup resolves and parses the BIMI record published at
// selector._bimi.domain. It returns ErrNoRecord when no record exists, or the
// resolver error when the DNS query fails.
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

	// BIMI records can be split across several TXT strings.
	return ParseRecord(domain, selector, strings.Join(txtRecords, "")), nil
}
