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
	"fmt"
	"slices"
	"strings"
)

// bimiTagSpec is one "name=value" pair of a BIMI record, with the folding
// whitespace the syntax allows already stripped.
type bimiTagSpec struct {
	name  string
	value string
}

// splitTagList splits a BIMI record into its tag specifications. BIMI records
// follow the extensible "tag=value" syntax of DKIM (RFC 6376, Section 3.2):
// specifications are separated by ';', a trailing ';' is allowed, and folding
// whitespace is permitted around the tag name, the '=' and the value ("v =
// BIMI1" and "v=BIMI1" are the same tag).
//
// Specifications with no '=' at all are returned separately as malformed: the
// caller reports them rather than guessing what was meant, since a receiver
// must not attempt to repair a syntax error.
func splitTagList(record string) (tags []bimiTagSpec, malformed []string) {
	for _, spec := range strings.Split(record, ";") {
		if strings.TrimSpace(spec) == "" {
			continue
		}

		name, value, found := strings.Cut(spec, "=")
		if !found {
			malformed = append(malformed, strings.TrimSpace(spec))
			continue
		}

		tags = append(tags, bimiTagSpec{
			name:  strings.TrimSpace(name),
			value: strings.TrimSpace(value),
		})
	}

	return tags, malformed
}

// hasBIMIVersionTag reports whether a TXT record starts with the BIMI version
// tag. The specification requires the value to match precisely and the tag to
// come first, so "v=BIMI12" or a record whose first tag is anything else is
// not a BIMI record: it must be discarded rather than repaired.
func hasBIMIVersionTag(txt string) bool {
	tags, _ := splitTagList(txt)
	return len(tags) > 0 && tags[0].name == "v" && tags[0].value == "BIMI1"
}

// ParseRecord parses a raw BIMI TXT record into a Record. The Record's
// LogoURL and VMCURL are always populated from the l= and a= tags. When the
// record is syntactically valid, Valid is true and Error is empty; otherwise
// Valid is false and Error explains why. No asset is fetched.
func ParseRecord(domain, selector, txt string) *Record {
	rec := &Record{
		Selector:     selector,
		Domain:       domain,
		RecordDomain: domain,
		Record:       txt,
	}

	tags, malformed := splitTagList(txt)

	// A tag may appear only once; the value kept for the duplicated ones is
	// the first, but the record is reported as an error either way.
	seen := make(map[string]bool, len(tags))
	var duplicates []string
	for _, tag := range tags {
		if seen[tag.name] {
			if !slices.Contains(duplicates, tag.name) {
				duplicates = append(duplicates, tag.name)
			}
			continue
		}
		seen[tag.name] = true

		switch tag.name {
		case "l":
			rec.LogoURL = tag.value
		case "a":
			rec.VMCURL = tag.value
		}
	}

	switch {
	case !hasBIMIVersionTag(txt):
		rec.Error = notABIMIRecordError(txt)
	case len(malformed) > 0:
		rec.Error = fmt.Sprintf("BIMI record contains a tag without a value: %q", malformed[0])
	case len(duplicates) > 0:
		rec.Error = fmt.Sprintf("BIMI record publishes the %s tag more than once: each tag may appear only once", quotedTagNames(duplicates))
	case !seen["l"]:
		rec.Error = "BIMI record is missing the l= (logo URL) tag"
	default:
		rec.RecordValid = true
		rec.Valid = true
	}

	return rec
}

// quotedTagNames renders tag names as a human-readable enumeration
// ("l=", or "l= and a=").
func quotedTagNames(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = n + "="
	}
	if len(quoted) < 2 {
		return strings.Join(quoted, "")
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
}

// notABIMIRecordError builds an explanatory error for a record found at the
// BIMI location that is not a BIMI record, hinting at the likely
// misconfiguration when a known record type is detected (commonly a DMARC
// record placed there by mistake).
func notABIMIRecordError(txt string) string {
	if desc := describeMisplacedRecord(leadingVersion(txt), "BIMI"); desc != "" {
		return fmt.Sprintf("No BIMI record found (%s is published at the BIMI location; this is a misconfiguration)", desc)
	}
	return "No BIMI record found (the record at the BIMI location does not start with a v=BIMI1 tag)"
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
