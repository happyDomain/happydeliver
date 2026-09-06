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
	"strings"
)

// MaxLocalPartSelectorLength is the longest a local-part selector, and each of
// the lps= prefixes it is matched against, may be.
const MaxLocalPartSelectorLength = 63

// parseLocalPartPrefixes splits the value of an lps= tag into its comma
// separated local-part prefixes, stripping the whitespace the syntax allows
// around each of them ("lps = brand-one , brand-two" is two prefixes).
//
// An empty value yields no prefix at all, which is not the same as no lps=
// tag: it means every local-part matches, and Record.LocalPartSelector is what
// tells the two apart. An empty entry inside a non-empty list, on the other
// hand, is kept, so that it is reported as the malformed prefix it is rather
// than silently widening the list to every local-part.
func parseLocalPartPrefixes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	prefixes := strings.Split(value, ",")
	for i, prefix := range prefixes {
		prefixes[i] = strings.TrimSpace(prefix)
	}
	return prefixes
}

// firstInvalidLocalPartPrefix returns the first prefix that does not match the
// local-part prefix syntax, and whether there is one.
func firstInvalidLocalPartPrefix(prefixes []string) (string, bool) {
	for _, prefix := range prefixes {
		if !isLocalPartSelectorText(prefix) {
			return prefix, true
		}
	}
	return "", false
}

// isLocalPartSelectorText reports whether s is 1 to 63 letters, digits or
// dashes: the character set both a local-part prefix and the selector derived
// from a local-part are restricted to.
func isLocalPartSelectorText(s string) bool {
	if s == "" || len(s) > MaxLocalPartSelectorLength {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
	}) < 0
}

// NormalizeLocalPart derives a BIMI selector from the local-part of a sending
// address, so that a Domain Owner publishing an lps= tag can serve a distinct
// Indicator per mailbox. It returns false when the local-part cannot be used
// as a selector, which is not an error: the specification presents it as an
// expected limitation of addresses built from a wider character set, and the
// record found at the original selector is then the one that applies.
//
// The derivation strips any subaddress extension ("bob+news" is "bob"), folds
// underscores and periods into dashes, collapses each run of dashes into one
// and trims the dashes at both ends. What remains must be letters, digits and
// dashes, and no longer than MaxLocalPartSelectorLength. The result is
// lowercased, selectors being case-insensitive where local-parts need not be.
func NormalizeLocalPart(localPart string) (string, bool) {
	// Subaddress extension: everything from the first '+' on is not part of
	// the mailbox identity.
	if plus := strings.IndexByte(localPart, '+'); plus >= 0 {
		localPart = localPart[:plus]
	}

	var b strings.Builder
	b.Grow(len(localPart))
	for _, r := range localPart {
		if r == '_' || r == '.' {
			r = '-'
		}
		// Collapse a run of dashes, however it was spelled, into one, and
		// drop the leading ones along the way.
		if r == '-' && (b.Len() == 0 || b.String()[b.Len()-1] == '-') {
			continue
		}
		b.WriteRune(r)
	}

	selector := strings.TrimSuffix(b.String(), "-")
	if !isLocalPartSelectorText(selector) {
		return "", false
	}

	return strings.ToLower(selector), true
}

// matchesLocalPart reports whether the record asks for a local-part selector
// lookup for the given derived selector: it publishes an lps= tag, and either
// that tag lists no prefix, in which case every local-part matches, or one of
// its prefixes matches the start of the selector.
//
// Matching happens on the derived selector rather than on the raw local-part:
// the prefixes are restricted to the very character set the derivation
// produces, so comparing against the raw form would make a prefix unable to
// match the addresses it is written for.
func (r *Record) matchesLocalPart(selector string) bool {
	if !r.LocalPartSelector {
		return false
	}
	if len(r.LocalPartPrefixes) == 0 {
		return true
	}

	for _, prefix := range r.LocalPartPrefixes {
		if strings.HasPrefix(selector, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// applyLocalPartSelector carries out the Local-part Selector step of Assertion
// Record discovery on the record just found at loc: if rec asks for it through
// an lps= tag matching localPart, the selector derived from that local-part is
// looked up at the same domain, and the record published there returned in
// rec's place.
//
// It is applied per location rather than once at the end, because discovery
// runs the step at every location it visits: a subdomain that publishes its
// own record refines it against its own local-part selectors, and one that
// inherits its organizational domain's refines it against that domain's.
//
// A record that fails syntax validation asks for nothing: its lps= tag is no
// more trustworthy than the rest of it, and following the tag would hide the
// broken record every other sender at that domain lands on behind the valid
// one the refinement leads to.
//
// Anything short of exactly one usable record at the derived location leaves
// rec untouched, a resolver failure included: the refinement is an
// improvement over an Indicator the caller already holds, so a transient DNS
// error on it must not cost the caller that Indicator, and even less turn the
// whole discovery into an error.
func (v *Validator) applyLocalPartSelector(ctx context.Context, rec *Record, loc bimiLocation, localPart string) *Record {
	if localPart == "" || !rec.RecordValid || !rec.LocalPartSelector {
		return rec
	}

	derived, ok := NormalizeLocalPart(localPart)
	if !ok || !rec.matchesLocalPart(derived) {
		return rec
	}

	// Only a selector that has not been queried at this domain yet is worth
	// a second query: a mailbox whose name is already the selector asked for
	// would only resolve the same name again.
	if strings.EqualFold(derived, rec.Selector) {
		return rec
	}

	derivedLoc, err := v.lookupLocation(ctx, loc.domain, derived)
	if err != nil || len(derivedLoc.bimi) != 1 {
		return rec
	}

	derivedRec := ParseRecord(rec.Domain, derived, derivedLoc.bimi[0])
	if !derivedRec.RecordValid {
		return rec
	}

	derivedRec.RequestedSelector = rec.RequestedSelector
	derivedRec.RecordDomain = loc.domain
	return derivedRec
}
