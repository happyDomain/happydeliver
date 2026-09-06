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

import "strings"

// MaxLocalPartSelectorLength is the longest a local-part prefix of the lps=
// tag may be.
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
// dashes, the character set a local-part prefix is restricted to.
func isLocalPartSelectorText(s string) bool {
	if s == "" || len(s) > MaxLocalPartSelectorLength {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
	}) < 0
}
