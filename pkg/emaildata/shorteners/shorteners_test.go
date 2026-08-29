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

package shorteners

import (
	"regexp"
	"strings"
	"testing"
)

// TestHostsAreSane guards the embedded list against the malformed entries such
// a list tends to accumulate, and against a refresh silently importing junk:
// every key must be a plausible, lowercase, bare hostname (no scheme, no path,
// no port, no wildcard) with a real TLD, and the comment header must not leak
// into the data.
func TestHostsAreSane(t *testing.T) {
	hostRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

	hosts := Hosts()

	if len(hosts) < 1000 {
		t.Errorf("only %d shorteners known, the embedded list looks truncated", len(hosts))
	}

	for host := range hosts {
		if !hostRegex.MatchString(host) {
			t.Errorf("shortener entry %q is not a plain lowercase hostname", host)
		}
		if strings.HasPrefix(host, "www.") {
			t.Errorf("shortener entry %q carries a www. prefix, which NormalizeHost strips before matching", host)
		}
	}
}

// TestNormalizeHost holds the one shape a host is looked up under.
func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"bit.ly":       "bit.ly",
		"  BIT.LY\n":   "bit.ly",
		"www.bit.ly":   "bit.ly",
		"WWW.Bit.Ly ":  "bit.ly",
		"wwwbit.ly":    "wwwbit.ly",
		"a.www.bit.ly": "a.www.bit.ly",
	}

	for host, want := range tests {
		if got := NormalizeHost(host); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", host, got, want)
		}
	}
}
