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

package domainset

import "testing"

func TestFromLines(t *testing.T) {
	set := FromLines("# a comment\n\nExample.COM\nmail.example.net.\n  spaced.example.org  \n")

	for _, domain := range []string{"example.com", "mail.example.net", "spaced.example.org"} {
		if _, ok := set[domain]; !ok {
			t.Errorf("FromLines() did not key %q", domain)
		}
	}
	if len(set) != 3 {
		t.Errorf("FromLines() = %d entries, want 3: comments and blank lines are not domains", len(set))
	}
}

func TestFromSlice(t *testing.T) {
	set := FromSlice([]string{"Example.COM", "", "  example.net.  "})

	if len(set) != 2 {
		t.Fatalf("FromSlice() = %d entries, want 2", len(set))
	}
	if _, ok := set["example.com"]; !ok {
		t.Error("FromSlice() did not normalise example.com")
	}
}

func TestHas(t *testing.T) {
	set := FromSlice([]string{"example.com"})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM.", true},
		{"mail.example.com", true}, // a subdomain of a listed provider is that provider
		{"deep.mail.example.com", true},
		{"example.net", false},
		{"notexample.com", false},
		{"com", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := set.Has(tt.domain); got != tt.want {
			t.Errorf("Has(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}
