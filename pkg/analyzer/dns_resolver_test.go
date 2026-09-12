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

import "testing"

// TestAbsoluteDNSName pins the form every query leaves in. A relative name is
// completed with the search list of the host's /etc/resolv.conf once it turns
// out not to exist, and a wildcard published under any of those suffixes then
// answers in place of the name asked for: the analysed domain is credited with
// a record it never published, and an RBL reports a listing it never made.
func TestAbsoluteDNSName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"Relative name is qualified", "default._bimi.example.com", "default._bimi.example.com."},
		{"Absolute name is left alone", "_dmarc.example.com.", "_dmarc.example.com."},
		{"RBL query is qualified", "1.2.0.192.zen.example.org", "1.2.0.192.zen.example.org."},
		{"Empty name is left alone", "", ""},
		// LookupHost takes an address literal in place of a name: a
		// trailing dot would turn it into a name to be resolved.
		{"IPv4 literal is left alone", "192.0.2.1", "192.0.2.1"},
		{"IPv6 literal is left alone", "2001:db8::1", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := absoluteDNSName(tt.in); got != tt.want {
				t.Errorf("absoluteDNSName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
