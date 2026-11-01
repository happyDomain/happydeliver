// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package netguard

import "testing"

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		"10.0.0.1":        false,
		"172.16.3.4":      false,
		"192.168.1.1":     false,
		"127.0.0.1":       false,
		"169.254.1.1":     false,
		"100.64.0.1":      false,
		"192.0.2.1":       false,
		"198.51.100.7":    false,
		"203.0.113.9":     false,
		"255.255.255.255": false,
		"0.0.0.0":         false,
		"::1":             false,
		"fe80::1":         false,
		"fd00::1":         false,
		"2001:db8::1":     false,
		"::ffff:10.0.0.1": false,
		"not an address":  false,
	} {
		if got := IsPublicString(addr); got != want {
			t.Errorf("IsPublicString(%q) = %v, want %v", addr, got, want)
		}
	}
}
