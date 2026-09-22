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

package disposable

import (
	"regexp"
	"strings"
	"testing"
)

// TestHostsAreSane checks every key is a plausible, lowercase, bare hostname,
// guarding against a refresh silently importing junk.
func TestHostsAreSane(t *testing.T) {
	hostRegex := regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.[a-z]{2,}$`)

	hosts := Hosts()

	if len(hosts) < 1000 {
		t.Errorf("only %d disposable domains known, the embedded list looks truncated", len(hosts))
	}

	for host := range hosts {
		if !hostRegex.MatchString(host) {
			t.Errorf("disposable entry %q is not a plain lowercase hostname", host)
		}
	}
}

func TestIs(t *testing.T) {
	// The list has to hold at least one well-known throwaway provider, and
	// must not hold the domains reserved for documentation.
	var listed string
	for _, candidate := range []string{"mailinator.com", "guerrillamail.com", "yopmail.com"} {
		if _, ok := Hosts()[candidate]; ok {
			listed = candidate
			break
		}
	}
	if listed == "" {
		t.Fatal("none of the well-known throwaway providers is in the list")
	}

	tests := map[string]bool{
		listed:                  true,
		strings.ToUpper(listed): true,
		"  " + listed + ".\n":   true,
		"mail." + listed:        true,
		"deep.sub." + listed:    true,
		"example-not-" + listed: false,
		"example.com":           false,
		"example.net":           false,
		"":                      false,
		"com":                   false,
	}

	for domain, want := range tests {
		if got := Is(domain); got != want {
			t.Errorf("Is(%q) = %v, want %v", domain, got, want)
		}
	}
}

// TestNoticeSaysWhatTheDedicationRequires checks the notice names the source
// and license terms.
func TestNoticeSaysWhatTheDedicationRequires(t *testing.T) {
	for _, want := range []string{
		"https://github.com/disposable-email-domains/disposable-email-domains",
		"CC0-1.0",
		"https://creativecommons.org/publicdomain/zero/1.0/",
		"Changes:",
	} {
		if !strings.Contains(Attribution, want) {
			t.Errorf("Attribution is missing %q", want)
		}
	}
	if !strings.Contains(License, "CC0 1.0 Universal") {
		t.Error("License does not carry the CC0 dedication text")
	}
}
