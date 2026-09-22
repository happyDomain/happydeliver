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

package freemail

import (
	"bytes"
	"log"
	"os"
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
		t.Errorf("only %d free providers known, the embedded list looks truncated", len(hosts))
	}

	for host := range hosts {
		if !hostRegex.MatchString(host) {
			t.Errorf("free provider entry %q is not a plain lowercase hostname", host)
		}
	}
}

func TestIs(t *testing.T) {
	// The list has to hold the providers everybody knows, and must not hold
	// the domains reserved for documentation.
	tests := map[string]bool{
		"gmail.com":             true,
		"GMAIL.COM":             true,
		"  outlook.com.\n":      true,
		"yahoo.fr":              true,
		"mail.gmail.com":        true,
		"example-not-gmail.com": false,
		// Sending infrastructure the upstream list carries, and the
		// subdomains an ESP actually signs its bounces with.
		"amazonses.com":           false,
		"us-east-1.amazonses.com": false,
		"example.com":           false,
		"example.org":           false,
		"":                      false,
		"com":                   false,
	}

	for domain, want := range tests {
		if got := Is(domain); got != want {
			t.Errorf("Is(%q) = %v, want %v", domain, got, want)
		}
	}
}

// TestLoadHostsOnAnUnreadableList checks a malformed embedded list degrades
// to an empty, usable set rather than taking an analysis down with it. The
// list is embedded at build time, so this can only happen to a broken build,
// and the breakage has to be reported rather than swallowed.
func TestLoadHostsOnAnUnreadableList(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	embedded := list
	t.Cleanup(func() { list = embedded })
	list = []byte(`{"gmail.com": true}`) // an object, where a JSON array of domains is expected

	hosts := loadHosts()

	if hosts == nil {
		t.Fatal("loadHosts() = nil, want an empty set callers can still query")
	}
	if len(hosts) != 0 {
		t.Errorf("loadHosts() = %d entries, want 0 for a list that cannot be read", len(hosts))
	}
	if hosts.Has("gmail.com") {
		t.Error("loadHosts() reported a known provider from a list it could not read")
	}
	if !strings.Contains(logged.String(), "the embedded list cannot be read") {
		t.Errorf("loadHosts() did not report the broken list, logged %q", logged.String())
	}
}

// TestNoticeSaysWhatTheLicenseRequires checks the notice carries the MIT
// copyright and permission notices.
func TestNoticeSaysWhatTheLicenseRequires(t *testing.T) {
	for _, want := range []string{
		"Kiko Beats",
		"https://github.com/Kikobeats/free-email-domains",
		"MIT",
		"Changes:",
	} {
		if !strings.Contains(Attribution, want) {
			t.Errorf("Attribution is missing %q", want)
		}
	}
	if !strings.Contains(License, "Permission is hereby granted") {
		t.Error("License does not carry the MIT permission notice")
	}
}
