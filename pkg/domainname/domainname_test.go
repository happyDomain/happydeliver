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

package domainname

import "testing"

// TestNormalize holds the one form a hostname is compared under.
func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"mail.example.com":    "mail.example.com",
		"Mail.Example.Com.":   "mail.example.com",
		"  MAIL.EXAMPLE.COM ": "mail.example.com",
		".":                   "",
		"":                    "",
	}

	for hostname, want := range tests {
		if got := Normalize(hostname); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", hostname, got, want)
		}
	}
}

// TestOrganizational says which names are read as one party.
//
// The multi-label suffixes are the reason this goes through the Public Suffix
// List at all: counting two labels would make "example.co.uk" read as "co.uk",
// and every domain under it would answer as the same organisation.
func TestOrganizational(t *testing.T) {
	tests := map[string]string{
		"mail.example.com":     "example.com",
		"example.com":          "example.com",
		"mail.example.co.uk":   "example.co.uk",
		"a.b.c.example.org":    "example.org",
		"EXAMPLE.NET":          "example.net",
		"  mail.example.com  ": "example.com",
		// A name with nothing to strip is its own organisational domain.
		"localhost": "localhost",
	}

	for domain, want := range tests {
		if got := Organizational(domain); got != want {
			t.Errorf("Organizational(%q) = %q, want %q", domain, got, want)
		}
	}
}

// TestHostOfURL says which URLs name a host at all: one on the web, read in
// the form hosts are compared under, whatever port or brackets it came with.
func TestHostOfURL(t *testing.T) {
	tests := map[string]string{
		"https://Mail.Example.Com/path?q=1": "mail.example.com",
		"http://example.com:8080/":          "example.com",
		"  https://example.com/  ":          "example.com",
		"https://192.0.2.1/login":           "192.0.2.1",
		"http://[2001:db8::1]:8080/":        "2001:db8::1",
		"mailto:sender@example.com":         "",
		"tel:+33123456789":                  "",
		"data:text/plain,hello":             "",
		"cid:image001@example.com":          "",
		"/relative/path":                    "",
		"example.com/no-scheme":             "",
		"http://exa mple.com/":              "",
		"":                                  "",
	}

	for rawURL, want := range tests {
		if got := HostOfURL(rawURL); got != want {
			t.Errorf("HostOfURL(%q) = %q, want %q", rawURL, got, want)
		}
	}
}
