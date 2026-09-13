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

// TestASCII checks that a hostname comes back in the one form two of
// them can be compared in, whichever of its spellings it was given in, and
// that a name no encoder accepts still comes back rather than disappearing.
func TestASCII(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{"ASCII host", "example.com", "example.com"},
		{"Uppercase and trailing dot", "  Mail.Example.Com.  ", "mail.example.com"},
		{"Unicode label", "éxample.org", "xn--xample-9ua.org"},
		{"Already an A-label", "xn--xample-9ua.org", "xn--xample-9ua.org"},
		{"Decomposed accent", "cafe\u0301.example.com", "xn--caf-dma.example.com"},
		{"Non-Latin script", "пример.example.com", "xn--e1afmkfd.example.com"},
		{"Unicode top-level domain", "пример.рф", "xn--e1afmkfd.xn--p1ai"},
		{"Underscore the rules reject", "_dmarc.example.com", "_dmarc.example.com"},
		{"Nothing at all", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ASCII(tt.hostname); got != tt.want {
				t.Errorf("ASCII(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

// TestOrganizationalUnicode checks that a host written in Unicode
// finds the registrable domain the suffix list holds in A-labels, which it
// cannot be compared against in any other form.
func TestOrganizationalUnicode(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"Unicode host", "boutique.éxample.org", "xn--xample-9ua.org"},
		{"Punycode host", "boutique.xn--xample-9ua.org", "xn--xample-9ua.org"},
		{"Unicode host under a Unicode suffix", "почта.пример.рф", "xn--e1afmkfd.xn--p1ai"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Organizational(tt.domain); got != tt.want {
				t.Errorf("Organizational(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// TestOrganizationalOfURL reads the party a URL leads to, and refuses to name
// one for an address literal, which nobody registered.
func TestOrganizationalOfURL(t *testing.T) {
	tests := map[string]string{
		"https://mail.example.com/path": "example.com",
		"https://shop.example.co.uk/":   "example.co.uk",
		"http://boutique.éxample.org/":  "xn--xample-9ua.org",
		"https://192.0.2.1/login":       "",
		"http://[2001:db8::1]/":         "",
		"mailto:sender@example.com":     "",
		"/relative/path":                "",
	}

	for rawURL, want := range tests {
		if got := OrganizationalOfURL(rawURL); got != want {
			t.Errorf("OrganizationalOfURL(%q) = %q, want %q", rawURL, got, want)
		}
	}
}
