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
	"net"
	"net/http"
	"testing"
	"time"
)

// stubResolver returns canned TXT records (or an error) for LookupTXT. txt
// answers every name, which suits the tests that visit a single location;
// byName answers per queried name and takes precedence, so a test can tell the
// queried domain's location apart from its organizational domain's. A name
// missing from byName does not exist, as the DNS would report it.
type stubResolver struct {
	txt    []string
	byName map[string][]string
	err    error
}

func (r stubResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.byName == nil {
		return r.txt, nil
	}
	// Discovery queries absolute names (see absoluteName); a stub keyed on
	// the location itself is clearer than one repeating the trailing dot,
	// and TestLookupQueriesAbsoluteNames asserts the wire form separately.
	txt, ok := r.byName[normalizeDomain(name)]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return txt, nil
}

// findCheck returns the evidence check of the given name, so a test can assert
// on the one it cares about without depending on where it sits in the list.
func findCheck(checks []Check, name string) (Check, bool) {
	for _, check := range checks {
		if check.Name == name {
			return check, true
		}
	}
	return Check{}, false
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.HTTPClient == nil {
		t.Error("HTTPClient should be set")
	} else if v.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("HTTPClient.Timeout = %s, want 30s", v.HTTPClient.Timeout)
	}
	if v.Resolver == nil {
		t.Error("Resolver should be set")
	}
}

func TestValidatorDefaults(t *testing.T) {
	// With no HTTPClient set, httpClient() falls back to http.DefaultClient.
	v := &Validator{}
	if v.httpClient() != http.DefaultClient {
		t.Error("httpClient() should default to http.DefaultClient")
	}
	// With no Now set, now() falls back to time.Now (a recent timestamp).
	before := time.Now().Add(-time.Minute)
	if got := v.now(); got.Before(before) {
		t.Errorf("now() = %s, expected a recent time", got)
	}
}

func TestDefaultOrganizationalDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"news.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"news.example.co.uk", "example.co.uk"},
		{"News.Example.COM.", "example.com"},
		// A public suffix has no organizational domain of its own.
		{"co.uk", ""},
		{"com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := DefaultOrganizationalDomain(tt.domain); got != tt.want {
				t.Errorf("DefaultOrganizationalDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}
