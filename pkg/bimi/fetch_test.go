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
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewHTTPClientRefusesNonPublicAddress checks the guard the whole package
// relies on: the fetched URLs come from the analysed domain's DNS, so a client
// built by NewHTTPClient must not reach an internal service, whatever name
// resolves to it.
func TestNewHTTPClientRefusesNonPublicAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	v := &Validator{HTTPClient: NewHTTPClient(0)}
	_, _, problems := v.fetchFile(context.Background(), server.URL, MaxLogoSize)

	if len(problems) == 0 || !strings.Contains(problems[0], "non-public address") {
		t.Errorf("expected the loopback server to be refused, got %v", problems)
	}
}

// TestIsPublicIP covers the address filter safeDialContext applies before
// connecting. The l= and a= URLs are attacker-controlled through DNS, so every
// range an internal service can sit in has to be refused, not only the RFC 1918
// ones net.IP.IsPrivate knows about.
func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true},
		{"2606:2800:220:1:248:1893:25c8:1946", true},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"::ffff:127.0.0.1", false},
		{"169.254.169.254", false}, // cloud instance metadata
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"224.0.0.1", false},
		{"fd00::1", false},
		{"fe80::1", false},
		{"100.64.0.1", false},      // CGNAT
		{"100.100.100.100", false}, // Tailscale MagicDNS
		{"192.0.0.8", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"64:ff9b::7f00:1", false}, // NAT64-mapped 127.0.0.1
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("%q is not a valid address", tt.ip)
		}
		if got := isPublicIP(ip); got != tt.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}

	if isPublicIP(nil) {
		t.Error("a nil address must not be considered public")
	}
}

func TestRejectInsecureRedirect(t *testing.T) {
	secure, _ := http.NewRequest(http.MethodGet, "https://example.com/logo.svg", nil)
	if err := rejectInsecureRedirect(secure, nil); err != nil {
		t.Errorf("an HTTPS redirect must be followed, got %v", err)
	}

	insecure, _ := http.NewRequest(http.MethodGet, "http://example.com/logo.svg", nil)
	if err := rejectInsecureRedirect(insecure, nil); err == nil {
		t.Error("a redirect away from HTTPS must be refused")
	}
}

// TestRejectInsecureRedirectBoundsChain checks the redirect cap: without it, a
// logo URL redirecting to itself would keep the client busy until its timeout.
func TestRejectInsecureRedirectBoundsChain(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/logo.svg", nil)

	var via []*http.Request
	for i := 0; i < maxRedirects-1; i++ {
		via = append(via, req)
		if err := rejectInsecureRedirect(req, via); err != nil {
			t.Fatalf("redirect %d must still be followed, got %v", i+1, err)
		}
	}

	via = append(via, req)
	if err := rejectInsecureRedirect(req, via); err == nil {
		t.Errorf("redirect %d must be refused", maxRedirects+1)
	}
}

func TestFetchFileInvalidURL(t *testing.T) {
	v := &Validator{}
	// A control character in the URL makes url.Parse fail.
	_, _, problems := v.fetchFile(context.Background(), "https://example.com/\x7f", MaxLogoSize)
	if len(problems) == 0 || !strings.Contains(problems[0], "Invalid URL") {
		t.Errorf("expected an invalid-URL problem, got %v", problems)
	}
}

func TestFetchFileRequiresHTTPS(t *testing.T) {
	v := &Validator{}
	_, _, problems := v.fetchFile(context.Background(), "http://example.com/logo.svg", MaxLogoSize)
	if len(problems) == 0 || !strings.Contains(problems[0], "HTTPS") {
		t.Errorf("expected HTTPS requirement problem, got %v", problems)
	}
}

func TestFetchFile(t *testing.T) {
	const logoContent = `<svg xmlns="http://www.w3.org/2000/svg"><title>Example Corp</title></svg>`

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Write([]byte(logoContent))
	})
	mux.HandleFunc("/huge.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(bytes.Repeat([]byte("a"), int(MaxLogoSize)+10))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}

	t.Run("Successful fetch", func(t *testing.T) {
		content, contentType, problems := v.fetchFile(context.Background(), server.URL+"/logo.svg", MaxLogoSize)
		if len(problems) > 0 {
			t.Fatalf("unexpected problems: %v", problems)
		}
		if contentType != "image/svg+xml" {
			t.Errorf("contentType = %q, want image/svg+xml", contentType)
		}
		if string(content) != logoContent {
			t.Errorf("unexpected content")
		}
	})

	t.Run("404 response", func(t *testing.T) {
		_, _, problems := v.fetchFile(context.Background(), server.URL+"/missing.svg", MaxLogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "404") {
			t.Errorf("expected 404 problem, got %v", problems)
		}
	})

	t.Run("Too large", func(t *testing.T) {
		_, _, problems := v.fetchFile(context.Background(), server.URL+"/huge.svg", MaxLogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "maximum allowed size") {
			t.Errorf("expected size problem, got %v", problems)
		}
	})
}
