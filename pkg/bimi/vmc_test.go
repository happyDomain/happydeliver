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
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// generateTestVMC builds a self-signed certificate mimicking a Verified
// Mark Certificate: BIMI EKU, SAN, and RFC 3709 logotype extension
// embedding the gzipped SVG logo.
func generateTestVMC(t *testing.T, domain string, svgLogo []byte, withEKU, withLogotype bool, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "Example Corp",
			Organization: []string{"Example Corp"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
		DNSNames:  []string{domain},
	}

	if withEKU {
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 31}}
	}

	if withLogotype {
		var gzipped bytes.Buffer
		gz := gzip.NewWriter(&gzipped)
		gz.Write(svgLogo)
		gz.Close()

		dataURI := "data:image/svg+xml-gzip;base64," + base64.StdEncoding.EncodeToString(gzipped.Bytes())
		// Wrap the data URI in an IA5String; the analyser only needs to
		// locate the URI inside the extension payload.
		uriBytes, err := asn1.MarshalWithParams(dataURI, "ia5")
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12},
			Value: uriBytes,
		}}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAnalyzeVMC(t *testing.T) {
	logo := []byte(validTinyPSSVG)
	now := time.Now()

	tests := []struct {
		name           string
		binding        VMCBinding
		pem            func(t *testing.T) []byte
		logoContent    []byte
		expectedStatus CheckStatus
		expectedInMsg  string
		expectedValid  bool
	}{
		{
			name:    "Valid VMC",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, now.Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusPass,
			expectedValid:  true,
		},
		{
			name:    "Valid VMC for subdomain sender",
			binding: VMCBinding{Selector: "default", Domain: "mail.example.com", OrganizationalDomain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, now.Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusPass,
			expectedValid:  true,
		},
		{
			name:    "Expired certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, now.Add(-24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "expired",
		},
		{
			name:    "Missing BIMI EKU",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, false, true, now.Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "Extended Key Usage",
		},
		{
			name:    "Missing logotype extension",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, false, now.Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "logotype",
		},
		{
			name:    "Domain not covered",
			binding: VMCBinding{Selector: "default", Domain: "example.org"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, now.Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "do not name this BIMI record",
		},
		{
			name:    "Embedded logo differs from published logo",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, now.Add(365*24*time.Hour))
			},
			logoContent:    []byte(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Other</title></svg>`),
			expectedStatus: StatusFail,
			expectedInMsg:  "differs",
		},
		{
			name:    "Not a certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			pem: func(t *testing.T) []byte {
				return []byte("this is not a PEM file")
			},
			expectedStatus: StatusFail,
			expectedInMsg:  "PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check, info := AnalyzeVMC(tt.pem(t), tt.binding, tt.logoContent, now)
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s (messages: %v)", check.Status, tt.expectedStatus, check.Messages)
			}
			if tt.expectedInMsg != "" {
				if !strings.Contains(strings.Join(check.MessageTexts(), " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
			if info.Valid != tt.expectedValid {
				t.Errorf("info.Valid = %t, want %t (error: %v)", info.Valid, tt.expectedValid, info.Error)
			}
		})
	}
}

func TestExtractLogotypeSVG(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><title>X</title></svg>`)

	gzipDataURI := func(payload []byte) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write(payload)
		gz.Close()
		return []byte("data:image/svg+xml-gzip;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()))
	}

	t.Run("gzipped payload is inflated", func(t *testing.T) {
		got, err := extractLogotypeSVG(gzipDataURI(svg))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, svg) {
			t.Errorf("got %q, want %q", got, svg)
		}
	})

	t.Run("raw (non-gzipped) payload is returned as-is", func(t *testing.T) {
		raw := []byte("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg))
		got, err := extractLogotypeSVG(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, svg) {
			t.Errorf("got %q, want %q", got, svg)
		}
	})

	t.Run("truncated gzip payload is an error, not the compressed bytes", func(t *testing.T) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write(svg)
		gz.Close()
		truncated := buf.Bytes()[:buf.Len()-5]

		got, err := extractLogotypeSVG([]byte("data:image/svg+xml-gzip;base64," + base64.StdEncoding.EncodeToString(truncated)))
		if err == nil {
			t.Fatalf("err = nil, want a gzip error (got %q)", got)
		}
		if !strings.Contains(err.Error(), "gzip") {
			t.Errorf("err = %v, want a gzip error", err)
		}
	})

	t.Run("no data URI", func(t *testing.T) {
		_, err := extractLogotypeSVG([]byte("nothing embedded here"))
		if err == nil || !strings.Contains(err.Error(), "no SVG data URI") {
			t.Errorf("err = %v, want a no-data-URI error", err)
		}
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		// "abc" is a valid base64 alphabet string but not a valid length,
		// so decoding fails while the data-URI regexp still matches.
		_, err := extractLogotypeSVG([]byte("data:image/svg+xml;base64,abc"))
		if err == nil || !strings.Contains(err.Error(), "base64") {
			t.Errorf("err = %v, want a base64 error", err)
		}
	})
}

func TestAnalyzeVMCURL(t *testing.T) {
	logo := []byte(validTinyPSSVG)
	binding := VMCBinding{Selector: "default", Domain: "example.com", OrganizationalDomain: "example.com"}
	vmcPEM := generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(365*24*time.Hour))

	mux := http.NewServeMux()
	mux.HandleFunc("/vmc.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(vmcPEM)
	})
	mux.HandleFunc("/wrong-type.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(vmcPEM)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}
	ctx := context.Background()

	t.Run("Fetch failure yields a failing check", func(t *testing.T) {
		// A non-HTTPS URL is rejected by fetchFile before any request.
		check, info := v.analyzeVMCURL(ctx, "http://example.com/vmc.pem", binding, logo)
		if check.Status != StatusFail {
			t.Errorf("status = %s, want fail", check.Status)
		}
		if info == nil || info.Valid {
			t.Errorf("expected invalid VMC info, got %+v", info)
		}
	})

	t.Run("Wrong Content-Type downgrades a pass to a warning", func(t *testing.T) {
		check, info := v.analyzeVMCURL(ctx, server.URL+"/wrong-type.pem", binding, logo)
		if check.Status != StatusWarning {
			t.Errorf("status = %s, want warning (messages: %v)", check.Status, check.Messages)
		}
		if !info.Valid {
			t.Errorf("VMC should remain valid despite the Content-Type warning")
		}
		if !strings.Contains(strings.Join(check.MessageTexts(), " "), "Content-Type") {
			t.Errorf("expected a Content-Type message, got %v", check.Messages)
		}
	})

	t.Run("Correct Content-Type passes", func(t *testing.T) {
		check, info := v.analyzeVMCURL(ctx, server.URL+"/vmc.pem", binding, logo)
		if check.Status != StatusPass {
			t.Errorf("status = %s, want pass (messages: %v)", check.Status, check.Messages)
		}
		if !info.Valid {
			t.Error("expected valid VMC")
		}
	})
}

// TestVMCBindingMatches covers the VMC domain verification of
// draft-fetch-validation-vmc-wchuang, Section 5.2: a certificate names the
// Assertion Record's domain, or its organizational domain, exactly, in either
// the bare or the <selector>._bimi. form.
func TestVMCBindingMatches(t *testing.T) {
	subdomain := VMCBinding{Selector: "default", Domain: "mail.example.com", OrganizationalDomain: "example.com"}
	orgDomain := VMCBinding{Selector: "default", Domain: "example.com", OrganizationalDomain: "example.com"}
	summer := VMCBinding{Selector: "summer", Domain: "example.com", OrganizationalDomain: "example.com"}

	tests := []struct {
		name    string
		binding VMCBinding
		sans    []string
		want    bool
	}{
		{"exact domain", orgDomain, []string{"example.com"}, true},
		{"trailing dot tolerated", orgDomain, []string{"example.com."}, true},
		{"case-insensitive", orgDomain, []string{"EXAMPLE.COM"}, true},
		{"one of several names", orgDomain, []string{"example.net", "example.com"}, true},
		{"unrelated domain", orgDomain, []string{"example.org"}, false},

		// A subdomain is reached through its organizational domain, which
		// the binding carries, never through a suffix match.
		{"organizational domain names the subdomain", subdomain, []string{"example.com"}, true},
		{"subdomain names itself", subdomain, []string{"mail.example.com"}, true},
		{"a sibling subdomain does not match", subdomain, []string{"news.example.com"}, false},
		{"a certificate does not cover the subdomains it names", orgDomain, []string{"mail.example.com"}, false},

		// A public suffix is not an organizational domain: without the
		// suffix match, a certificate naming one covers nothing.
		{"public suffix names nothing", VMCBinding{Selector: "default", Domain: "example.co.uk", OrganizationalDomain: "example.co.uk"}, []string{"co.uk"}, false},

		// The selector-scoped form restricts the certificate to one selector.
		{"selector-scoped name", orgDomain, []string{"default._bimi.example.com"}, true},
		{"selector-scoped name of the organizational domain", subdomain, []string{"default._bimi.example.com"}, true},
		{"selector-scoped name of another selector", summer, []string{"default._bimi.example.com"}, false},
		{"selector-scoped name of this selector", summer, []string{"summer._bimi.example.com"}, true},

		// The specification provides for no wildcard in a VMC.
		{"wildcard name", subdomain, []string{"*.example.com"}, false},

		{"no name at all", orgDomain, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.binding.matches(tt.sans); got != tt.want {
				t.Errorf("VMCBinding{%s/%s, org %s}.matches(%v) = %t, want %t",
					tt.binding.Selector, tt.binding.Domain, tt.binding.OrganizationalDomain, tt.sans, got, tt.want)
			}
		})
	}
}

// TestVMCBindingAcceptableSANs pins the names reported to a domain owner whose
// certificate does not match, and that a domain which is its own
// organizational domain is not listed twice.
func TestVMCBindingAcceptableSANs(t *testing.T) {
	tests := []struct {
		name    string
		binding VMCBinding
		want    []string
	}{
		{
			name:    "domain and organizational domain",
			binding: VMCBinding{Selector: "default", Domain: "mail.example.com", OrganizationalDomain: "example.com"},
			want:    []string{"mail.example.com", "default._bimi.mail.example.com", "example.com", "default._bimi.example.com"},
		},
		{
			name:    "own organizational domain is not repeated",
			binding: VMCBinding{Selector: "default", Domain: "example.com", OrganizationalDomain: "example.com"},
			want:    []string{"example.com", "default._bimi.example.com"},
		},
		{
			name:    "no organizational domain known",
			binding: VMCBinding{Selector: "summer", Domain: "example.com"},
			want:    []string{"example.com", "summer._bimi.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.binding.acceptableSANs(); !slices.Equal(got, tt.want) {
				t.Errorf("acceptableSANs() = %v, want %v", got, tt.want)
			}
		})
	}
}
