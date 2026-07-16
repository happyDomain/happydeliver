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

package analyzer

import (
	"bytes"
	"compress/gzip"
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
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

const validTinyPSSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40" fill="#123456"/>
</svg>`

func TestCheckBIMILogoXML(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedStatus model.BIMICheckStatus
		expectedInMsg  string
	}{
		{
			name:           "Well-formed SVG",
			content:        validTinyPSSVG,
			expectedStatus: model.BIMICheckStatusPass,
		},
		{
			name:           "Unclosed element",
			content:        `<svg xmlns="http://www.w3.org/2000/svg"><title>x</title>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "not well-formed",
		},
		{
			name:           "Mismatched tags",
			content:        `<svg><title>x</circle></svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "line 1",
		},
		{
			name:           "Not XML at all",
			content:        `PNG binary content`,
			expectedStatus: model.BIMICheckStatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := checkBIMILogoXML([]byte(tt.content))
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s", check.Status, tt.expectedStatus)
			}
			if tt.expectedInMsg != "" {
				if check.Messages == nil || !strings.Contains(strings.Join(*check.Messages, " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}

func TestCheckBIMILogoSVGTinyPS(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedStatus model.BIMICheckStatus
		expectedInMsg  string
	}{
		{
			name:           "Valid SVG Tiny P/S",
			content:        validTinyPSSVG,
			expectedStatus: model.BIMICheckStatusPass,
		},
		{
			name: "Missing baseProfile",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "baseProfile",
		},
		{
			name: "Wrong baseProfile",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  `baseProfile="tiny-ps"`,
		},
		{
			name: "Missing version",
			content: `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  `version="1.2"`,
		},
		{
			name: "Missing title",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <circle cx="50" cy="50" r="40"/>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "<title>",
		},
		{
			name: "Script element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <script>alert(1)</script>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "scripting",
		},
		{
			name: "Animation element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40"><animate attributeName="r" from="40" to="10" dur="1s"/></circle>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "animation",
		},
		{
			name: "Image element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <image href="https://example.com/photo.png" width="10" height="10"/>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "image",
		},
		{
			name: "Event attribute",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40" onclick="alert(1)"/>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "onclick",
		},
		{
			name: "External reference",
			content: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <use xlink:href="https://example.com/shape.svg#circle"/>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "External reference",
		},
		{
			name: "Local reference is allowed",
			content: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <defs><circle id="c" cx="50" cy="50" r="40"/></defs>
  <use xlink:href="#c"/>
</svg>`,
			expectedStatus: model.BIMICheckStatusPass,
		},
		{
			name: "x/y on root element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" x="10" y="10">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "must not have",
		},
		{
			name: "DOCTYPE declaration",
			content: `<?xml version="1.0"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "DOCTYPE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := checkBIMILogoSVGTinyPS([]byte(tt.content))
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s (messages: %v)", check.Status, tt.expectedStatus, check.Messages)
			}
			if tt.expectedInMsg != "" {
				if check.Messages == nil || !strings.Contains(strings.Join(*check.Messages, " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}

func TestFetchBIMIFileRequiresHTTPS(t *testing.T) {
	analyzer := NewDNSAnalyzer(5 * time.Second)

	_, _, problems := analyzer.fetchBIMIFile("http://example.com/logo.svg", maxBIMILogoSize)
	if len(problems) == 0 || !strings.Contains(problems[0], "HTTPS") {
		t.Errorf("expected HTTPS requirement problem, got %v", problems)
	}
}

func TestFetchBIMIFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Write([]byte(validTinyPSSVG))
	})
	mux.HandleFunc("/huge.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(bytes.Repeat([]byte("a"), maxBIMILogoSize+10))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	analyzer := NewDNSAnalyzer(5 * time.Second)
	analyzer.httpClient = server.Client()

	t.Run("Successful fetch", func(t *testing.T) {
		content, contentType, problems := analyzer.fetchBIMIFile(server.URL+"/logo.svg", maxBIMILogoSize)
		if len(problems) > 0 {
			t.Fatalf("unexpected problems: %v", problems)
		}
		if contentType != "image/svg+xml" {
			t.Errorf("contentType = %q, want image/svg+xml", contentType)
		}
		if string(content) != validTinyPSSVG {
			t.Errorf("unexpected content")
		}
	})

	t.Run("404 response", func(t *testing.T) {
		_, _, problems := analyzer.fetchBIMIFile(server.URL+"/missing.svg", maxBIMILogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "404") {
			t.Errorf("expected 404 problem, got %v", problems)
		}
	})

	t.Run("Too large", func(t *testing.T) {
		_, _, problems := analyzer.fetchBIMIFile(server.URL+"/huge.svg", maxBIMILogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "maximum allowed size") {
			t.Errorf("expected size problem, got %v", problems)
		}
	})
}

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

func TestAnalyzeBIMIVMC(t *testing.T) {
	logo := []byte(validTinyPSSVG)

	tests := []struct {
		name           string
		domain         string
		pem            func(t *testing.T) []byte
		logoContent    []byte
		expectedStatus model.BIMICheckStatus
		expectedInMsg  string
		expectedValid  bool
	}{
		{
			name:   "Valid VMC",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusPass,
			expectedValid:  true,
		},
		{
			name:   "Valid VMC for subdomain sender",
			domain: "mail.example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusPass,
			expectedValid:  true,
		},
		{
			name:   "Expired certificate",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(-24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "expired",
		},
		{
			name:   "Missing BIMI EKU",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, false, true, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "Extended Key Usage",
		},
		{
			name:   "Missing logotype extension",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, false, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "logotype",
		},
		{
			name:   "Domain not covered",
			domain: "example.org",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    logo,
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "do not cover",
		},
		{
			name:   "Embedded logo differs from published logo",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return generateTestVMC(t, "example.com", logo, true, true, time.Now().Add(365*24*time.Hour))
			},
			logoContent:    []byte(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Other</title></svg>`),
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "differs",
		},
		{
			name:   "Not a certificate",
			domain: "example.com",
			pem: func(t *testing.T) []byte {
				return []byte("this is not a PEM file")
			},
			expectedStatus: model.BIMICheckStatusFail,
			expectedInMsg:  "PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemData := tt.pem(t)

			mux := http.NewServeMux()
			mux.HandleFunc("/vmc.pem", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				w.Write(pemData)
			})
			server := httptest.NewTLSServer(mux)
			defer server.Close()

			analyzer := NewDNSAnalyzer(5 * time.Second)
			analyzer.httpClient = server.Client()

			check, info := analyzer.analyzeBIMIVMC(server.URL+"/vmc.pem", tt.domain, tt.logoContent)
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s (messages: %v)", check.Status, tt.expectedStatus, check.Messages)
			}
			if tt.expectedInMsg != "" {
				if check.Messages == nil || !strings.Contains(strings.Join(*check.Messages, " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
			if info.Valid != tt.expectedValid {
				t.Errorf("info.Valid = %t, want %t (error: %v)", info.Valid, tt.expectedValid, info.Error)
			}
		})
	}
}

func TestRunBIMIChecks(t *testing.T) {
	logoPEM := generateTestVMC(t, "example.com", []byte(validTinyPSSVG), true, true, time.Now().Add(365*24*time.Hour))

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(validTinyPSSVG))
	})
	mux.HandleFunc("/bad.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	})
	mux.HandleFunc("/vmc.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(logoPEM)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	analyzer := NewDNSAnalyzer(5 * time.Second)
	analyzer.httpClient = server.Client()

	t.Run("All checks pass", func(t *testing.T) {
		record := &model.BIMIRecord{
			Selector: "default",
			Domain:   "example.com",
			LogoUrl:  utils.PtrTo(server.URL + "/logo.svg"),
			VmcUrl:   utils.PtrTo(server.URL + "/vmc.pem"),
			Valid:    true,
		}
		if !analyzer.runBIMIChecks(record) {
			t.Errorf("expected all checks to pass, got checks: %+v", record.Checks)
		}
		if record.Vmc == nil || !record.Vmc.Valid {
			t.Errorf("expected valid VMC info, got %+v", record.Vmc)
		}
	})

	t.Run("Non-compliant logo fails", func(t *testing.T) {
		record := &model.BIMIRecord{
			Selector: "default",
			Domain:   "example.com",
			LogoUrl:  utils.PtrTo(server.URL + "/bad.svg"),
			Valid:    true,
		}
		if analyzer.runBIMIChecks(record) {
			t.Errorf("expected checks to fail for non-compliant logo")
		}
	})

	t.Run("Declination record skips checks", func(t *testing.T) {
		record := &model.BIMIRecord{
			Selector: "default",
			Domain:   "example.com",
			LogoUrl:  utils.PtrTo(""),
			VmcUrl:   utils.PtrTo(""),
			Valid:    true,
		}
		if !analyzer.runBIMIChecks(record) {
			t.Errorf("declination record should not fail checks")
		}
		for _, check := range *record.Checks {
			if check.Status != model.BIMICheckStatusSkipped {
				t.Errorf("check %s = %s, want skipped", check.Name, check.Status)
			}
		}
	})

	t.Run("Unreachable logo fails", func(t *testing.T) {
		record := &model.BIMIRecord{
			Selector: "default",
			Domain:   "example.com",
			LogoUrl:  utils.PtrTo(server.URL + "/missing.svg"),
			Valid:    true,
		}
		if analyzer.runBIMIChecks(record) {
			t.Errorf("expected checks to fail for unreachable logo")
		}
	})
}
