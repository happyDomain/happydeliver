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
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// oidBIMIExtKeyUsage, oidLogotype and oidSCTList are the three extensions a
// Verified Mark Certificate is recognised by, spelled out here so the fixtures
// do not lean on the constants the code under test uses.
var (
	oidBIMIExtKeyUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}
	oidLogotype        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}
	oidSCTList         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// testVMCOptions describes the chain generateTestVMCChain has to build. The
// zero value of every flag yields a conforming certificate; each one names the
// single requirement to be broken, so a test case reads as the deviation it
// exercises.
type testVMCOptions struct {
	Domain   string
	Logo     []byte
	NotAfter time.Time

	WithoutEKU      bool
	WithoutLogotype bool
	WithoutCRLDP    bool
	WithoutSCT      bool
	EmptySCTList    bool
	LeafIsCA        bool

	// WithoutIssuer publishes the leaf alone, as a chain that omits the CA
	// certificates that issued it.
	WithoutIssuer    bool
	IssuerWithoutEKU bool
	IssuerNotCA      bool
	IssuerNotAfter   time.Time
}

// logotypeExtension builds an RFC 3709 logotype extension embedding svgLogo as
// a gzipped base64 data URI. The URI is wrapped in a bare IA5String: the
// analyser only needs to locate it inside the extension payload.
func logotypeExtension(t *testing.T, svgLogo []byte) pkix.Extension {
	t.Helper()

	var gzipped bytes.Buffer
	gz := gzip.NewWriter(&gzipped)
	gz.Write(svgLogo)
	gz.Close()

	dataURI := "data:image/svg+xml-gzip;base64," + base64.StdEncoding.EncodeToString(gzipped.Bytes())
	uriBytes, err := asn1.MarshalWithParams(dataURI, "ia5")
	if err != nil {
		t.Fatal(err)
	}

	return pkix.Extension{Id: oidLogotype, Value: uriBytes}
}

// sctListExtension builds an RFC 6962 extension announcing count Signed
// Certificate Timestamps: an OCTET STRING wrapping the TLS-encoded list, in
// which each timestamp is announced by a 16-bit length. The bodies are
// arbitrary, since only their number is under test.
func sctListExtension(t *testing.T, count int) pkix.Extension {
	t.Helper()

	var list []byte
	for i := range count {
		body := []byte(fmt.Sprintf("timestamp-%d", i))
		list = binary.BigEndian.AppendUint16(list, uint16(len(body)))
		list = append(list, body...)
	}

	payload := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	payload = append(payload, list...)

	value, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	return pkix.Extension{Id: oidSCTList, Value: value}
}

// generateTestVMCChain builds the issuance chain of a Verified Mark
// Certificate: a self-signed root, the intermediate CA designated to issue
// mark certificates, and the leaf itself. It returns the published chain (the
// leaf followed by the intermediate, the root being optional in the published
// file) and a pool holding the root, so that both branches of the anchoring
// check can be exercised.
func generateTestVMCChain(t *testing.T, opts testVMCOptions) (chainPEM []byte, roots *x509.CertPool) {
	t.Helper()

	if opts.IssuerNotAfter.IsZero() {
		opts.IssuerNotAfter = opts.NotAfter.Add(365 * 24 * time.Hour)
	}

	issue := func(template, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
		t.Helper()

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer, signerKey := parent, parentKey
		if signer == nil { // self-signed
			signer, signerKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}

	rootCert, rootKey := issue(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Mark Verifying Authority Root"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              opts.IssuerNotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Example Verified Mark CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              opts.IssuerNotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if !opts.IssuerWithoutEKU {
		issuerTemplate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidBIMIExtKeyUsage}
	}
	if opts.IssuerNotCA {
		issuerTemplate.IsCA = false
		issuerTemplate.KeyUsage = 0
	}
	issuerCert, issuerKey := issue(issuerTemplate, rootCert, rootKey)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "Example Corp",
			Organization: []string{"Example Corp"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  opts.NotAfter,
		DNSNames:  []string{opts.Domain},
	}
	if opts.LeafIsCA {
		leafTemplate.BasicConstraintsValid = true
		leafTemplate.IsCA = true
	}
	if !opts.WithoutEKU {
		leafTemplate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidBIMIExtKeyUsage}
	}
	if !opts.WithoutLogotype {
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, logotypeExtension(t, opts.Logo))
	}
	if !opts.WithoutCRLDP {
		leafTemplate.CRLDistributionPoints = []string{"https://crl.example.com/vmc.crl"}
	}
	if !opts.WithoutSCT {
		count := 2
		if opts.EmptySCTList {
			count = 0
		}
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, sctListExtension(t, count))
	}
	leafCert, _ := issue(leafTemplate, issuerCert, issuerKey)

	published := []*x509.Certificate{leafCert, issuerCert}
	if opts.WithoutIssuer {
		published = published[:1]
	}
	for _, cert := range published {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	roots = x509.NewCertPool()
	roots.AddCert(rootCert)

	return chainPEM, roots
}

func TestAnalyzeVMC(t *testing.T) {
	logo := []byte(validTinyPSSVG)
	now := time.Now()

	// vmc builds a conforming chain for example.com, mutate breaking the one
	// requirement the case is about. The trust anchors are left out: the
	// anchoring check is exercised by the two cases that pass them.
	vmc := func(mutate func(*testVMCOptions)) func(*testing.T) ([]byte, *x509.CertPool) {
		return func(t *testing.T) ([]byte, *x509.CertPool) {
			opts := testVMCOptions{
				Domain:   "example.com",
				Logo:     logo,
				NotAfter: now.Add(365 * 24 * time.Hour),
			}
			if mutate != nil {
				mutate(&opts)
			}
			chain, _ := generateTestVMCChain(t, opts)
			return chain, nil
		}
	}

	tests := []struct {
		name           string
		binding        VMCBinding
		chain          func(t *testing.T) ([]byte, *x509.CertPool)
		logoContent    []byte
		expectedStatus CheckStatus
		expectedInMsg  string
		expectedValid  bool
	}{
		{
			name:           "Valid VMC",
			binding:        VMCBinding{Selector: "default", Domain: "example.com"},
			chain:          vmc(nil),
			logoContent:    logo,
			expectedStatus: StatusPass,
			expectedValid:  true,
		},
		{
			name:           "Valid VMC for subdomain sender",
			binding:        VMCBinding{Selector: "default", Domain: "mail.example.com", OrganizationalDomain: "example.com"},
			chain:          vmc(nil),
			logoContent:    logo,
			expectedStatus: StatusPass,
			expectedValid:  true,
		},
		{
			name:    "Expired certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.NotAfter = now.Add(-24 * time.Hour)
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "The certificate expired on",
		},
		{
			name:    "Expired issuer certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.IssuerNotAfter = now.Add(-24 * time.Hour)
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "Issuer certificate #2 (Example Verified Mark CA) expired on",
		},
		{
			name:    "Missing BIMI EKU",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.WithoutEKU = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "The certificate does not carry the BIMI Extended Key Usage",
		},
		{
			name:    "Issuer without the BIMI EKU",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.IssuerWithoutEKU = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "is not designated to issue Verified Mark Certificates",
		},
		{
			name:    "Chain reduced to the leaf certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.WithoutIssuer = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "the certificate of the issuing CA must be published alongside it",
		},
		{
			name:    "Issuer not allowed to sign certificates",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.IssuerNotCA = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "is not allowed to sign certificates, yet the chain presents it as the issuer of",
		},
		{
			name:    "Leaf asserting it is a CA",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.LeafIsCA = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "asserts it is a certification authority",
		},
		{
			name:    "Missing CRL distribution point",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.WithoutCRLDP = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "does not publish a CRL distribution point",
		},
		{
			name:    "Missing Signed Certificate Timestamps",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.WithoutSCT = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "was not logged to Certificate Transparency logs",
		},
		{
			name:    "Empty Signed Certificate Timestamp list",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.EmptySCTList = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "Timestamp list of the certificate is empty",
		},
		{
			name:    "Missing logotype extension",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.WithoutLogotype = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "logotype",
		},
		{
			name:           "Domain not covered",
			binding:        VMCBinding{Selector: "default", Domain: "example.org"},
			chain:          vmc(nil),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "do not name this BIMI record",
		},
		{
			name:           "Embedded logo differs from published logo",
			binding:        VMCBinding{Selector: "default", Domain: "example.com"},
			chain:          vmc(nil),
			logoContent:    []byte(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Other</title></svg>`),
			expectedStatus: StatusFail,
			expectedInMsg:  "differs",
		},
		{
			name:    "Not a certificate",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: func(t *testing.T) ([]byte, *x509.CertPool) {
				return []byte("this is not a PEM file"), nil
			},
			expectedStatus: StatusFail,
			expectedInMsg:  "PEM",
		},

		// Anchoring: the two branches of the trust-anchor decision.
		{
			name:    "Chain leading to a trusted root",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: func(t *testing.T) ([]byte, *x509.CertPool) {
				return generateTestVMCChain(t, testVMCOptions{
					Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour),
				})
			},
			logoContent:    logo,
			expectedStatus: StatusPass,
			expectedValid:  true,
		},
		{
			name:    "Chain leading to an unknown root",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: func(t *testing.T) ([]byte, *x509.CertPool) {
				opts := testVMCOptions{Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour)}
				chain, _ := generateTestVMCChain(t, opts)
				// The anchors of another authority, which never issued
				// this chain.
				_, foreignRoots := generateTestVMCChain(t, opts)
				return chain, foreignRoots
			},
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "does not lead to a trusted BIMI root certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, roots := tt.chain(t)
			check, info := AnalyzeVMC(chain, tt.binding, tt.logoContent, roots, now)
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

// TestAnalyzeVMCAnchoring pins what the analysis says about the issuer's
// legitimacy: without a set of trust anchors it says nothing, and says so.
func TestAnalyzeVMCAnchoring(t *testing.T) {
	logo := []byte(validTinyPSSVG)
	now := time.Now()
	binding := VMCBinding{Selector: "default", Domain: "example.com"}
	chain, roots := generateTestVMCChain(t, testVMCOptions{
		Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour),
	})

	t.Run("without anchors the chain is not claimed to be trusted", func(t *testing.T) {
		check, info := AnalyzeVMC(chain, binding, logo, nil, now)
		if info.ChainTrusted != nil {
			t.Errorf("ChainTrusted = %v, want nil when no anchor was supplied", *info.ChainTrusted)
		}
		if check.Status != StatusPass || !info.Valid {
			t.Fatalf("status = %s, valid = %t, want a passing check (messages: %v)", check.Status, info.Valid, check.Messages)
		}
		var informed bool
		for _, m := range check.Messages {
			if m.Severity == SeverityInfo && strings.Contains(m.Text, "trusted BIMI root certificates") {
				informed = true
			}
		}
		if !informed {
			t.Errorf("expected an informational message about the missing anchors, got %v", check.Messages)
		}
	})

	t.Run("with the issuing anchors the chain is trusted", func(t *testing.T) {
		_, info := AnalyzeVMC(chain, binding, logo, roots, now)
		if info.ChainTrusted == nil || !*info.ChainTrusted {
			t.Errorf("ChainTrusted = %v, want true", info.ChainTrusted)
		}
	})
}

// TestParseSCTList covers the walk over the RFC 6962 timestamp list, which
// tells "not logged" apart from "logged, but the proof is unreadable".
func TestParseSCTList(t *testing.T) {
	// sctList encodes count timestamps the way sctListExtension does, so the
	// malformed cases below can be derived from a well-formed list.
	sctList := func(t *testing.T, count int) []byte {
		ext := sctListExtension(t, count)
		var payload []byte
		if _, err := asn1.Unmarshal(ext.Value, &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}

	certWith := func(t *testing.T, payload []byte) *x509.Certificate {
		value, err := asn1.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSCTList, Value: value}}}
	}

	t.Run("extension absent", func(t *testing.T) {
		count, found, err := parseSCTList(&x509.Certificate{})
		if found || err != nil || count != 0 {
			t.Errorf("parseSCTList() = %d, %t, %v; want 0, false, nil", count, found, err)
		}
	})

	for _, count := range []int{0, 1, 3} {
		t.Run(fmt.Sprintf("%d timestamps", count), func(t *testing.T) {
			got, found, err := parseSCTList(certWith(t, sctList(t, count)))
			if err != nil || !found {
				t.Fatalf("parseSCTList() = _, %t, %v; want found and no error", found, err)
			}
			if got != count {
				t.Errorf("count = %d, want %d", got, count)
			}
		})
	}

	t.Run("truncated list", func(t *testing.T) {
		full := sctList(t, 2)
		_, found, err := parseSCTList(certWith(t, full[:len(full)-4]))
		if !found || err == nil {
			t.Errorf("parseSCTList() = _, %t, %v; want the extension found and an error", found, err)
		}
	})

	t.Run("list shorter than its own length prefix", func(t *testing.T) {
		_, found, err := parseSCTList(certWith(t, []byte{0x00}))
		if !found || err == nil {
			t.Errorf("parseSCTList() = _, %t, %v; want the extension found and an error", found, err)
		}
	})

	t.Run("payload is not an OCTET STRING", func(t *testing.T) {
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSCTList, Value: []byte{0xff, 0xff}}}}
		if _, found, err := parseSCTList(cert); !found || err == nil {
			t.Errorf("parseSCTList() = _, %t, %v; want the extension found and an error", found, err)
		}
	})
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
	vmcPEM, _ := generateTestVMCChain(t, testVMCOptions{
		Domain: "example.com", Logo: logo, NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

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
