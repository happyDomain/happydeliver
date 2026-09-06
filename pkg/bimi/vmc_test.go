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
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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

	// Logotype describes the logotype extension to embed. Its zero value
	// yields a conforming one.
	Logotype testLogotypeOptions
}

// Digest algorithms the fixture hashes a mark with, spelled out here so it
// does not lean on the table the code under test uses.
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
)

// The RFC 9399 logotype structures, transcribed a second time for the fixture
// so that a mistake in the production ones cannot cancel itself out here.
//
// The tagged members carry their tag in the asn1.RawValue rather than in a
// struct tag: encoding/asn1 emits a RawValue's FullBytes verbatim and drops
// any explicit wrapper asked for by a tag, so the header has to be described
// by Class, Tag and IsCompound with FullBytes left nil.
type derLogotypeExtn struct {
	IssuerLogo  asn1.RawValue `asn1:"optional"`
	SubjectLogo asn1.RawValue `asn1:"optional"`
}

type derLogotypeData struct {
	Image []derLogotypeImage
}

type derLogotypeImage struct {
	ImageDetails derLogotypeDetails
}

type derLogotypeDetails struct {
	MediaType string `asn1:"ia5"`
	// LogotypeHash and LogotypeURI are SEQUENCE OF. The URIs go through
	// asn1.RawValue because a []string is marshalled with empty parameters,
	// which would emit them as UTF8String rather than IA5String.
	LogotypeHash []derHashAlgAndValue
	LogotypeURI  []asn1.RawValue
}

type derHashAlgAndValue struct {
	HashAlg   pkix.AlgorithmIdentifier
	HashValue []byte
}

type derLogotypeReference struct {
	RefStructHash []derHashAlgAndValue
	RefStructURI  []asn1.RawValue
}

// testLogotypeOptions describes the logotype extension to embed. Its zero
// value yields a conforming one: the mark under subjectLogo, gzipped in a
// base64 data URI, with a SHA-256 logotypeHash computed over the document with
// canonicalized end-of-line characters. Each flag names the single requirement
// the case is about.
type testLogotypeOptions struct {
	// UnderIssuerLogo files the mark under issuerLogo instead of
	// subjectLogo, as the authority's own branding would be.
	UnderIssuerLogo bool
	// IssuerLogo additionally files this document under issuerLogo, to check
	// that the subject's mark is the one that comes out.
	IssuerLogo []byte

	Indirect bool // a LogotypeReference instead of a LogotypeData
	NoImage  bool // a LogotypeData carrying an empty image sequence

	MediaType          string // overrides both the mediaType member and the data URI's
	DataURIMediaType   string // overrides the data URI's alone
	DataURINoMediaType bool   // the data URI announces none

	HashAlg          asn1.ObjectIdentifier // defaults to SHA-256
	WrongHash        bool
	NoHash           bool
	HashOverRawBytes bool // hashes without canonicalizing the end-of-line characters

	Uncompressed  bool
	PrecedingLink bool // lists an https:// URI before the data one
	ExternalURI   bool // lists an https:// URI and nothing else
	NoBase64      bool
	CorruptBase64 bool
	CorruptGzip   bool

	// RawValue replaces the whole extension value, for payloads no
	// structured builder would produce.
	RawValue []byte
}

// testCanonicalEOL is the fixture's own rendition of the RFC 9399 section 7
// end-of-line canonicalization, so that the hash it computes does not lean on
// the implementation under test.
func testCanonicalEOL(svg []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(svg, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n"))
}

// testDigest hashes b with the algorithm alg names.
func testDigest(t *testing.T, alg asn1.ObjectIdentifier, b []byte) []byte {
	t.Helper()

	switch alg.String() {
	case oidSHA1.String():
		sum := sha1.Sum(b)
		return sum[:]
	case oidSHA256.String():
		sum := sha256.Sum256(b)
		return sum[:]
	case oidMD5.String():
		sum := md5.Sum(b)
		return sum[:]
	}

	t.Fatalf("the fixture cannot hash with %s", alg)
	return nil
}

// marshalIA5Strings encodes each value as an IA5String, ready to be carried in
// a SEQUENCE OF.
func marshalIA5Strings(t *testing.T, values []string) []asn1.RawValue {
	t.Helper()

	out := make([]asn1.RawValue, 0, len(values))
	for _, value := range values {
		tlv, err := asn1.MarshalWithParams(value, "ia5")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, asn1.RawValue{FullBytes: tlv})
	}
	return out
}

// logotypeInfo builds a LogotypeInfo, that is the complete [0] direct (or [1]
// indirect) element that goes inside an explicit issuerLogo or subjectLogo.
func logotypeInfo(t *testing.T, svgLogo []byte, opts testLogotypeOptions) []byte {
	t.Helper()

	mediaType := opts.MediaType
	if mediaType == "" {
		mediaType = "image/svg+xml"
	}
	dataURIMediaType := opts.DataURIMediaType
	if dataURIMediaType == "" {
		dataURIMediaType = mediaType
	}
	if opts.DataURINoMediaType {
		dataURIMediaType = ""
	}

	payload := svgLogo
	if !opts.Uncompressed {
		var gzipped bytes.Buffer
		gz := gzip.NewWriter(&gzipped)
		gz.Write(svgLogo)
		gz.Close()
		payload = gzipped.Bytes()
	}
	if opts.CorruptGzip {
		payload = payload[:len(payload)/2]
	}

	encoded := base64.StdEncoding.EncodeToString(payload)
	if opts.CorruptBase64 {
		encoded = "not base64 at all!"
	}
	separator := ";base64,"
	if opts.NoBase64 {
		separator = ","
	}

	var uris []string
	switch {
	case opts.ExternalURI:
		uris = []string{"https://logo.example.com/mark.svg"}
	case opts.PrecedingLink:
		uris = []string{"https://logo.example.com/mark.svg", "data:" + dataURIMediaType + separator + encoded}
	default:
		uris = []string{"data:" + dataURIMediaType + separator + encoded}
	}

	alg := opts.HashAlg
	if alg == nil {
		alg = oidSHA256
	}
	hashed := testCanonicalEOL(svgLogo)
	if opts.HashOverRawBytes {
		hashed = svgLogo
	}
	var hashes []derHashAlgAndValue
	if !opts.NoHash {
		value := testDigest(t, alg, hashed)
		if opts.WrongHash {
			value[0] ^= 0xff
		}
		hashes = []derHashAlgAndValue{{
			HashAlg:   pkix.AlgorithmIdentifier{Algorithm: alg, Parameters: asn1.NullRawValue},
			HashValue: value,
		}}
	}

	details := derLogotypeDetails{
		MediaType:    mediaType,
		LogotypeHash: hashes,
		LogotypeURI:  marshalIA5Strings(t, uris),
	}

	if opts.Indirect {
		reference, err := asn1.MarshalWithParams(derLogotypeReference{
			RefStructHash: hashes,
			RefStructURI:  details.LogotypeURI,
		}, "tag:1")
		if err != nil {
			t.Fatal(err)
		}
		return reference
	}

	images := []derLogotypeImage{{ImageDetails: details}}
	if opts.NoImage {
		images = nil
	}
	direct, err := asn1.MarshalWithParams(derLogotypeData{Image: images}, "tag:0")
	if err != nil {
		t.Fatal(err)
	}
	return direct
}

// logotypeExtension builds an RFC 9399 logotype extension embedding svgLogo,
// by default as the conforming subjectLogo of a Verified Mark Certificate.
func logotypeExtension(t *testing.T, svgLogo []byte, opts testLogotypeOptions) pkix.Extension {
	t.Helper()

	if opts.RawValue != nil {
		return pkix.Extension{Id: oidLogotype, Value: opts.RawValue}
	}

	mark := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      logotypeInfo(t, svgLogo, opts),
	}

	var extn derLogotypeExtn
	if opts.UnderIssuerLogo {
		mark.Tag = 1
		extn.IssuerLogo = mark
	} else {
		extn.SubjectLogo = mark
		if opts.IssuerLogo != nil {
			extn.IssuerLogo = asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        1,
				IsCompound: true,
				Bytes:      logotypeInfo(t, opts.IssuerLogo, testLogotypeOptions{}),
			}
		}
	}

	value, err := asn1.Marshal(extn)
	if err != nil {
		t.Fatal(err)
	}

	return pkix.Extension{Id: oidLogotype, Value: value}
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
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, logotypeExtension(t, opts.Logo, opts.Logotype))
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
			name:    "Logo hash does not cover the embedded logo",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.Logotype.WrongHash = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "does not match the hash the authority certified it by",
		},
		{
			name:    "Logo embedded under issuerLogo",
			binding: VMCBinding{Selector: "default", Domain: "example.com"},
			chain: vmc(func(o *testVMCOptions) {
				o.Logotype.UnderIssuerLogo = true
			}),
			logoContent:    logo,
			expectedStatus: StatusFail,
			expectedInMsg:  "no subjectLogo",
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

// TestAnalyzeVMCLogotype pins how the mark the certificate carries reaches the
// rest of the analysis: which digest authenticated it, and what the comparison
// with the logo published at the l= URL makes of it.
//
// RFC 9399 section 4.1 has a client discard logotype data whose hash does not
// match, so a mark that fails it must not go on to be compared, not even
// when the two happen to be the same bytes, which is exactly the case set up
// below.
func TestAnalyzeVMCLogotype(t *testing.T) {
	logo := []byte(validTinyPSSVG)
	now := time.Now()
	binding := VMCBinding{Selector: "default", Domain: "example.com"}

	t.Run("a verified hash is reported with the digest that established it", func(t *testing.T) {
		chain, _ := generateTestVMCChain(t, testVMCOptions{
			Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour),
			Logotype: testLogotypeOptions{HashAlg: oidSHA1},
		})

		_, info := AnalyzeVMC(chain, binding, logo, nil, now)
		if info.LogoHashVerified == nil || !*info.LogoHashVerified {
			t.Errorf("LogoHashVerified = %v, want true", info.LogoHashVerified)
		}
		if info.LogoHashAlgorithm != "SHA-1" {
			t.Errorf("LogoHashAlgorithm = %q, want %q", info.LogoHashAlgorithm, "SHA-1")
		}
		if info.LogoMediaType != "image/svg+xml" {
			t.Errorf("LogoMediaType = %q, want %q", info.LogoMediaType, "image/svg+xml")
		}
		if info.LogoMatches == nil || !*info.LogoMatches {
			t.Errorf("LogoMatches = %v, want true", info.LogoMatches)
		}
	})

	t.Run("a logo published with other end-of-line characters still matches", func(t *testing.T) {
		chain, _ := generateTestVMCChain(t, testVMCOptions{
			Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour),
		})
		published := bytes.ReplaceAll(logo, []byte("\n"), []byte("\r\n"))

		check, info := AnalyzeVMC(chain, binding, published, nil, now)
		if info.LogoMatches == nil || !*info.LogoMatches {
			t.Errorf("LogoMatches = %v, want true: the two documents differ only by their end-of-line characters", info.LogoMatches)
		}
		if check.Status == StatusFail {
			t.Errorf("status = %s, want the check not to fail (messages: %v)", check.Status, check.Messages)
		}
	})

	t.Run("a logo that fails its hash is never compared with the published one", func(t *testing.T) {
		chain, _ := generateTestVMCChain(t, testVMCOptions{
			Domain: "example.com", Logo: logo, NotAfter: now.Add(365 * 24 * time.Hour),
			Logotype: testLogotypeOptions{WrongHash: true},
		})

		check, info := AnalyzeVMC(chain, binding, logo, nil, now)
		if check.Status != StatusFail || info.Valid {
			t.Errorf("status = %s, valid = %t, want a failing check", check.Status, info.Valid)
		}
		if info.LogoHashVerified == nil || *info.LogoHashVerified {
			t.Errorf("LogoHashVerified = %v, want false", info.LogoHashVerified)
		}
		if info.LogoMatches != nil {
			t.Errorf("LogoMatches = %v, want nil: the logotype data had to be discarded before any comparison", *info.LogoMatches)
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

func TestParseLogotypeExtension(t *testing.T) {
	svg := []byte(validTinyPSSVG)
	crlfSVG := bytes.ReplaceAll(svg, []byte("\n"), []byte("\r\n"))
	otherSVG := []byte(strings.Replace(validTinyPSSVG, "<title>", "<title>Not ", 1))

	// The old fixture: the data URI in a bare IA5String, with none of the
	// RFC 9399 structure around it. The regexp-based extractor accepted it.
	bareDataURI := marshalIA5Strings(t, []string{"data:image/svg+xml;base64,"})[0].FullBytes

	cases := []struct {
		name string
		// logo is the document the fixture embeds and hashes; it defaults
		// to a conforming SVG Tiny P/S one.
		logo        []byte
		opts        testLogotypeOptions
		wantSVG     []byte // defaults to logo
		wantAlg     string
		wantWarning string
		wantErr     string
	}{
		{
			name:    "conforming certificate",
			wantAlg: "SHA-256",
		},
		{
			name:    "SHA-1, as the authorities in the field hash",
			opts:    testLogotypeOptions{HashAlg: oidSHA1},
			wantAlg: "SHA-1",
		},
		{
			name:    "end-of-line characters are canonicalized before hashing",
			logo:    crlfSVG,
			wantAlg: "SHA-256",
		},
		{
			name:        "authority hashed the document as it stands",
			logo:        crlfSVG,
			opts:        testLogotypeOptions{HashOverRawBytes: true},
			wantAlg:     "SHA-256",
			wantWarning: "end-of-line characters left as they are",
		},
		{
			name:    "a link listed before the embedded logo is stepped over",
			opts:    testLogotypeOptions{PrecedingLink: true},
			wantAlg: "SHA-256",
		},
		{
			name:    "unregistered but deployed media type spelling",
			opts:    testLogotypeOptions{MediaType: "image/svg+xml-gzip"},
			wantAlg: "SHA-256",
		},
		{
			// The whole point of reading subjectLogo rather than the first
			// data URI that turns up: the issuer's own branding sits in the
			// same extension, earlier in the encoding.
			name:    "the subject's mark wins over the issuer's",
			opts:    testLogotypeOptions{IssuerLogo: otherSVG},
			wantSVG: svg,
			wantAlg: "SHA-256",
		},
		{
			name:    "mark filed under issuerLogo alone",
			opts:    testLogotypeOptions{UnderIssuerLogo: true},
			wantErr: "no subjectLogo",
		},
		{
			name:    "logo referenced instead of embedded",
			opts:    testLogotypeOptions{Indirect: true},
			wantErr: "references its logo instead of embedding it",
		},
		{
			name:    "logo linked instead of embedded",
			opts:    testLogotypeOptions{ExternalURI: true},
			wantErr: "links to its logo instead of embedding it",
		},
		{
			name:    "hash does not cover the embedded logo",
			opts:    testLogotypeOptions{WrongHash: true},
			wantErr: errLogotypeHashMismatch.Error(),
		},
		{
			name:    "no hash of the embedded logo",
			opts:    testLogotypeOptions{NoHash: true},
			wantErr: "carries no hash of the embedded logo",
		},
		{
			name:    "digest this implementation does not compute",
			opts:    testLogotypeOptions{HashAlg: oidMD5},
			wantErr: "1.2.840.113549.2.5",
		},
		{
			name:    "embedded image is not an SVG",
			opts:    testLogotypeOptions{MediaType: "image/png"},
			wantErr: "has to be an SVG document",
		},
		{
			name:    "the two media types disagree",
			opts:    testLogotypeOptions{MediaType: "image/svg+xml", DataURIMediaType: "image/svg+xml+gzip"},
			wantErr: "both have to name the same one",
		},
		{
			name:    "the data URI announces no media type",
			opts:    testLogotypeOptions{DataURINoMediaType: true},
			wantErr: "announces no media type",
		},
		{
			name:    "embedded logo is not compressed",
			opts:    testLogotypeOptions{Uncompressed: true},
			wantErr: "not gzip-compressed",
		},
		{
			name:    "payload is not announced as base64",
			opts:    testLogotypeOptions{NoBase64: true},
			wantErr: "not base64-encoded",
		},
		{
			name:    "payload is not valid base64",
			opts:    testLogotypeOptions{CorruptBase64: true},
			wantErr: "base64 payload",
		},
		{
			name:    "gzip stream is truncated",
			opts:    testLogotypeOptions{CorruptGzip: true},
			wantErr: "gzip",
		},
		{
			name:    "subjectLogo carries no image",
			opts:    testLogotypeOptions{NoImage: true},
			wantErr: "carries no image",
		},
		{
			// A decompression bomb hidden in the certificate: small on the
			// wire, past the profile's ceiling once inflated.
			name:    "embedded logo inflates past the maximum size",
			logo:    bytes.Repeat([]byte("A"), int(MaxFileSize)+1),
			wantErr: "maximum allowed size",
		},
		{
			name:    "extension value is not a logotype structure",
			opts:    testLogotypeOptions{RawValue: []byte("not DER at all")},
			wantErr: "not a well-formed RFC 9399 structure",
		},
		{
			name:    "a bare data URI, as the regexp extractor used to accept",
			opts:    testLogotypeOptions{RawValue: bareDataURI},
			wantErr: "not a well-formed RFC 9399 structure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logo := tc.logo
			if logo == nil {
				logo = svg
			}
			wantSVG := tc.wantSVG
			if wantSVG == nil {
				wantSVG = logo
			}

			mark, warnings, err := parseLogotypeExtension(logotypeExtension(t, logo, tc.opts).Value)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseLogotypeExtension() = %v, nil; want an error mentioning %q", mark, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %q, want it to mention %q", err, tc.wantErr)
				}
				if mark != nil {
					t.Errorf("mark = %v, want none alongside an error: unauthenticated logotype data must not leave the parser", mark)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseLogotypeExtension() error = %v", err)
			}
			if !bytes.Equal(mark.SVG, wantSVG) {
				t.Errorf("mark.SVG = %q, want %q", mark.SVG, wantSVG)
			}
			if mark.HashAlgorithm != tc.wantAlg {
				t.Errorf("mark.HashAlgorithm = %q, want %q", mark.HashAlgorithm, tc.wantAlg)
			}
			if tc.wantWarning == "" {
				if len(warnings) > 0 {
					t.Errorf("warnings = %q, want none", warnings)
				}
			} else if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, tc.wantWarning) }) {
				t.Errorf("warnings = %q, want one mentioning %q", warnings, tc.wantWarning)
			}
		})
	}
}

func TestCanonicalizeEOL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "linefeeds are left alone", in: "<svg>\n<title/>\n</svg>", want: "<svg>\n<title/>\n</svg>"},
		{name: "no end of line at all", in: "<svg><title/></svg>", want: "<svg><title/></svg>"},
		{name: "carriage return and linefeed", in: "<svg>\r\n<title/>\r\n</svg>", want: "<svg>\n<title/>\n</svg>"},
		{name: "lone carriage return", in: "<svg>\r<title/>\r</svg>", want: "<svg>\n<title/>\n</svg>"},
		{name: "trailing carriage return", in: "<svg/>\r", want: "<svg/>\n"},
		{name: "the two mixed", in: "a\r\nb\rc\nd", want: "a\nb\nc\nd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(canonicalizeEOL([]byte(tc.in))); got != tc.want {
				t.Errorf("canonicalizeEOL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
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
