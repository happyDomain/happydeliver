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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// OIDBIMIExtKeyUsage is the Extended Key Usage assigned to BIMI Verified Mark
// Certificates (id-kp-BrandIndicatorforMessageIdentification).
const OIDBIMIExtKeyUsage = "1.3.6.1.5.5.7.3.31"

// OIDLogotypeExtension is the RFC 3709 logotype extension carrying the
// certified brand logo.
const OIDLogotypeExtension = "1.3.6.1.5.5.7.1.12"

// svgDataURIRegexp locates the embedded logo data URI inside the logotype
// extension (RFC 3709). The SVG is base64-encoded, usually gzipped
// (image/svg+xml-gzip per the BIMI profile).
var svgDataURIRegexp = regexp.MustCompile(`data:image/svg\+xml(?:-gzip)?(?:;[a-zA-Z0-9=/+.-]+)*;base64,([A-Za-z0-9+/=]+)`)

// VMCInfo describes an analysed Verified Mark Certificate. Optional boolean
// fields are pointers: a nil value means the criterion was not evaluated
// (e.g. because the certificate could not be parsed).
type VMCInfo struct {
	// Issuer is the leaf certificate issuer distinguished name.
	Issuer string
	// Subject is the leaf certificate subject distinguished name.
	Subject string
	// SerialNumber is the leaf certificate serial number in decimal form.
	SerialNumber string
	// NotBefore is the start of the leaf validity period.
	NotBefore time.Time
	// NotAfter is the end of the leaf validity period.
	NotAfter time.Time
	// ChainLength is the number of certificates in the PEM chain.
	ChainLength int
	// SanDomains lists the dNSName Subject Alternative Names of the leaf.
	SanDomains []string
	// HasBimiEku reports whether the leaf carries the BIMI Extended Key
	// Usage (OIDBIMIExtKeyUsage).
	HasBimiEku *bool
	// HasLogotype reports whether the leaf carries the RFC 3709 logotype
	// extension (OIDLogotypeExtension).
	HasLogotype *bool
	// LogoMatches reports whether the SVG embedded in the certificate
	// matches the logo published at the l= URL. Nil when no comparison was
	// made (no published logo or extraction failure).
	LogoMatches *bool
	// Valid reports whether the certificate passed every mandatory
	// criterion.
	Valid bool
	// Error, when set, summarises the reasons the certificate is invalid.
	Error string
}

// analyzeVMCURL downloads the Verified Mark Certificate published in the BIMI
// a= tag and analyses it. logoContent, when non-nil, is the SVG published at
// the l= URL, compared against the logo embedded in the certificate.
func (v *Validator) analyzeVMCURL(ctx context.Context, vmcURL, domain string, logoContent []byte) (Check, *VMCInfo) {
	content, contentType, problems := v.fetchFile(ctx, vmcURL, MaxFileSize)
	if len(problems) > 0 {
		return newCheck("vmc", "Verified Mark Certificate", StatusFail, problems...),
			&VMCInfo{Valid: false, Error: strings.Join(problems, "; ")}
	}

	check, info := AnalyzeVMC(content, domain, logoContent, v.now())

	// The Content-Type is a transport concern handled here rather than in
	// the pure AnalyzeVMC helper.
	if contentType != "application/pem-certificate-chain" {
		msg := fmt.Sprintf("VMC served with Content-Type %q, expected \"application/pem-certificate-chain\"", contentType)
		check.Messages = append(check.Messages, msg)
		if check.Status == StatusPass {
			check.Status = StatusWarning
		}
	}

	return check, info
}

// AnalyzeVMC parses and validates a PEM certificate chain as a BIMI Verified
// Mark Certificate. logoContent, when non-nil, is the SVG published at the l=
// URL, compared against the logo embedded in the certificate. now is the
// reference time used for the validity-period checks.
//
// It returns the "vmc" evidence Check and a VMCInfo describing the leaf
// certificate.
func AnalyzeVMC(pemChain []byte, domain string, logoContent []byte, now time.Time) (Check, *VMCInfo) {
	fail := func(messages ...string) (Check, *VMCInfo) {
		return newCheck("vmc", "Verified Mark Certificate", StatusFail, messages...),
			&VMCInfo{Valid: false, Error: strings.Join(messages, "; ")}
	}

	// Parse every certificate of the PEM chain; the first one is the leaf
	// (subscriber) certificate.
	var certs []*x509.Certificate
	rest := pemChain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fail(fmt.Sprintf("Unable to parse certificate #%d of the chain: %s", len(certs)+1, err))
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fail("The file does not contain any PEM-encoded certificate")
	}

	leaf := certs[0]

	info := &VMCInfo{
		Issuer:       leaf.Issuer.String(),
		Subject:      leaf.Subject.String(),
		SerialNumber: leaf.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		ChainLength:  len(certs),
		SanDomains:   leaf.DNSNames,
	}

	var problems []string
	var warnings []string

	// Validity period
	if now.Before(leaf.NotBefore) {
		problems = append(problems, fmt.Sprintf("The certificate is not yet valid (valid from %s)", leaf.NotBefore.Format(time.RFC3339)))
	}
	if now.After(leaf.NotAfter) {
		problems = append(problems, fmt.Sprintf("The certificate expired on %s", leaf.NotAfter.Format(time.RFC3339)))
	} else if now.Add(30 * 24 * time.Hour).After(leaf.NotAfter) {
		warnings = append(warnings, fmt.Sprintf("The certificate expires soon (%s)", leaf.NotAfter.Format(time.RFC3339)))
	}

	// The certificate must cover the BIMI domain
	if !vmcCoversDomain(leaf.DNSNames, domain) {
		problems = append(problems, fmt.Sprintf("The certificate Subject Alternative Names (%s) do not cover the domain %q", strings.Join(leaf.DNSNames, ", "), domain))
	}

	// BIMI Extended Key Usage
	hasBIMIEKU := false
	for _, eku := range leaf.UnknownExtKeyUsage {
		if eku.String() == OIDBIMIExtKeyUsage {
			hasBIMIEKU = true
		}
	}
	info.HasBimiEku = &hasBIMIEKU
	if !hasBIMIEKU {
		problems = append(problems, "The certificate does not carry the BIMI Extended Key Usage (1.3.6.1.5.5.7.3.31): this is not a Verified Mark Certificate")
	}

	// Logotype extension and embedded logo comparison
	var logotypeValue []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == OIDLogotypeExtension {
			logotypeValue = ext.Value
		}
	}
	hasLogotype := logotypeValue != nil
	info.HasLogotype = &hasLogotype
	if logotypeValue == nil {
		problems = append(problems, "The certificate does not carry the logotype extension (1.3.6.1.5.5.7.1.12) embedding the certified logo")
	} else {
		embeddedSVG, err := extractLogotypeSVG(logotypeValue)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Unable to extract the logo embedded in the certificate: %s", err))
		} else if logoContent != nil {
			matches := bytes.Equal(normalizeSVG(embeddedSVG), normalizeSVG(logoContent))
			info.LogoMatches = &matches
			if !matches {
				problems = append(problems, "The logo embedded in the certificate differs from the logo published at the l= URL: both must be identical")
			}
		}
	}

	// Verify the chain signatures (the VMC roots are not in the system
	// trust store, so only the provided chain consistency is checked)
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			warnings = append(warnings, fmt.Sprintf("Certificate #%d is not signed by the next certificate in the provided chain: %s", i+1, err))
			break
		}
	}

	if len(problems) > 0 {
		info.Valid = false
		info.Error = strings.Join(problems, "; ")
		return newCheck("vmc", "Verified Mark Certificate", StatusFail, append(problems, warnings...)...), info
	}

	info.Valid = true
	if len(warnings) > 0 {
		return newCheck("vmc", "Verified Mark Certificate", StatusWarning, warnings...), info
	}
	return newCheck("vmc", "Verified Mark Certificate", StatusPass), info
}

// vmcCoversDomain tells whether one of the SAN dNSNames covers the given
// domain: exact match, or the SAN is a parent (organizational) domain of it.
func vmcCoversDomain(sans []string, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(san, "."))
		if san == domain || strings.HasSuffix(domain, "."+san) {
			return true
		}
		// Wildcard SAN (uncommon for VMC but tolerated)
		if strings.HasPrefix(san, "*.") && strings.HasSuffix(domain, san[1:]) {
			return true
		}
	}
	return false
}

// extractLogotypeSVG extracts the SVG image embedded in the RFC 3709 logotype
// extension. The image is carried as a base64 data URI, gzipped per the BIMI
// profile.
func extractLogotypeSVG(extensionValue []byte) ([]byte, error) {
	matches := svgDataURIRegexp.FindSubmatch(extensionValue)
	if matches == nil {
		return nil, fmt.Errorf("no SVG data URI found in the logotype extension")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(matches[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}

	// The BIMI profile requires the embedded SVG to be gzipped, but
	// tolerate a raw SVG payload.
	if reader, err := gzip.NewReader(bytes.NewReader(decoded)); err == nil {
		if inflated, err := io.ReadAll(reader); err == nil {
			return inflated, nil
		}
	}

	return decoded, nil
}

// normalizeSVG makes the byte comparison between the published and the
// embedded logo resilient to trailing whitespace differences.
func normalizeSVG(svg []byte) []byte {
	return bytes.TrimSpace(svg)
}
