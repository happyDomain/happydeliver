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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// oidBIMIExtKeyUsage is the Extended Key Usage assigned to BIMI Verified
// Mark Certificates (id-kp-BrandIndicatorforMessageIdentification).
var oidBIMIExtKeyUsageStr = "1.3.6.1.5.5.7.3.31"

// oidLogotypeExtension is the RFC 3709 logotype extension carrying the
// certified brand logo.
var oidLogotypeExtensionStr = "1.3.6.1.5.5.7.1.12"

// svgDataURIRegexp locates the embedded logo data URI inside the logotype
// extension (RFC 3709). The SVG is base64-encoded, usually gzipped
// (image/svg+xml-gzip per the BIMI profile).
var svgDataURIRegexp = regexp.MustCompile(`data:image/svg\+xml(?:-gzip)?(?:;[a-zA-Z0-9=/+.-]+)*;base64,([A-Za-z0-9+/=]+)`)

// analyzeBIMIVMC downloads and analyses the Verified Mark Certificate
// published in the BIMI a= tag. logoContent, when non-nil, is the SVG
// published at the l= URL, compared against the logo embedded in the
// certificate.
func (d *DNSAnalyzer) analyzeBIMIVMC(vmcURL, domain string, logoContent []byte) (*model.BIMICheck, *model.VMCInfo) {
	fail := func(messages ...string) (*model.BIMICheck, *model.VMCInfo) {
		c := bimiCheck("vmc", "Verified Mark Certificate", model.BIMICheckStatusFail, messages...)
		return &c, &model.VMCInfo{
			Valid: false,
			Error: utils.PtrTo(strings.Join(messages, "; ")),
		}
	}

	content, contentType, problems := d.fetchBIMIFile(vmcURL, maxBIMIFileSize)
	if len(problems) > 0 {
		return fail(problems...)
	}

	var warnings []string
	if contentType != "application/pem-certificate-chain" {
		warnings = append(warnings, fmt.Sprintf("VMC served with Content-Type %q, expected \"application/pem-certificate-chain\"", contentType))
	}

	// Parse every certificate of the PEM chain; the first one is the
	// leaf (subscriber) certificate.
	var certs []*x509.Certificate
	rest := content
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

	info := &model.VMCInfo{
		Issuer:       utils.PtrTo(leaf.Issuer.String()),
		Subject:      utils.PtrTo(leaf.Subject.String()),
		SerialNumber: utils.PtrTo(leaf.SerialNumber.String()),
		NotBefore:    utils.PtrTo(leaf.NotBefore),
		NotAfter:     utils.PtrTo(leaf.NotAfter),
		ChainLength:  utils.PtrTo(len(certs)),
	}
	if len(leaf.DNSNames) > 0 {
		info.SanDomains = utils.PtrTo(leaf.DNSNames)
	}

	var problems2 []string

	// Validity period
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		problems2 = append(problems2, fmt.Sprintf("The certificate is not yet valid (valid from %s)", leaf.NotBefore.Format(time.RFC3339)))
	}
	if now.After(leaf.NotAfter) {
		problems2 = append(problems2, fmt.Sprintf("The certificate expired on %s", leaf.NotAfter.Format(time.RFC3339)))
	} else if now.Add(30 * 24 * time.Hour).After(leaf.NotAfter) {
		warnings = append(warnings, fmt.Sprintf("The certificate expires soon (%s)", leaf.NotAfter.Format(time.RFC3339)))
	}

	// The certificate must cover the BIMI domain
	if !vmcCoversDomain(leaf.DNSNames, domain) {
		problems2 = append(problems2, fmt.Sprintf("The certificate Subject Alternative Names (%s) do not cover the domain %q", strings.Join(leaf.DNSNames, ", "), domain))
	}

	// BIMI Extended Key Usage
	hasBIMIEKU := false
	for _, eku := range leaf.UnknownExtKeyUsage {
		if eku.String() == oidBIMIExtKeyUsageStr {
			hasBIMIEKU = true
		}
	}
	info.HasBimiEku = utils.PtrTo(hasBIMIEKU)
	if !hasBIMIEKU {
		problems2 = append(problems2, "The certificate does not carry the BIMI Extended Key Usage (1.3.6.1.5.5.7.3.31): this is not a Verified Mark Certificate")
	}

	// Logotype extension and embedded logo comparison
	var logotypeValue []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == oidLogotypeExtensionStr {
			logotypeValue = ext.Value
		}
	}
	info.HasLogotype = utils.PtrTo(logotypeValue != nil)
	if logotypeValue == nil {
		problems2 = append(problems2, "The certificate does not carry the logotype extension (1.3.6.1.5.5.7.1.12) embedding the certified logo")
	} else {
		embeddedSVG, err := extractLogotypeSVG(logotypeValue)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Unable to extract the logo embedded in the certificate: %s", err))
		} else if logoContent != nil {
			matches := bytes.Equal(normalizeSVG(embeddedSVG), normalizeSVG(logoContent))
			info.LogoMatches = utils.PtrTo(matches)
			if !matches {
				problems2 = append(problems2, "The logo embedded in the certificate differs from the logo published at the l= URL: both must be identical")
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

	if len(problems2) > 0 {
		info.Valid = false
		info.Error = utils.PtrTo(strings.Join(problems2, "; "))
		c := bimiCheck("vmc", "Verified Mark Certificate", model.BIMICheckStatusFail, append(problems2, warnings...)...)
		return &c, info
	}

	info.Valid = true
	if len(warnings) > 0 {
		c := bimiCheck("vmc", "Verified Mark Certificate", model.BIMICheckStatusWarning, warnings...)
		return &c, info
	}
	c := bimiCheck("vmc", "Verified Mark Certificate", model.BIMICheckStatusPass)
	return &c, info
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

// extractLogotypeSVG extracts the SVG image embedded in the RFC 3709
// logotype extension. The image is carried as a base64 data URI, gzipped
// per the BIMI profile.
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
