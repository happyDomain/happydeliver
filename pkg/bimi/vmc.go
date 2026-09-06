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
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// OIDBIMIExtKeyUsage is the Extended Key Usage assigned to BIMI Verified Mark
// Certificates (id-kp-BrandIndicatorforMessageIdentification).
const OIDBIMIExtKeyUsage = "1.3.6.1.5.5.7.3.31"

// OIDLogotypeExtension is the RFC 3709 logotype extension carrying the
// certified brand logo.
const OIDLogotypeExtension = "1.3.6.1.5.5.7.1.12"

// OIDSCTList is the RFC 6962 extension carrying the Signed Certificate
// Timestamps that prove the certificate was logged to Certificate
// Transparency logs.
const OIDSCTList = "1.3.6.1.4.1.11129.2.4.2"

// The same three OIDs in the decoded form the certificates carry them in.
// Comparisons run over every extension and every unknown EKU of the chain, so
// they compare component by component rather than formatting each candidate
// back into its dotted string; the constants above stay the form used in
// messages.
var (
	bimiEKUOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}
	logotypeOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}
	sctListOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

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
	// IssuerHasBimiEku reports whether the certificate of the immediate
	// issuer carries the BIMI Extended Key Usage too, as the profile
	// requires of it. Nil when the chain does not carry that certificate.
	IssuerHasBimiEku *bool
	// HasLogotype reports whether the leaf carries the RFC 3709 logotype
	// extension (OIDLogotypeExtension).
	HasLogotype *bool
	// LogoHashVerified reports whether the logo embedded in the leaf matches
	// the logotypeHash the authority computed over it, which is the
	// integrity binding RFC 9399 provides between a certificate and the mark
	// it certifies. Nil when no hash could be checked, because the extension
	// could not be read or named no digest this implementation computes.
	LogoHashVerified *bool
	// LogoHashAlgorithm names the digest logotypeHash was verified with,
	// e.g. "SHA-256". Empty when no verification took place.
	LogoHashAlgorithm string
	// LogoMediaType is the media type the leaf carries its mark under.
	// Empty when the extension could not be read.
	LogoMediaType string
	// HasCRLDistributionPoints reports whether the leaf publishes where its
	// revocation status can be checked (RFC 5280 cRLDistributionPoints).
	HasCRLDistributionPoints *bool
	// SCTCount is the number of Signed Certificate Timestamps embedded in
	// the leaf, proving it was logged to Certificate Transparency logs. Nil
	// when the extension could not be read.
	SCTCount *int
	// ChainTrusted reports whether the chain leads to one of the trust
	// anchors the caller supplied. Nil when no anchor set was supplied, in
	// which case nothing is claimed about the issuer's legitimacy.
	ChainTrusted *bool
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

// VMCBinding names the BIMI Assertion Record a Verified Mark Certificate must
// be bound to. The certificate is issued for a domain, not for a host, so the
// binding carries every name the record may legitimately be identified by
// rather than a single domain.
type VMCBinding struct {
	// Selector is the selector the Assertion Record was found under.
	Selector string
	// Domain is the Author Domain the record was requested for.
	Domain string
	// OrganizationalDomain is Domain's organizational domain, which a
	// certificate may name in its stead. Leave empty when Domain has none,
	// or when it is Domain itself.
	OrganizationalDomain string
}

// acceptableSANs returns the dNSName values a Verified Mark Certificate may
// carry to be bound to this Assertion Record: the Author Domain and its
// organizational domain, each also in the <selector>._bimi.<domain> form that
// restricts the certificate to a single selector.
//
// This is the domain verification of draft-fetch-validation-vmc-wchuang,
// Section 5.2, gathered into one set: the specification sorts the certificate
// names into a "selector-set" and a "domain-set" before comparing, but a name
// carrying the _bimi label can never equal one that does not, so matching
// against the union decides the same way.
func (b VMCBinding) acceptableSANs() []string {
	var names []string
	for _, domain := range []string{b.Domain, b.OrganizationalDomain} {
		domain = normalizeDomain(domain)
		if domain == "" || slices.Contains(names, domain) {
			continue
		}
		names = append(names, domain, normalizeDomain(fmt.Sprintf("%s._bimi.%s", b.Selector, domain)))
	}
	return names
}

// matches reports whether the certificate's SAN dNSNames bind it to this
// Assertion Record. The comparison is exact: unlike a TLS server certificate,
// a VMC covers the domain it names and not the subdomains beneath it, and a
// subdomain is instead reached through the organizational domain the binding
// already carries.
func (b VMCBinding) matches(sans []string) bool {
	return matchesAny(b.acceptableSANs(), sans)
}

// matchesAny reports whether any of the certificate's SAN dNSNames is one of
// the acceptable names, which acceptableSANs already returns normalized.
func matchesAny(acceptable, sans []string) bool {
	for _, san := range sans {
		if slices.Contains(acceptable, normalizeDomain(san)) {
			return true
		}
	}
	return false
}

// analyzeVMCURL downloads the Verified Mark Certificate published in the BIMI
// a= tag and analyses it. logoContent, when non-nil, is the SVG published at
// the l= URL, compared against the logo embedded in the certificate.
func (v *Validator) analyzeVMCURL(ctx context.Context, vmcURL string, binding VMCBinding, logoContent []byte) (Check, *VMCInfo) {
	content, contentType, problems := v.fetchFile(ctx, vmcURL, MaxFileSize)
	return v.analyzeVMCFetch(fetchedFile{content: content, contentType: contentType, problems: problems}, binding, logoContent)
}

// analyzeVMCFetch is analyzeVMCURL for a certificate already downloaded, so
// that the caller can pull it at the same time as the logo instead of waiting
// for one fetch before starting the other.
func (v *Validator) analyzeVMCFetch(fetched fetchedFile, binding VMCBinding, logoContent []byte) (Check, *VMCInfo) {
	content, contentType, problems := fetched.content, fetched.contentType, fetched.problems
	if len(problems) > 0 {
		return newCheck("vmc", "Verified Mark Certificate", StatusFail, problems...),
			&VMCInfo{Valid: false, Error: strings.Join(problems, "; ")}
	}

	check, info := AnalyzeVMC(content, binding, logoContent, v.VMCRoots, v.now())

	// The Content-Type is a transport concern handled here rather than in
	// the pure AnalyzeVMC helper.
	if contentType != "application/pem-certificate-chain" {
		msg := fmt.Sprintf("VMC served with Content-Type %q, expected \"application/pem-certificate-chain\"", contentType)
		check.Messages = append(check.Messages, CheckMessage{Text: msg, Severity: SeverityWarning})
		if check.Status == StatusPass {
			check.Status = StatusWarning
		}
	}

	return check, info
}

// AnalyzeVMC parses and validates a PEM certificate chain as a BIMI Verified
// Mark Certificate. binding names the Assertion Record the certificate must be
// bound to. logoContent, when non-nil, is the SVG published at the l= URL,
// compared against the logo embedded in the certificate. roots, when non-nil,
// is the set of trust anchors the chain must lead to; a nil pool leaves the
// issuer's legitimacy unexamined and says so in the returned Check. now is the
// reference time used for the validity-period checks.
//
// It returns the "vmc" evidence Check and a VMCInfo describing the leaf
// certificate.
func AnalyzeVMC(pemChain []byte, binding VMCBinding, logoContent []byte, roots *x509.CertPool, now time.Time) (Check, *VMCInfo) {
	fail := func(messages ...string) (Check, *VMCInfo) {
		return newCheck("vmc", "Verified Mark Certificate", StatusFail, messages...),
			&VMCInfo{Valid: false, Error: strings.Join(messages, "; ")}
	}

	certs, err := parseVMCChain(pemChain)
	if err != nil {
		return fail(err.Error())
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
	var infos []string

	// The chain has to carry the certificates that issued the leaf: without
	// them nothing above the Verified Mark Certificate can be examined, and
	// the profile requires them to be published alongside it.
	if len(certs) < 2 {
		problems = append(problems, "The file contains only the Verified Mark Certificate: the certificate of the issuing CA must be published alongside it, so that the issuance chain can be verified")
	}

	// A Verified Mark Certificate is issued to a brand, not to an authority:
	// a leaf asserting it is a CA is not one.
	if leaf.BasicConstraintsValid && leaf.IsCA {
		problems = append(problems, "The Verified Mark Certificate asserts it is a certification authority: a mark certificate is an end-entity certificate")
	}

	validityProblems, validityWarnings := checkValidityPeriods(certs, now)
	problems = append(problems, validityProblems...)
	warnings = append(warnings, validityWarnings...)

	// The certificate must name the domain the Assertion Record belongs to
	if acceptable := binding.acceptableSANs(); !matchesAny(acceptable, leaf.DNSNames) {
		problems = append(problems, fmt.Sprintf(
			"The certificate Subject Alternative Names (%s) do not name this BIMI record: a Verified Mark Certificate must carry one of %s exactly",
			strings.Join(leaf.DNSNames, ", "), strings.Join(acceptable, ", ")))
	}

	// BIMI Extended Key Usage
	hasBIMIEKU := certHasBIMIEKU(leaf)
	info.HasBimiEku = &hasBIMIEKU
	if !hasBIMIEKU {
		problems = append(problems, "The certificate does not carry the BIMI Extended Key Usage (1.3.6.1.5.5.7.3.31): this is not a Verified Mark Certificate")
	}

	// The authority that issued it must itself be designated for that use:
	// the BIMI Extended Key Usage is required of the immediate issuer too.
	if len(certs) > 1 {
		issuerHasBIMIEKU := certHasBIMIEKU(certs[1])
		info.IssuerHasBimiEku = &issuerHasBIMIEKU
		if !issuerHasBIMIEKU {
			problems = append(problems, fmt.Sprintf("%s does not carry the BIMI Extended Key Usage (1.3.6.1.5.5.7.3.31): it is not designated to issue Verified Mark Certificates", certLabel(1, certs[1])))
		}
	}

	logotypeProblems, logotypeWarnings := checkLogotype(leaf, logoContent, info)
	problems = append(problems, logotypeProblems...)
	warnings = append(warnings, logotypeWarnings...)

	// Revocation has to remain checkable for the whole life of the
	// certificate, so the certificate has to say where.
	hasCRLDP := len(leaf.CRLDistributionPoints) > 0
	info.HasCRLDistributionPoints = &hasCRLDP
	if !hasCRLDP {
		problems = append(problems, "The certificate does not publish a CRL distribution point: its revocation status cannot be checked")
	}

	// Certificate Transparency: the issuance must be publicly auditable.
	sctCount, foundSCT, err := parseSCTList(leaf)
	switch {
	case !foundSCT:
		problems = append(problems, "The certificate does not carry any Signed Certificate Timestamp (1.3.6.1.4.1.11129.2.4.2): its issuance was not logged to Certificate Transparency logs")
	case err != nil:
		problems = append(problems, fmt.Sprintf("The Signed Certificate Timestamp list of the certificate cannot be read: %s", err))
	case sctCount == 0:
		info.SCTCount = &sctCount
		problems = append(problems, "The Signed Certificate Timestamp list of the certificate is empty: at least one timestamp is required")
	default:
		info.SCTCount = &sctCount
	}

	anchorProblems, anchorInfos := checkChainAnchoring(certs, roots, now, info)
	problems = append(problems, anchorProblems...)
	infos = append(infos, anchorInfos...)

	info.Valid = len(problems) == 0

	status := statusFor(problems, warnings)
	if status == StatusFail {
		info.Error = strings.Join(problems, "; ")
	}

	return newCheckWithSeverities("vmc", "Verified Mark Certificate", status, problems, warnings, infos), info
}

// certLabel names a certificate of the chain in a message. The leaf is the
// Verified Mark Certificate itself and is simply "the certificate"; the ones
// above it are told apart by their position and their subject, so a domain
// owner reading the report knows which link of the chain is at fault.
func certLabel(i int, cert *x509.Certificate) string {
	if i == 0 {
		return "The certificate"
	}
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	return fmt.Sprintf("Issuer certificate #%d (%s)", i+1, name)
}

// certHasBIMIEKU reports whether cert carries the BIMI Extended Key Usage.
// The OID is unknown to crypto/x509, which files it under UnknownExtKeyUsage
// rather than in the parsed ExtKeyUsage list.
func certHasBIMIEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(bimiEKUOID) {
			return true
		}
	}
	return false
}

// parseSCTList counts the Signed Certificate Timestamps embedded in cert by
// the RFC 6962 extension. found reports whether the extension is present at
// all, which is what tells "not logged" apart from "logged, but the proof is
// unreadable".
//
// Only the structure is walked: validating the timestamps themselves would
// require the public keys of the recognised Certificate Transparency logs,
// which is a matter of receiver policy, like the trust anchors.
func parseSCTList(cert *x509.Certificate) (count int, found bool, err error) {
	var payload []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(sctListOID) {
			payload = ext.Value
			found = true
			break
		}
	}
	if !found {
		return 0, false, nil
	}

	// The extension value is a DER OCTET STRING wrapping the TLS-encoded
	// SignedCertificateTimestampList of RFC 6962, Section 3.3.
	var list []byte
	if rest, err := asn1.Unmarshal(payload, &list); err != nil {
		return 0, true, fmt.Errorf("invalid extension payload: %w", err)
	} else if len(rest) > 0 {
		return 0, true, fmt.Errorf("invalid extension payload: %d trailing bytes", len(rest))
	}

	if len(list) < 2 {
		return 0, true, fmt.Errorf("the timestamp list is truncated")
	}
	// A 16-bit length prefix announces the whole list, then each timestamp
	// is announced by its own.
	if declared := int(binary.BigEndian.Uint16(list)); declared != len(list)-2 {
		return 0, true, fmt.Errorf("the timestamp list announces %d bytes but carries %d", declared, len(list)-2)
	}

	for rest := list[2:]; len(rest) > 0; count++ {
		if len(rest) < 2 {
			return 0, true, fmt.Errorf("timestamp #%d is truncated", count+1)
		}
		length := int(binary.BigEndian.Uint16(rest))
		if len(rest[2:]) < length {
			return 0, true, fmt.Errorf("timestamp #%d announces %d bytes but only %d remain", count+1, length, len(rest[2:]))
		}
		rest = rest[2+length:]
	}

	return count, true, nil
}

// normalizeSVG makes the byte comparison between the published and the
// embedded logo resilient to the differences that do not change the document:
// the end-of-line characters, which RFC 9399 section 7 canonicalizes to
// linefeeds before hashing an SVG, and the surrounding whitespace.
//
// The trimming goes beyond that canonicalization, and belongs to this
// comparison alone: confronting the published logo with the embedded one is a
// MAY of the Verified Mark Certificate profile, so a tolerant comparison is
// defensible here, where the hash that authenticates the mark tolerates
// nothing.
func normalizeSVG(svg []byte) []byte {
	return bytes.TrimSpace(canonicalizeEOL(svg))
}

// parseVMCChain decodes the PEM chain the a= URL served. The first certificate
// is the leaf (subscriber) certificate, the ones after it its issuers.
func parseVMCChain(pemChain []byte) ([]*x509.Certificate, error) {
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
			return nil, fmt.Errorf("Unable to parse certificate #%d of the chain: %s", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("The file does not contain any PEM-encoded certificate")
	}
	return certs, nil
}

// checkValidityPeriods checks the validity period of every certificate of the
// chain, not just of the leaf: an expired issuer invalidates what it signed.
func checkValidityPeriods(certs []*x509.Certificate, now time.Time) (problems, warnings []string) {
	for i, cert := range certs {
		label := certLabel(i, cert)
		switch {
		case now.Before(cert.NotBefore):
			problems = append(problems, fmt.Sprintf("%s is not yet valid (valid from %s)", label, cert.NotBefore.Format(time.RFC3339)))
		case now.After(cert.NotAfter):
			problems = append(problems, fmt.Sprintf("%s expired on %s", label, cert.NotAfter.Format(time.RFC3339)))
		case now.Add(30 * 24 * time.Hour).After(cert.NotAfter):
			warnings = append(warnings, fmt.Sprintf("%s expires soon (%s)", label, cert.NotAfter.Format(time.RFC3339)))
		}
	}
	return problems, warnings
}

// checkLogotype examines the mark the certificate embeds and records what it
// found in info. logoContent, when non-nil, is the SVG published at the l= URL,
// which the certified mark must be identical to.
func checkLogotype(leaf *x509.Certificate, logoContent []byte, info *VMCInfo) (problems, warnings []string) {
	// Logotype extension: the mark itself. RFC 9399 binds it to the
	// certificate through logotypeHash, and its section 4.1 has a client
	// discard logotype data whose hash does not match, so nothing is
	// compared against the embedded logo until that hash has checked out.
	var logotypeValue []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(logotypeOID) {
			logotypeValue = ext.Value
			break
		}
	}
	hasLogotype := logotypeValue != nil
	info.HasLogotype = &hasLogotype
	if logotypeValue == nil {
		problems = append(problems, "The certificate does not carry the logotype extension (1.3.6.1.5.5.7.1.12) embedding the certified logo")
	} else {
		mark, markWarnings, err := parseLogotypeExtension(logotypeValue)
		warnings = append(warnings, markWarnings...)
		switch {
		case errors.Is(err, errLogotypeHashMismatch):
			verified := false
			info.LogoHashVerified = &verified
			problems = append(problems, "The logo embedded in the certificate does not match the hash the authority certified it by: it is not the logo the certificate was issued for, and it cannot be trusted")
		case err != nil:
			problems = append(problems, err.Error())
		default:
			verified := true
			info.LogoHashVerified = &verified
			info.LogoHashAlgorithm = mark.HashAlgorithm
			info.LogoMediaType = mark.MediaType
			if logoContent != nil {
				matches := bytes.Equal(normalizeSVG(mark.SVG), normalizeSVG(logoContent))
				info.LogoMatches = &matches
				if !matches {
					problems = append(problems, "The logo embedded in the certificate differs from the logo published at the l= URL: both must be identical")
				}
			}
		}
	}
	return problems, warnings
}

// checkChainAnchoring verifies the chain against itself and, when roots is
// non-nil, against the Mark Verifying Authorities the caller recognises.
func checkChainAnchoring(certs []*x509.Certificate, roots *x509.CertPool, now time.Time, info *VMCInfo) (problems, infos []string) {
	// Each certificate must be signed by the next one. This is what the
	// chain says about itself, and it names the faulty link where the
	// anchoring below can only reject the chain as a whole.
	for i := 0; i+1 < len(certs); i++ {
		err := certs[i].CheckSignatureFrom(certs[i+1])
		if err == nil {
			continue
		}
		var violation x509.ConstraintViolationError
		if errors.As(err, &violation) {
			problems = append(problems, fmt.Sprintf("%s is not allowed to sign certificates, yet the chain presents it as the issuer of %s", certLabel(i+1, certs[i+1]), certLabel(i, certs[i])))
		} else {
			problems = append(problems, fmt.Sprintf("%s is not signed by the next certificate in the provided chain: %s", certLabel(i, certs[i]), err))
		}
		break
	}

	// Anchoring: whether the issuer is an authority the caller recognises.
	// Mark certificate roots are a matter of receiver policy and are absent
	// from the system trust store, so without a pool there is nothing to
	// anchor to, and the check reports that it did not happen rather than
	// letting the chain pass for trusted.
	if roots == nil {
		infos = append(infos, "The issuance chain was not checked against a set of trusted BIMI root certificates: its consistency is verified, but not that it leads to a recognised Mark Verifying Authority")
	} else {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		// The BIMI Extended Key Usage is unknown to crypto/x509, which
		// would reject the whole chain if asked to filter on it; the two
		// checks above cover it. No DNSName either: a mark certificate is
		// bound to its record by VMCBinding, not by the TLS name rules.
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		trusted := err == nil
		info.ChainTrusted = &trusted
		if !trusted {
			problems = append(problems, fmt.Sprintf("The issuance chain does not lead to a trusted BIMI root certificate: %s", err))
		}
	}
	return problems, infos
}
