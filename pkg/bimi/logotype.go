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
	"crypto"
	_ "crypto/sha1"   // registers crypto.SHA1, which real logotypeHashes use
	_ "crypto/sha256" // registers crypto.SHA224 and crypto.SHA256
	_ "crypto/sha512" // registers crypto.SHA384 and crypto.SHA512
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"slices"
	"strings"
)

// The RFC 9399 (which obsoletes RFC 3709) logotype extension, section 4.1.
// The ASN.1 module uses IMPLICIT TAGS, so only the four members of
// LogotypeExtn are EXPLICIT; everything below them is implicitly tagged.
//
//	LogotypeExtn ::= SEQUENCE {
//	   communityLogos  [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL,
//	   issuerLogo      [1] EXPLICIT LogotypeInfo OPTIONAL,
//	   subjectLogo     [2] EXPLICIT LogotypeInfo OPTIONAL,
//	   otherLogos      [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }
//
// Only subjectLogo is read: it is the mark certified for the subject of the
// certificate, and the only one that may stand for the sending domain. The
// three others are the authority's own branding, a community emblem and
// unclassified images; displaying any of them as the sender's mark would be a
// misattribution. They are still declared, and in this order, because
// encoding/asn1 matches the members of a SEQUENCE positionally: without them a
// certificate carrying an issuerLogo alongside its subjectLogo would leave the
// latter unmatched.
type logotypeExtn struct {
	CommunityLogos asn1.RawValue `asn1:"optional,explicit,tag:0"`
	IssuerLogo     asn1.RawValue `asn1:"optional,explicit,tag:1"`
	SubjectLogo    asn1.RawValue `asn1:"optional,explicit,tag:2"`
	OtherLogos     asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

// logotypeData is the direct alternative of the LogotypeInfo CHOICE, carried
// under an implicit [0]:
//
//	LogotypeData ::= SEQUENCE {
//	   image  SEQUENCE OF LogotypeImage OPTIONAL,
//	   audio  [1] SEQUENCE OF LogotypeAudio OPTIONAL }
//
// audio is not declared: encoding/asn1 tolerates trailing members of a
// SEQUENCE, and a BIMI Indicator is an image.
type logotypeData struct {
	Image []logotypeImage `asn1:"optional"`
}

// logotypeImage is LogotypeImage. Its optional imageInfo member (recommended
// display size, file size, language) is not declared: it is advisory, no
// conformance verdict rests on it, and encoding/asn1 tolerates it as a
// trailing member when an authority includes one.
type logotypeImage struct {
	ImageDetails logotypeDetails
}

// logotypeDetails is LogotypeDetails: what the image is, where to get it, and
// the hash that binds it to the certificate.
//
// LogotypeURI must not carry an `asn1:"ia5"` tag: on a slice the tag is
// inoperative when parsing, since parseSequenceOf already lets an IA5String
// stand for a PrintableString, and it is an outright error when marshalling.
type logotypeDetails struct {
	MediaType    string `asn1:"ia5"`
	LogotypeHash []hashAlgAndValue
	LogotypeURI  []string
}

// hashAlgAndValue is HashAlgAndValue. The algorithm parameters are never
// examined: RFC 3279 puts a NULL after the SHA-1 identifier while RFC 5754
// omits it after the SHA-2 ones, and both spellings are issued today.
type hashAlgAndValue struct {
	HashAlg   pkix.AlgorithmIdentifier
	HashValue []byte
}

// logotypeHashAlgorithms maps the digests a logotypeHash may identify to their
// implementation. SHA-1 is listed although RFC 9399 section 4.1 tells
// authorities to use the hash that goes with the certificate signature: every
// Verified Mark Certificate examined, from two different authorities, signs
// with SHA-256 and hashes its mark with SHA-1. Refusing SHA-1 would discard
// the mark of every certificate in the field, and the digest is an integrity
// binding inside an already-signed certificate rather than a signature: a
// second preimage on it buys nothing that forging the certificate would not
// already give.
//
// MD5 is deliberately absent: a digest we will not compute is reported as one
// we cannot verify, which is the right outcome for a broken one.
var logotypeHashAlgorithms = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// svgMediaTypes are the media types a certificate may carry an SVG mark under.
// RFC 9399 section 7 registers the first two; the last two are unregistered
// spellings that the same section acknowledges are widely implemented.
var svgMediaTypes = []string{
	"image/svg+xml",
	"image/svg+xml+gzip",
	"image/svg+xml-gzip",
	"image/svg+xml-compressed",
}

// certifiedMark is the brand mark a Verified Mark Certificate carries: the SVG
// the authority certified, once it has been extracted from the logotype
// extension and checked against the hash that binds it to the certificate.
type certifiedMark struct {
	// SVG is the document itself, base64-decoded and inflated, exactly as
	// the certificate carries it.
	SVG []byte
	// MediaType is the media type the certificate announces the mark under.
	MediaType string
	// HashAlgorithm names the digest logotypeHash was verified with, e.g.
	// "SHA-256".
	HashAlgorithm string
}

// errLogotypeHashMismatch reports that the logo embedded in the certificate is
// not the one the authority hashed. RFC 9399 section 4.1 requires a client to
// discard logotype data whose hash does not match, so the mark is never
// returned alongside this error: nothing downstream can compare against an
// image the certificate does not vouch for.
var errLogotypeHashMismatch = errors.New("the logo embedded in the certificate does not match the logotypeHash the authority computed over it")

// errNotADataURI tells a logotypeURI pointing somewhere else apart from a
// malformed one, so that a certificate linking to its mark can be reported for
// what it is.
var errNotADataURI = errors.New("not a data URI")

// parseLogotypeExtension reads the brand mark out of the RFC 9399 logotype
// extension of a Verified Mark Certificate.
//
// Only the subjectLogo is read, and only through direct addressing: the BIMI
// profile has the Indicator embedded in the certificate as a data URI
// (draft-fetch-validation-vmc, sections 4.1 and 4.2), and a mark filed under
// issuerLogo or communityLogos belongs to the authority or to a community, not
// to the domain being analysed.
//
// The mark is returned only once its logotypeHash has been verified, so an
// unauthenticated SVG never leaves this function. A hash that does not match
// yields errLogotypeHashMismatch and no mark, which is what RFC 9399
// section 4.1 means by discarding the logotype data.
//
// warnings gather the deviations that do not stop the mark from being read.
func parseLogotypeExtension(extensionValue []byte) (mark *certifiedMark, warnings []string, err error) {
	var extn logotypeExtn
	rest, err := asn1.Unmarshal(extensionValue, &extn)
	if err != nil {
		return nil, nil, fmt.Errorf("The logotype extension of the certificate is not a well-formed RFC 9399 structure: %s", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("The logotype extension of the certificate carries %d trailing bytes after its RFC 9399 structure", len(rest))
	}

	if len(extn.SubjectLogo.FullBytes) == 0 {
		return nil, nil, errors.New("The logotype extension of the certificate carries no subjectLogo: only the mark certified for the subject of the certificate may be displayed for this domain, and the certificate does not carry one")
	}

	details, err := subjectLogoDetails(extn.SubjectLogo)
	if err != nil {
		return nil, nil, err
	}

	mediaType, payload, err := embeddedImage(details)
	if err != nil {
		return nil, nil, err
	}

	// The compression is read off the payload itself, never off the media
	// type: both certificates issued by real Mark Verifying Authorities
	// announce "image/svg+xml" for gzipped bytes, so only the gzip header
	// tells the truth. This is the same reasoning DecodeLogo gives for the
	// file published at the l= URL.
	svg, compressed, err := DecodeLogo(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("The logo embedded in the certificate cannot be decoded: %s", err)
	}
	if !compressed {
		return nil, nil, errors.New("The logo embedded in the certificate is not gzip-compressed: a mark carried by a data URI has to be, both by RFC 9399 section 7 and by the Verified Mark Certificate profile")
	}

	algorithm, warning, err := verifyLogotypeHash(svg, details.LogotypeHash)
	if err != nil {
		return nil, nil, err
	}
	if warning != "" {
		warnings = append(warnings, warning)
	}

	return &certifiedMark{SVG: svg, MediaType: mediaType, HashAlgorithm: algorithm}, warnings, nil
}

// subjectLogoDetails resolves the LogotypeInfo CHOICE of a subjectLogo and
// returns the details of the image it describes.
//
// The alternative is discriminated before being parsed. Unmarshalling straight
// into the direct alternative would report an indirect one as a tag mismatch,
// which says nothing to a domain owner about what their certificate actually
// does.
func subjectLogoDetails(subjectLogo asn1.RawValue) (*logotypeDetails, error) {
	// subjectLogo is EXPLICIT, so its Bytes are the complete TLV of the
	// alternative inside it. A bare RawValue matches whichever it is.
	var choice asn1.RawValue
	rest, err := asn1.Unmarshal(subjectLogo.Bytes, &choice)
	if err != nil {
		return nil, fmt.Errorf("The subjectLogo entry of the logotype extension is malformed: %s", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("The subjectLogo entry of the logotype extension carries %d trailing bytes", len(rest))
	}

	switch {
	case choice.Class != asn1.ClassContextSpecific:
		return nil, errors.New("The subjectLogo entry of the logotype extension is not a LogotypeInfo")
	case choice.Tag == 1:
		return nil, errors.New("The certificate references its logo instead of embedding it (indirect addressing): a Verified Mark Certificate has to carry the Indicator itself, in a data URI")
	case choice.Tag != 0:
		return nil, fmt.Errorf("The subjectLogo entry of the logotype extension uses an unknown LogotypeInfo alternative ([%d])", choice.Tag)
	}

	// The direct alternative is [0] IMPLICIT, so the context tag replaces
	// the SEQUENCE tag: the whole element has to be handed over, not just
	// its contents.
	var data logotypeData
	if _, err := asn1.UnmarshalWithParams(choice.FullBytes, &data, "tag:0"); err != nil {
		return nil, fmt.Errorf("The logo data embedded in the certificate is malformed: %s", err)
	}
	if len(data.Image) == 0 {
		return nil, errors.New("The subjectLogo of the certificate carries no image: there is no Indicator to display")
	}

	return &data.Image[0].ImageDetails, nil
}

// embeddedImage returns the media type and the raw bytes of the image the
// details embed.
//
// RFC 9399 allows a logotype to list several URIs for the same image, as
// alternative locations. They are scanned in order for the first one that
// embeds the image rather than pointing at it; a certificate offering only
// links carries no Indicator this profile can use.
func embeddedImage(details *logotypeDetails) (mediaType string, payload []byte, err error) {
	if len(details.LogotypeURI) == 0 {
		return "", nil, errors.New("The logotype extension of the certificate names no location for the logo")
	}

	found := false
	for _, uri := range details.LogotypeURI {
		mediaType, payload, err = parseDataURI(uri)
		if errors.Is(err, errNotADataURI) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		found = true
		break
	}
	if !found {
		return "", nil, errors.New("The certificate links to its logo instead of embedding it: a Verified Mark Certificate has to carry the Indicator itself, in a data URI")
	}

	// RFC 9399 section 4.3: what LogotypeDetails announces and what the data
	// URI announces have to be one and the same media type.
	declared, _, err := mime.ParseMediaType(details.MediaType)
	if err != nil {
		return "", nil, fmt.Errorf("The logotype extension of the certificate announces an unreadable media type %q: %s", details.MediaType, err)
	}
	if mediaType == "" {
		return "", nil, fmt.Errorf("The data URI embedding the logo announces no media type, where the logotype extension announces %q: both have to name the same one", declared)
	}
	if mediaType != declared {
		return "", nil, fmt.Errorf("The logotype extension of the certificate announces the media type %q while the data URI embedding the logo announces %q: both have to name the same one", declared, mediaType)
	}

	if !slices.Contains(svgMediaTypes, mediaType) {
		return "", nil, fmt.Errorf("The logo embedded in the certificate is announced as %q: a BIMI Indicator has to be an SVG document", mediaType)
	}

	return mediaType, payload, nil
}

// parseDataURI splits an RFC 2397 "data:[<mediatype>][;base64],<data>" URI
// into the media type it announces and the bytes it carries. A URI that is not
// a data one is reported with errNotADataURI, so that a certificate pointing
// at its logo can be told apart from one that malforms it.
func parseDataURI(uri string) (mediaType string, payload []byte, err error) {
	rest, ok := cutPrefixFold(strings.TrimSpace(uri), "data:")
	if !ok {
		return "", nil, errNotADataURI
	}

	meta, data, found := strings.Cut(rest, ",")
	if !found {
		return "", nil, errors.New("The data URI embedding the logo has no comma separating its media type from its payload")
	}

	// RFC 2397 puts ";base64" last, after any media type parameter. Without
	// it the bytes cannot be recovered at all, so nothing downstream (the
	// hash, the comparison with the published logo, the profile checks)
	// could run.
	meta, isBase64 := cutSuffixFold(strings.TrimSpace(meta), ";base64")
	if !isBase64 {
		return "", nil, errors.New("The logo embedded in the certificate is not base64-encoded: a data URI carrying a compressed document has to announce ;base64")
	}

	if meta != "" {
		if mediaType, _, err = mime.ParseMediaType(meta); err != nil {
			return "", nil, fmt.Errorf("The data URI embedding the logo announces an unreadable media type %q: %s", meta, err)
		}
	}

	// A data URI is usually a single unbroken line: only pay for stripping
	// the folding whitespace when there is some to strip.
	if strings.ContainsAny(data, " \t\r\n") {
		data = strings.Join(strings.Fields(data), "")
	}

	payload, err = base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", nil, fmt.Errorf("The base64 payload of the logo embedded in the certificate is invalid: %s", err)
	}

	return mediaType, payload, nil
}

// verifyLogotypeHash checks svg against the hashes the certificate binds it to.
// RFC 9399 section 4.1 has the client compute one of the identified digests and
// discard the image unless it matches, so anything short of a match is an
// error: errLogotypeHashMismatch when a digest could be computed and disagreed,
// a plain error when none of the identified ones can be.
//
// algorithm names the digest that established the match. warning is set when
// the match was only obtained on the bytes as they stand, which RFC 9399
// section 7 does not allow the authority to hash.
func verifyLogotypeHash(svg []byte, hashes []hashAlgAndValue) (algorithm, warning string, err error) {
	// Section 7: the hash of an SVG covers the uncompressed document with
	// its end-of-line characters canonicalized to linefeeds.
	canonical := canonicalizeEOL(svg)

	var identified []string
	computed := false

	for _, entry := range hashes {
		oid := entry.HashAlg.Algorithm.String()
		identified = append(identified, oid)

		hash, known := logotypeHashAlgorithms[oid]
		if !known || !hash.Available() {
			continue
		}
		computed = true

		if bytes.Equal(digest(hash, canonical), entry.HashValue) {
			return hash.String(), "", nil
		}

		// RFC 9399 is from 2023, long after the tooling of the authorities
		// issuing today, and no certificate examined carries an end-of-line
		// character at all: the rule is untested in the field. An authority
		// that hashed the document as it stands still binds it to the
		// certificate, it just computed the hash the wrong way, and saying
		// so beats reporting a logo that is genuinely the certified one as
		// an impostor.
		if !bytes.Equal(canonical, svg) && bytes.Equal(digest(hash, svg), entry.HashValue) {
			return hash.String(), fmt.Sprintf("The %s hash the certificate binds its logo by covers the document with its end-of-line characters left as they are, where RFC 9399 section 7 has them canonicalized to linefeeds: the logo is the certified one, but the authority computed the hash the wrong way", hash), nil
		}
	}

	if !computed {
		if len(identified) == 0 {
			return "", "", errors.New("The logotype extension of the certificate carries no hash of the embedded logo: the logo cannot be authenticated, and RFC 9399 section 4.1 has unauthenticated logotype data discarded")
		}
		return "", "", fmt.Errorf("The logotype extension of the certificate hashes the embedded logo with %s, which this implementation cannot compute: the logo cannot be authenticated", strings.Join(identified, ", "))
	}

	return "", "", errLogotypeHashMismatch
}

// digest returns the hash of b, hash having been checked as Available.
func digest(hash crypto.Hash, b []byte) []byte {
	h := hash.New()
	h.Write(b)
	return h.Sum(nil)
}

// canonicalizeEOL rewrites CRLF and lone CR as the single linefeed RFC 9399
// section 7 requires as the end-of-line character of an SVG being hashed.
//
// The result feeds a hash and nothing else: the bytes the certificate carries
// are what gets reported, so that a logo published with other line endings is
// seen for what it is instead of being quietly rewritten.
func canonicalizeEOL(svg []byte) []byte {
	if !bytes.ContainsRune(svg, '\r') {
		return svg
	}

	out := make([]byte, 0, len(svg))
	for i := 0; i < len(svg); i++ {
		switch {
		case svg[i] != '\r':
			out = append(out, svg[i])
		case i+1 < len(svg) && svg[i+1] == '\n':
			// CRLF: the CR goes, the LF that follows stays.
		default:
			out = append(out, '\n')
		}
	}
	return out
}

// cutPrefixFold is strings.CutPrefix, matching the prefix without regard to
// case.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// cutSuffixFold is strings.CutSuffix, matching the suffix without regard to
// case.
func cutSuffixFold(s, suffix string) (string, bool) {
	if len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}
