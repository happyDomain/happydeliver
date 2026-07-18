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

// Package bimi validates Brand Indicators for Message Identification (BIMI)
// records and the assets they reference: the SVG Tiny Portable/Secure logo
// and the Verified Mark Certificate (VMC).
//
// The package is self-contained and has no dependency on the rest of
// happyDeliver, so it can be reused as a standalone BIMI validation library.
// It reports, for every record, why it is considered valid or invalid
// through a list of per-check evidence (Check values) instead of a bare
// boolean.
//
// A minimal use looks like:
//
//	v := bimi.NewValidator()
//	rec, err := v.Analyze(ctx, "example.com", "default")
//
// The returned Record fully describes validity (Valid, Error, Checks, VMC).
// The building blocks (ParseRecord, CheckLogoXML, CheckLogoSVGTinyPS,
// AnalyzeVMC) are also exported for callers that already hold the record
// text or the assets.
package bimi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// MaxLogoSize is the maximum size allowed for a BIMI SVG logo (BIMI
	// group recommendation: 32 kilobytes).
	MaxLogoSize int64 = 32 * 1024

	// MaxFileSize is a hard cap on any file downloaded during BIMI
	// evidence collection (VMC chains are larger than logos).
	MaxFileSize int64 = 512 * 1024
)

// ErrNoRecord is returned by Lookup and Analyze when the domain publishes no
// BIMI record for the requested selector.
var ErrNoRecord = errors.New("no BIMI record found")

// CheckStatus is the outcome of an individual evidence check.
type CheckStatus string

const (
	StatusPass    CheckStatus = "pass"
	StatusFail    CheckStatus = "fail"
	StatusWarning CheckStatus = "warning"
	StatusSkipped CheckStatus = "skipped"
)

// Check is one evidence check performed on a BIMI record's assets.
type Check struct {
	// Name is a machine-readable identifier (e.g. "logo_fetch").
	Name string
	// Description is a human-readable title.
	Description string
	// Status is the check outcome.
	Status CheckStatus
	// Messages explains a failure or warning; empty when the check passed.
	Messages []string
}

// Record is a parsed BIMI record together with the evidence gathered about
// the assets it references.
type Record struct {
	// Selector is the BIMI selector queried (e.g. "default").
	Selector string
	// Domain is the domain the record belongs to.
	Domain string
	// Record is the raw TXT record content.
	Record string
	// LogoURL is the value of the l= tag (empty for a declination record).
	LogoURL string
	// VMCURL is the value of the a= tag (empty when no VMC is published).
	VMCURL string
	// Valid reports whether the record and its assets are compliant.
	Valid bool
	// Error, when set, explains why the record is invalid.
	Error string
	// Checks holds the per-asset evidence checks (nil until ValidateAssets
	// runs).
	Checks []Check
	// VMC holds the analysis of the Verified Mark Certificate, when one is
	// published.
	VMC *VMCInfo
}

// Resolver looks up DNS TXT records. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validator gathers the dependencies needed to fetch and validate BIMI
// assets. The zero value is not usable: Resolver is required for Lookup and
// Analyze. HTTPClient defaults to http.DefaultClient and Now to time.Now.
type Validator struct {
	// HTTPClient fetches the logo and VMC files. Defaults to
	// http.DefaultClient.
	HTTPClient *http.Client
	// Resolver performs the DNS TXT lookup.
	Resolver Resolver
	// Now returns the reference time for certificate validity checks.
	// Defaults to time.Now.
	Now func() time.Time
}

// NewValidator returns a Validator ready to use, backed by a default HTTP
// client with a sane timeout and the system DNS resolver. Callers that need
// custom transport, DNS or reference time can set the corresponding fields on
// the returned Validator, or build the struct literal directly.
func NewValidator() *Validator {
	return &Validator{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Resolver:   &net.Resolver{},
	}
}

func (v *Validator) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return http.DefaultClient
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// newCheck builds a Check value.
func newCheck(name, description string, status CheckStatus, messages ...string) Check {
	c := Check{Name: name, Description: description, Status: status}
	if len(messages) > 0 {
		c.Messages = messages
	}
	return c
}

// BIMI tag matchers. A tag must appear at the start of the record or right
// after a ';' separator so that a value which happens to contain "<tag>="
// (e.g. "html=1" for tag "l") is not misread as that tag. The tag set is
// fixed, so the regexps are compiled once at package load.
var (
	bimiLogoTag = regexp.MustCompile(`(?:^|;)\s*l=([^;]+)`)
	bimiVMCTag  = regexp.MustCompile(`(?:^|;)\s*a=([^;]+)`)
	bimiHasLogo = regexp.MustCompile(`(?:^|;)\s*l=`)
)

// bimiTag extracts a tag value from a BIMI record using the given precompiled
// matcher (whose first submatch is the value).
func bimiTag(record string, re *regexp.Regexp) string {
	matches := re.FindStringSubmatch(record)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// ParseRecord parses a raw BIMI TXT record into a Record. The Record's
// LogoURL and VMCURL are always populated from the l= and a= tags. When the
// record is syntactically valid, Valid is true and Error is empty; otherwise
// Valid is false and Error explains why. No asset is fetched.
func ParseRecord(domain, selector, txt string) *Record {
	rec := &Record{
		Selector: selector,
		Domain:   domain,
		Record:   txt,
		LogoURL:  bimiTag(txt, bimiLogoTag),
		VMCURL:   bimiTag(txt, bimiVMCTag),
	}

	switch {
	case !strings.HasPrefix(txt, "v=BIMI1"):
		rec.Error = notABIMIRecordError(txt)
	case !bimiHasLogo.MatchString(txt):
		rec.Error = "BIMI record is missing the l= (logo URL) tag"
	default:
		rec.Valid = true
	}

	return rec
}

// notABIMIRecordError builds an explanatory error for a record found at the
// BIMI location that is not a BIMI record, hinting at the likely
// misconfiguration when a known record type is detected (commonly a DMARC
// record placed there by mistake).
func notABIMIRecordError(txt string) string {
	if desc := describeMisplacedRecord(leadingVersion(txt), "BIMI"); desc != "" {
		return fmt.Sprintf("No BIMI record found (%s is published at the BIMI location; this is a misconfiguration)", desc)
	}
	return "No BIMI record found (the record at the BIMI location does not begin with v=BIMI1)"
}

// leadingVersion returns the value of a record's leading "v=" tag (up to the
// first ';' or whitespace), or "" if the record does not start with one. It
// handles both ';'-delimited records (BIMI/DKIM/DMARC) and space-delimited
// ones (SPF).
func leadingVersion(record string) string {
	r := strings.TrimSpace(record)
	if !strings.HasPrefix(r, "v=") {
		return ""
	}
	v := r[len("v="):]
	if i := strings.IndexAny(v, "; \t"); i >= 0 {
		v = v[:i]
	}
	return v
}

// describeMisplacedRecord returns a human-readable description ("a DMARC
// record", "an SPF record", …) of a record identified by its "v=" version
// value, or "" when the version is unknown. It is used to explain the common
// misconfiguration (or misbehaving resolver) where a record of the wrong type
// is served at a BIMI/DKIM/SPF location.
//
// ownFamily names the record type expected at the caller's location (e.g.
// "BIMI" for a BIMI lookup). A record whose version belongs to that family
// (an unsupported-version record of the location's own type) is not
// "misplaced", so "" is returned and the caller falls back to its generic
// message.
func describeMisplacedRecord(version, ownFamily string) string {
	v := strings.ToUpper(version)
	if ownFamily != "" && strings.HasPrefix(v, strings.ToUpper(ownFamily)) {
		return ""
	}
	switch {
	case strings.HasPrefix(v, "DMARC"):
		return "a DMARC record"
	case strings.HasPrefix(v, "SPF"):
		return "an SPF record"
	case strings.HasPrefix(v, "DKIM"):
		return "a DKIM record"
	case strings.HasPrefix(v, "BIMI"):
		return "a BIMI record"
	default:
		return ""
	}
}

// Lookup resolves and parses the BIMI record published at
// selector._bimi.domain. It returns ErrNoRecord when no record exists, or the
// resolver error when the DNS query fails. Assets are not validated; call
// ValidateAssets or use Analyze for that.
func (v *Validator) Lookup(ctx context.Context, domain, selector string) (*Record, error) {
	if v.Resolver == nil {
		return nil, errors.New("bimi: Validator.Resolver is nil")
	}

	name := fmt.Sprintf("%s._bimi.%s", selector, domain)
	txtRecords, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(txtRecords) == 0 {
		return nil, ErrNoRecord
	}

	// BIMI records can be split across several TXT strings.
	return ParseRecord(domain, selector, strings.Join(txtRecords, "")), nil
}

// Analyze looks up the BIMI record for domain/selector, parses it and, when
// it is syntactically valid, runs the asset evidence checks. The returned
// Record fully describes validity. A non-nil error is returned only when the
// DNS lookup fails or no record exists (ErrNoRecord).
func (v *Validator) Analyze(ctx context.Context, domain, selector string) (*Record, error) {
	rec, err := v.Lookup(ctx, domain, selector)
	if err != nil {
		return nil, err
	}
	if rec.Valid {
		v.ValidateAssets(ctx, rec)
	}
	return rec, nil
}

// ValidateAssets performs the evidence checks (logo download, XML
// well-formedness, SVG Tiny P/S profile, VMC analysis) for a syntactically
// valid record, filling rec.Checks and rec.VMC. When a mandatory check fails
// it sets rec.Valid to false and rec.Error. A BIMI record only leads to a
// displayed logo if its assets are compliant.
func (v *Validator) ValidateAssets(ctx context.Context, rec *Record) {
	var checks []Check
	allPassed := true

	var logoContent []byte

	if rec.LogoURL == "" {
		checks = append(checks,
			newCheck("logo_fetch", "Logo file retrieval", StatusSkipped,
				"No logo URL published (declination record)"))
	} else {
		content, contentType, problems := v.fetchFile(ctx, rec.LogoURL, MaxLogoSize)
		if len(problems) > 0 {
			checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusFail, problems...))
			allPassed = false
		} else {
			logoContent = content
			if contentType != "image/svg+xml" {
				checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusWarning,
					fmt.Sprintf("Logo served with Content-Type %q, expected \"image/svg+xml\"", contentType)))
			} else {
				checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusPass))
			}
		}

		if logoContent == nil {
			checks = append(checks,
				newCheck("logo_xml", "Logo XML well-formedness", StatusSkipped,
					"Skipped: the logo could not be retrieved"),
				newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusSkipped,
					"Skipped: the logo could not be retrieved"))
		} else {
			xmlCheck := CheckLogoXML(logoContent)
			checks = append(checks, xmlCheck)
			if xmlCheck.Status == StatusFail {
				allPassed = false
			}

			svgCheck := CheckLogoSVGTinyPS(logoContent)
			checks = append(checks, svgCheck)
			if svgCheck.Status == StatusFail {
				allPassed = false
			}
		}
	}

	if rec.VMCURL == "" {
		checks = append(checks,
			newCheck("vmc", "Verified Mark Certificate", StatusSkipped,
				"No VMC published (a= tag absent or empty): VMC is optional but required by some mail providers (e.g. Gmail, Apple Mail)"))
	} else {
		vmcCheck, vmcInfo := v.analyzeVMCURL(ctx, rec.VMCURL, rec.Domain, logoContent)
		checks = append(checks, vmcCheck)
		rec.VMC = vmcInfo
		if vmcCheck.Status == StatusFail {
			allPassed = false
		}
	}

	rec.Checks = checks
	if !allPassed {
		rec.Valid = false
		rec.Error = "BIMI assets failed validation, see detailed checks below"
	}
}

// fetchFile downloads a file referenced by a BIMI record and validates
// transport requirements (HTTPS, reachability, size). It returns the file
// content, the media type announced by the server and the list of problems
// encountered (empty when the fetch is acceptable).
func (v *Validator) fetchFile(ctx context.Context, fileURL string, maxSize int64) (content []byte, contentType string, problems []string) {
	u, err := url.Parse(fileURL)
	if err != nil {
		return nil, "", []string{fmt.Sprintf("Invalid URL: %s", err)}
	}

	if !strings.EqualFold(u.Scheme, "https") {
		problems = append(problems, fmt.Sprintf("URL uses %q scheme: BIMI requires files to be served over HTTPS", u.Scheme))
		return nil, "", problems
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, "", []string{fmt.Sprintf("Invalid URL: %s", err)}
	}

	resp, err := v.httpClient().Do(req)
	if err != nil {
		problems = append(problems, fmt.Sprintf("Unable to retrieve file: %s", err))
		return nil, "", problems
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		problems = append(problems, fmt.Sprintf("Server responded with HTTP status %d instead of 200", resp.StatusCode))
		return nil, "", problems
	}

	content, err = io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		problems = append(problems, fmt.Sprintf("Error while downloading file: %s", err))
		return nil, "", problems
	}

	if int64(len(content)) > maxSize {
		problems = append(problems, fmt.Sprintf("File exceeds the maximum allowed size of %d bytes", maxSize))
		return nil, "", problems
	}

	contentType = resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		contentType = mt
	}

	return content, contentType, nil
}
