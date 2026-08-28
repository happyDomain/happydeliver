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
// records and the assets they reference.
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
// The returned Record fully describes validity (Valid, Error, Checks).
//
// Conformance of the logo to the SVG Tiny Portable/Secure profile is decided by
// the [git.happydns.org/happyDeliver/pkg/bimi/svgps] sub-package, which is
// driven by the profile schema itself and can also be used on its own.
package bimi

import (
	"context"
	"errors"
	"net"
	"net/http"
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

// MessageSeverity distinguishes a hard failure reason from an accompanying
// warning within a single Check's Messages. A "fail" Check can carry both:
// only the error messages are the reason the check failed. A Check that did
// not fail carries informational messages, which state why it was skipped or
// what it observed without asserting anything went wrong.
type MessageSeverity string

const (
	SeverityError   MessageSeverity = "error"
	SeverityWarning MessageSeverity = "warning"
	SeverityInfo    MessageSeverity = "info"
)

// CheckMessage is one explanation attached to a Check, tagged with its own
// severity so a UI can distinguish a hard failure reason from a mere warning
// even within a "fail" status check.
type CheckMessage struct {
	// Text is the human-readable explanation.
	Text string
	// Severity is this message's own severity.
	Severity MessageSeverity
}

// Check is one evidence check performed on a BIMI record's assets.
type Check struct {
	// Name is a machine-readable identifier (e.g. "logo_fetch").
	Name string
	// Description is a human-readable title.
	Description string
	// Status is the check outcome.
	Status CheckStatus
	// Messages explains a failure or warning; empty when the check passed.
	Messages []CheckMessage
}

// MessageTexts returns the text of every message, discarding severity.
func (c Check) MessageTexts() []string {
	texts := make([]string, len(c.Messages))
	for i, m := range c.Messages {
		texts[i] = m.Text
	}
	return texts
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
}

// Resolver looks up DNS TXT records. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validator gathers the dependencies needed to fetch and validate BIMI
// assets. The zero value is not usable: Resolver is required for Lookup and
// Analyze. HTTPClient defaults to http.DefaultClient and Now to time.Now.
type Validator struct {
	// HTTPClient fetches the logo and VMC files. It carries the protections
	// against the URLs being attacker-controlled, so a caller setting it must
	// build it with NewHTTPClient (or install the same guards): anything else,
	// http.DefaultClient included, will happily connect to a loopback address
	// and follow a redirect off HTTPS. Defaults to http.DefaultClient, which
	// only suits a caller feeding the validator URLs it trusts, such as a test
	// pointing at its own server.
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
		HTTPClient: NewHTTPClient(0),
		Resolver:   &net.Resolver{},
	}
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// newCheck builds a Check value. The messages inherit the severity implied by
// the check's own status: only a check that actually failed carries errors, so
// a "skipped" or "pass" check explains itself informationally rather than
// asserting a failure that did not happen.
func newCheck(name, description string, status CheckStatus, messages ...string) Check {
	var severity MessageSeverity
	switch status {
	case StatusFail:
		severity = SeverityError
	case StatusWarning:
		severity = SeverityWarning
	default:
		severity = SeverityInfo
	}
	c := Check{Name: name, Description: description, Status: status}
	for _, m := range messages {
		c.Messages = append(c.Messages, CheckMessage{Text: m, Severity: severity})
	}
	return c
}

// newCheckWithSeverities builds a Check whose Messages mix hard failure
// reasons (errors) and accompanying warnings under a single status.
func newCheckWithSeverities(name, description string, status CheckStatus, errors, warnings []string) Check {
	c := Check{Name: name, Description: description, Status: status}
	for _, m := range errors {
		c.Messages = append(c.Messages, CheckMessage{Text: m, Severity: SeverityError})
	}
	for _, m := range warnings {
		c.Messages = append(c.Messages, CheckMessage{Text: m, Severity: SeverityWarning})
	}
	return c
}
