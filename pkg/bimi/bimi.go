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
// records.
//
// The package is self-contained and has no dependency on the rest of
// happyDeliver, so it can be reused as a standalone BIMI validation library.
//
// A minimal use looks like:
//
//	v := bimi.NewValidator()
//	rec, err := v.Lookup(ctx, "example.com", "default")
//
// The returned Record describes whether the record is syntactically valid
// (Valid, Error). Evidence checks on the assets it references (the logo and
// the Verified Mark Certificate) are added by later validators built on top
// of this package.
package bimi

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrNoRecord is returned by Lookup when the domain publishes no BIMI record
// for the requested selector.
var ErrNoRecord = errors.New("no BIMI record found")

// Record is a parsed BIMI record.
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
	// Valid reports whether the record is syntactically compliant.
	Valid bool
	// Error, when set, explains why the record is invalid.
	Error string
}

// Resolver looks up DNS TXT records. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validator gathers the dependencies needed to look up and validate BIMI
// records. The zero value is not usable: Resolver is required for Lookup.
type Validator struct {
	// Resolver performs the DNS TXT lookup.
	Resolver Resolver
	// Now returns the reference time for time-sensitive checks. Defaults to
	// time.Now.
	Now func() time.Time
}

// NewValidator returns a Validator ready to use, backed by the system DNS
// resolver. Callers that need a custom resolver or reference time can set
// the corresponding fields on the returned Validator, or build the struct
// literal directly.
func NewValidator() *Validator {
	return &Validator{
		Resolver: &net.Resolver{},
	}
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
