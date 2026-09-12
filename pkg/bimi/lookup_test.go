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
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
)

func TestLookupNilResolver(t *testing.T) {
	v := &Validator{}
	_, err := v.Lookup(context.Background(), "example.com", "default")
	if err == nil || !strings.Contains(err.Error(), "Resolver is nil") {
		t.Errorf("err = %v, want a nil-resolver error", err)
	}
}

func TestLookup(t *testing.T) {
	t.Run("No record", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: nil}}
		_, err := v.Lookup(context.Background(), "example.com", "default")
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})

	t.Run("Resolver failure", func(t *testing.T) {
		boom := errors.New("boom")
		v := &Validator{Resolver: stubResolver{err: boom}}
		_, err := v.Lookup(context.Background(), "example.com", "default")
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})

	t.Run("Picks the BIMI record among unrelated TXT records", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: []string{
			"google-site-verification=abcdef",
			"v=BIMI1; l=https://example.com/logo.svg",
		}}}
		rec, err := v.Lookup(context.Background(), "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Valid {
			t.Errorf("Valid = false, want true (error: %q)", rec.Error)
		}
		if rec.LogoURL != "https://example.com/logo.svg" {
			t.Errorf("LogoURL = %q", rec.LogoURL)
		}
	})

	t.Run("Does not join distinct TXT records", func(t *testing.T) {
		// Each element is a whole record; joining them would build a
		// record neither of them is.
		v := &Validator{Resolver: stubResolver{txt: []string{
			"v=BIMI1; l=",
			"https://example.com/logo.svg",
		}}}
		rec, err := v.Lookup(context.Background(), "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.LogoURL != "" {
			t.Errorf("LogoURL = %q, want empty: the second TXT record is not part of the BIMI one", rec.LogoURL)
		}
	})

	t.Run("Several BIMI records is an error", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: []string{
			"v=BIMI1; l=https://example.com/a.svg",
			"v=BIMI1; l=https://example.com/b.svg",
		}}}
		rec, err := v.Lookup(context.Background(), "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Valid {
			t.Error("Valid = true, want false")
		}
		if !strings.Contains(rec.Error, "2 BIMI records") {
			t.Errorf("Error = %q, want to report the duplicate records", rec.Error)
		}
		if rec.LogoURL != "" {
			t.Errorf("LogoURL = %q, want empty: no record can be used", rec.LogoURL)
		}
		for _, want := range []string{"https://example.com/a.svg", "https://example.com/b.svg"} {
			if !strings.Contains(rec.Record, want) {
				t.Errorf("Record = %q, want it to show %q", rec.Record, want)
			}
		}
	})

	t.Run("Reports a misplaced record over an unrelated one", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: []string{
			"google-site-verification=abcdef",
			"v=DMARC1; p=reject",
		}}}
		rec, err := v.Lookup(context.Background(), "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rec.Error, "a DMARC record") {
			t.Errorf("Error = %q, want to mention the misplaced DMARC record", rec.Error)
		}
	})
}

// recordingResolver notes every name queried, to check that discovery visits
// the locations the specification asks for and no other.
type recordingResolver struct {
	stubResolver
	queried []string
}

func (r *recordingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.queried = append(r.queried, normalizeDomain(name))
	return r.stubResolver.LookupTXT(ctx, name)
}

// TestLookupQueriesAbsoluteNames pins the form the queries go out in. A
// relative name is completed with the search list of the host's resolv.conf
// when the location does not exist, and a wildcard published under one of
// those suffixes then answers in its place: the domain under analysis gets
// credited with a record it never published, usually not even a BIMI one, and
// is told it misconfigured its BIMI location.
func TestLookupQueriesAbsoluteNames(t *testing.T) {
	r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}}
	// Record the names as they reach the resolver, trailing dot included.
	raw := &rawRecordingResolver{inner: r}
	v := &Validator{Resolver: raw}

	if _, err := v.Lookup(context.Background(), "news.example.com", "default"); err != nil {
		t.Fatal(err)
	}

	want := []string{"default._bimi.news.example.com.", "default._bimi.example.com."}
	if !slices.Equal(raw.queried, want) {
		t.Errorf("queried %q, want %q", raw.queried, want)
	}
}

// rawRecordingResolver notes the names exactly as they are handed to the
// resolver, where recordingResolver normalizes them to the location queried.
type rawRecordingResolver struct {
	inner   Resolver
	queried []string
}

func (r *rawRecordingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.queried = append(r.queried, name)
	return r.inner.LookupTXT(ctx, name)
}

// TestLookupOrganizationalDomainFallback covers Assertion Record discovery:
// a domain publishing no record of its own inherits the one its organizational
// domain publishes for the same selector, but a domain that did answer keeps
// its own answer, however unusable.
func TestLookupOrganizationalDomainFallback(t *testing.T) {
	const (
		subLocation = "default._bimi.news.example.com"
		orgLocation = "default._bimi.example.com"
	)

	t.Run("Inherits the organizational domain record", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
			orgLocation: {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}
		v := &Validator{Resolver: r}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Valid {
			t.Errorf("Valid = false, want true (error: %q)", rec.Error)
		}
		if rec.LogoURL != "https://example.com/logo.svg" {
			t.Errorf("LogoURL = %q", rec.LogoURL)
		}
		if rec.Domain != "news.example.com" {
			t.Errorf("Domain = %q, want the queried domain", rec.Domain)
		}
		if rec.RecordDomain != "example.com" {
			t.Errorf("RecordDomain = %q, want the organizational domain", rec.RecordDomain)
		}
		if !rec.Inherited() {
			t.Error("Inherited() = false, want true")
		}
		if want := []string{subLocation, orgLocation}; !slices.Equal(r.queried, want) {
			t.Errorf("queried %v, want %v", r.queried, want)
		}
	})

	t.Run("The selector is kept for the fallback query", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
			"summer._bimi.example.com": {"v=BIMI1; l=https://example.com/summer.svg"},
			orgLocation:                {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}
		v := &Validator{Resolver: r}

		rec, err := v.Lookup(context.Background(), "news.example.com", "summer")
		if err != nil {
			t.Fatal(err)
		}
		if rec.LogoURL != "https://example.com/summer.svg" {
			t.Errorf("LogoURL = %q, want the summer selector record: the fallback must not switch to default", rec.LogoURL)
		}
	})

	t.Run("A domain with its own record does not fall back", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
			subLocation: {"v=BIMI1; l=https://news.example.com/logo.svg"},
			orgLocation: {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}
		v := &Validator{Resolver: r}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.LogoURL != "https://news.example.com/logo.svg" {
			t.Errorf("LogoURL = %q, want the domain's own record", rec.LogoURL)
		}
		if rec.Inherited() {
			t.Errorf("Inherited() = true, want false (RecordDomain = %q)", rec.RecordDomain)
		}
		if want := []string{subLocation}; !slices.Equal(r.queried, want) {
			t.Errorf("queried %v, want %v: the organizational domain must not be queried", r.queried, want)
		}
	})

	t.Run("A malformed record is the domain's own answer", func(t *testing.T) {
		// The l= tag is missing: the record is unusable, but it exists, so
		// the parent's Indicator must not be substituted for it.
		v := &Validator{Resolver: stubResolver{byName: map[string][]string{
			subLocation: {"v=BIMI1;"},
			orgLocation: {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Valid {
			t.Error("Valid = true, want false")
		}
		if rec.LogoURL != "" {
			t.Errorf("LogoURL = %q, want empty: the organizational domain record must not be used", rec.LogoURL)
		}
		if rec.Inherited() {
			t.Error("Inherited() = true, want false")
		}
	})

	t.Run("Several records is the domain's own answer", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{byName: map[string][]string{
			subLocation: {
				"v=BIMI1; l=https://news.example.com/a.svg",
				"v=BIMI1; l=https://news.example.com/b.svg",
			},
			orgLocation: {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rec.Error, "2 BIMI records") || !strings.Contains(rec.Error, subLocation) {
			t.Errorf("Error = %q, want to report the duplicate records at %s", rec.Error, subLocation)
		}
		if rec.LogoURL != "" {
			t.Errorf("LogoURL = %q, want empty: no record can be used", rec.LogoURL)
		}
	})

	t.Run("An unrelated TXT record leaves the location empty of BIMI records", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{byName: map[string][]string{
			subLocation: {"google-site-verification=abcdef"},
			orgLocation: {"v=BIMI1; l=https://example.com/logo.svg"},
		}}}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Inherited() || rec.LogoURL != "https://example.com/logo.svg" {
			t.Errorf("RecordDomain = %q, LogoURL = %q, want the organizational domain record", rec.RecordDomain, rec.LogoURL)
		}
	})

	t.Run("Reports the queried domain's misconfiguration over the parent's", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{byName: map[string][]string{
			subLocation: {"v=DMARC1; p=reject"},
			orgLocation: {"v=spf1 -all"},
		}}}

		rec, err := v.Lookup(context.Background(), "news.example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rec.Error, "a DMARC record") {
			t.Errorf("Error = %q, want the queried domain's own misplaced record", rec.Error)
		}
		if rec.RecordDomain != "news.example.com" {
			t.Errorf("RecordDomain = %q, want the queried domain", rec.RecordDomain)
		}
	})

	t.Run("Nothing anywhere is ErrNoRecord", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{byName: map[string][]string{}}}
		_, err := v.Lookup(context.Background(), "news.example.com", "default")
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})

	t.Run("A resolution failure does not fall back", func(t *testing.T) {
		// Inheriting the parent's Indicator because a query happened to
		// fail would attribute it to a domain that never asked for it.
		boom := errors.New("SERVFAIL")
		r := &recordingResolver{stubResolver: stubResolver{err: boom}}
		v := &Validator{Resolver: r}

		if _, err := v.Lookup(context.Background(), "news.example.com", "default"); !errors.Is(err, boom) {
			t.Errorf("err = %v, want the resolver error", err)
		}
		if len(r.queried) != 1 {
			t.Errorf("queried %v, want the organizational domain left alone", r.queried)
		}
	})

	t.Run("An organizational domain queries itself only once", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{}}}
		v := &Validator{Resolver: r}

		if _, err := v.Lookup(context.Background(), "example.com", "default"); !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
		if want := []string{orgLocation}; !slices.Equal(r.queried, want) {
			t.Errorf("queried %v, want %v", r.queried, want)
		}
	})

	t.Run("A domain with no organizational domain does not fall back", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{}}}
		v := &Validator{Resolver: r}

		if _, err := v.Lookup(context.Background(), "co.uk", "default"); !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
		if want := []string{"default._bimi.co.uk"}; !slices.Equal(r.queried, want) {
			t.Errorf("queried %v, want %v", r.queried, want)
		}
	})

	t.Run("The OrganizationalDomain hook is honoured", func(t *testing.T) {
		r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
			"default._bimi.internal.test": {"v=BIMI1; l=https://internal.test/logo.svg"},
		}}}
		v := &Validator{
			Resolver:             r,
			OrganizationalDomain: func(string) string { return "internal.test" },
		}

		rec, err := v.Lookup(context.Background(), "mail.internal.test", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.RecordDomain != "internal.test" {
			t.Errorf("RecordDomain = %q, want the hook's answer", rec.RecordDomain)
		}
	})
}

// TestLookupMissingNameIsNoRecord checks that a name that does not exist is
// reported as the absence of a record rather than as a lookup failure.
func TestLookupMissingNameIsNoRecord(t *testing.T) {
	v := &Validator{Resolver: stubResolver{
		err: &net.DNSError{Err: "no such host", Name: "default._bimi.example.com", IsNotFound: true},
	}}

	if _, err := v.Lookup(context.Background(), "example.com", "default"); !errors.Is(err, ErrNoRecord) {
		t.Errorf("err = %v, want ErrNoRecord", err)
	}
}
