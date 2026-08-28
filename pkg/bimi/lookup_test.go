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
