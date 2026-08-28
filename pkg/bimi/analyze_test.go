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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateAssets(t *testing.T) {
	const logoContent = validTinyPSSVG

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(logoContent))
	})
	mux.HandleFunc("/bad.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}
	ctx := context.Background()

	t.Run("Fetchable logo passes", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if !rec.Valid {
			t.Errorf("expected checks to pass, got checks: %+v", rec.Checks)
		}
	})

	t.Run("Non-compliant logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/bad.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if rec.Valid {
			t.Errorf("expected checks to fail for non-compliant logo")
		}
	})

	t.Run("Declination record skips checks", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if !rec.Valid {
			t.Errorf("declination record should not fail checks")
		}
		for _, check := range rec.Checks {
			if check.Status != StatusSkipped {
				t.Errorf("check %s = %s, want skipped", check.Name, check.Status)
			}
			for _, msg := range check.Messages {
				if msg.Severity != SeverityInfo {
					t.Errorf("check %s message %q severity = %s, want info: a skipped check reports no failure", check.Name, msg.Text, msg.Severity)
				}
			}
		}
	})

	t.Run("Unreachable logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/missing.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if rec.Valid {
			t.Errorf("expected checks to fail for unreachable logo")
		}
	})
}

func TestAnalyze(t *testing.T) {
	const logoContent = validTinyPSSVG

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(logoContent))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()

	t.Run("Valid record runs asset checks", func(t *testing.T) {
		txt := "v=BIMI1; l=" + server.URL + "/logo.svg"
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{txt}}}

		rec, err := v.Analyze(ctx, "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Valid {
			t.Errorf("expected valid record, error: %q, checks: %+v", rec.Error, rec.Checks)
		}
		if len(rec.Checks) == 0 {
			t.Error("expected asset checks to be populated")
		}
	})

	t.Run("Invalid record skips asset checks", func(t *testing.T) {
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{"v=BIMI1;"}}}

		rec, err := v.Analyze(ctx, "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Valid {
			t.Error("expected invalid record for missing l= tag")
		}
		if rec.Checks != nil {
			t.Errorf("expected no asset checks for a syntactically invalid record, got %+v", rec.Checks)
		}
	})

	t.Run("Propagates lookup error", func(t *testing.T) {
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: nil}}
		_, err := v.Analyze(ctx, "example.com", "default")
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})
}
