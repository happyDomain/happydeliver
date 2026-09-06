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
	"strings"
	"testing"
	"time"
)

func TestValidateAssets(t *testing.T) {
	logoPEM, _ := generateTestVMCChain(t, testVMCOptions{
		Domain: "example.com", Logo: []byte(validTinyPSSVG), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(validTinyPSSVG))
	})
	mux.HandleFunc("/bad.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	})
	// An SVGZ is the gzip stream itself, served under the media type RFC 6170
	// section 5.2 mandates for SVG and SVGZ alike. Content-Encoding is
	// deliberately left unset: the transport would then inflate it on its own,
	// which is the case that already worked.
	svgz := gzipBytes(t, []byte(validTinyPSSVG))
	mux.HandleFunc("/logo.svgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(svgz)
	})
	mux.HandleFunc("/truncated.svgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(svgz[:len(svgz)-5])
	})
	mux.HandleFunc("/vmc.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(logoPEM)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}
	ctx := context.Background()

	t.Run("All checks pass", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svg",
			VMCURL:   server.URL + "/vmc.pem",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if !rec.Valid {
			t.Errorf("expected all checks to pass, got checks: %+v", rec.Checks)
		}
		if rec.VMC == nil || !rec.VMC.Valid {
			t.Errorf("expected valid VMC info, got %+v", rec.VMC)
		}
	})

	// Section 7.1 is a precondition, not an asset: a domain whose policy
	// forbids BIMI processing displays no Indicator however good its logo and
	// its certificate are, and the verdict has to say so.
	t.Run("Policy of none fails the record despite compliant assets", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svg",
			VMCURL:   server.URL + "/vmc.pem",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, &DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyNone})

		if rec.Valid {
			t.Errorf("p=none must fail the record, got checks: %+v", rec.Checks)
		}
		if !strings.Contains(rec.Error, "DMARC at enforcement") {
			t.Errorf("Error = %q, want it to name the failing check", rec.Error)
		}
		for _, name := range []string{"logo_fetch", "logo_xml", "logo_svg_tiny_ps", "vmc"} {
			if check, found := findCheck(rec.Checks, name); !found || check.Status != StatusPass {
				t.Errorf("check %s = %+v, want it to still pass: the assets are compliant, the policy is not", name, check)
			}
		}
	})

	// A caller that does not resolve DMARC gets no verdict on it, rather than
	// a silent pass on a criterion nobody checked.
	t.Run("Nil policy leaves the DMARC check skipped", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svg",
			VMCURL:   server.URL + "/vmc.pem",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, nil)

		if !rec.Valid {
			t.Errorf("an unevaluated DMARC policy must not fail the record, got checks: %+v", rec.Checks)
		}
		check, found := findCheck(rec.Checks, "dmarc_enforcement")
		if !found || check.Status != StatusSkipped {
			t.Errorf("check dmarc_enforcement = %+v, want skipped", check)
		}
	})

	t.Run("SVGZ logo is decompressed before every check", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svgz",
			VMCURL:   server.URL + "/vmc.pem",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if !rec.Valid {
			t.Errorf("BIMI accepts SVG and SVGZ alike for the l= tag, got checks: %+v", rec.Checks)
		}

		logoFetch, found := findCheck(rec.Checks, "logo_fetch")
		if !found || logoFetch.Status != StatusPass {
			t.Errorf("logo_fetch = %+v, want a passing check: an SVGZ is not a defect", logoFetch)
		}
		if len(logoFetch.Messages) != 1 || logoFetch.Messages[0].Severity != SeverityInfo ||
			!strings.Contains(logoFetch.Messages[0].Text, "SVGZ") {
			t.Errorf("logo_fetch messages = %+v, want a single informational message naming SVGZ", logoFetch.Messages)
		}

		// Both checks read XML: they can only pass on the inflated document.
		for _, name := range []string{"logo_xml", "logo_svg_tiny_ps"} {
			check, found := findCheck(rec.Checks, name)
			if !found || check.Status != StatusPass {
				t.Errorf("%s = %+v, want a passing check on the inflated document", name, check)
			}
		}

		// The certificate carries the same logo, gzipped inside its logotype
		// extension. Comparing the published file without inflating it would
		// oppose gzip bytes to an SVG document, and never match.
		if rec.VMC == nil || rec.VMC.LogoMatches == nil || !*rec.VMC.LogoMatches {
			t.Errorf("VMC.LogoMatches = %v, want true: both sides carry the same document", rec.VMC)
		}
	})

	t.Run("Corrupt SVGZ fails the fetch and skips the logo checks", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/truncated.svgz",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if rec.Valid {
			t.Error("a logo that cannot be decoded is no logo at all")
		}

		logoFetch, found := findCheck(rec.Checks, "logo_fetch")
		if !found || logoFetch.Status != StatusFail {
			t.Errorf("logo_fetch = %+v, want a failing check", logoFetch)
		}

		// Reporting the still-compressed bytes as malformed XML would send the
		// Domain Owner looking for a syntax error that is not there.
		for _, name := range []string{"logo_xml", "logo_svg_tiny_ps"} {
			check, found := findCheck(rec.Checks, name)
			if !found || check.Status != StatusSkipped {
				t.Errorf("%s = %+v, want a skipped check", name, check)
			}
		}
	})

	t.Run("Non-compliant logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/bad.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
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
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if !rec.Valid {
			t.Errorf("declination record should not fail checks")
		}
		for _, check := range rec.Checks {
			// record_tags reports on the record itself and
			// dmarc_enforcement on the policy that governs it: neither
			// judges an asset. A declination has nothing to download,
			// but both of them still have something to say.
			if check.Name == "record_tags" || check.Name == "dmarc_enforcement" {
				continue
			}
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

	t.Run("Empty l= with a VMC published fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			VMCURL:   server.URL + "/vmc.pem",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if rec.Valid {
			t.Errorf("an empty l= is a declination only when a= is empty too: with a VMC published, no Indicator can be displayed")
		}
		logoFetch, found := findCheck(rec.Checks, "logo_fetch")
		if !found || logoFetch.Status != StatusFail {
			t.Errorf("logo_fetch = %+v, want a failing check", logoFetch)
		}
	})

	t.Run("Unreachable logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/missing.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec, enforcedDMARC(rec.Domain))
		if rec.Valid {
			t.Errorf("expected checks to fail for unreachable logo")
		}
	})
}

func TestAnalyze(t *testing.T) {
	logoPEM, _ := generateTestVMCChain(t, testVMCOptions{
		Domain: "example.com", Logo: []byte(validTinyPSSVG), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(validTinyPSSVG))
	})
	mux.HandleFunc("/vmc.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(logoPEM)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()

	t.Run("Valid record runs asset checks", func(t *testing.T) {
		txt := "v=BIMI1; l=" + server.URL + "/logo.svg; a=" + server.URL + "/vmc.pem"
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{txt}}}

		rec, err := v.Analyze(ctx, "example.com", "default", enforcedDMARC("example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Valid {
			t.Errorf("expected valid record, error: %q, checks: %+v", rec.Error, rec.Checks)
		}
		if len(rec.Checks) == 0 {
			t.Error("expected asset checks to be populated")
		}
		if rec.VMC == nil || !rec.VMC.Valid {
			t.Errorf("expected a valid VMC, got %+v", rec.VMC)
		}
	})

	t.Run("Invalid record skips asset checks", func(t *testing.T) {
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{"v=BIMI1;"}}}

		rec, err := v.Analyze(ctx, "example.com", "default", enforcedDMARC("example.com"))
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
		_, err := v.Analyze(ctx, "example.com", "default", enforcedDMARC("example.com"))
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})
}
