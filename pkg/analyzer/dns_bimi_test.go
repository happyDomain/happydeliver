// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
)

// Record parsing and asset validation are covered by the reusable pkg/bimi
// package. These tests exercise the analyzer adapter: DNS lookup wiring and
// the mapping of *bimi.Record onto the API *model.BIMIRecord.

func TestCheckBIMIRecordLookup(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		txt         map[string][]string
		wantValid   bool
		wantLogoURL string
		wantVMCURL  string
		// wantRecordDom, when set, is the domain the record must be
		// reported as coming from.
		wantRecordDom string
		wantErrSubst  string
	}{
		{
			name:   "no BIMI record published",
			domain: "example.com",
			txt:    map[string][]string{},
			// The _bimi location does not exist: that is the absence of a
			// record, not a failure to look one up.
			wantValid:    false,
			wantErrSubst: "No BIMI record found",
		},
		{
			name:   "malformed record (missing version)",
			domain: "example.com",
			txt: map[string][]string{
				"default._bimi.example.com": {"l=https://example.com/logo.svg"},
			},
			wantValid:    false,
			wantLogoURL:  "https://example.com/logo.svg",
			wantErrSubst: "v=BIMI1",
		},
		{
			name:   "declination record is syntactically valid",
			domain: "example.com",
			txt: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=;"},
			},
			// No assets to fetch: all checks skipped, record stays valid.
			wantValid: true,
		},
		{
			name:   "record inherited from the organizational domain",
			domain: "news.example.com",
			txt: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=;"},
			},
			wantValid:     true,
			wantRecordDom: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := newMockAnalyzer(tt.txt, nil)
			rec := analyzer.checkBIMIRecord(tt.domain, "default", "", enforcingDMARC(tt.domain))

			if rec.Valid != tt.wantValid {
				errStr := ""
				if rec.Error != nil {
					errStr = *rec.Error
				}
				t.Errorf("Valid = %t, want %t (error: %q)", rec.Valid, tt.wantValid, errStr)
			}
			if tt.wantLogoURL != "" {
				if rec.LogoUrl == nil || *rec.LogoUrl != tt.wantLogoURL {
					t.Errorf("LogoUrl = %v, want %q", rec.LogoUrl, tt.wantLogoURL)
				}
			}
			if tt.wantVMCURL != "" {
				if rec.VmcUrl == nil || *rec.VmcUrl != tt.wantVMCURL {
					t.Errorf("VmcUrl = %v, want %q", rec.VmcUrl, tt.wantVMCURL)
				}
			}
			if tt.wantRecordDom != "" {
				if rec.RecordDomain == nil || *rec.RecordDomain != tt.wantRecordDom {
					t.Errorf("RecordDomain = %v, want %q", rec.RecordDomain, tt.wantRecordDom)
				}
				if rec.Domain != tt.domain {
					t.Errorf("Domain = %q, want the queried domain %q", rec.Domain, tt.domain)
				}
			}
			if tt.wantErrSubst != "" {
				if rec.Error == nil || !strings.Contains(*rec.Error, tt.wantErrSubst) {
					t.Errorf("Error = %v, want substring %q", rec.Error, tt.wantErrSubst)
				}
			}
		})
	}
}

// TestDNSAnalyzerHTTPClientIsGuarded pins the wiring rather than the guard
// itself (pkg/bimi covers that): the BIMI logo and VMC are downloaded from URLs
// the analysed domain publishes, so the analyzer must fetch them through
// bimi.NewHTTPClient and never through a bare client, which would let a crafted
// record reach a service on the instance's own network.
func TestDNSAnalyzerHTTPClientIsGuarded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	_, err := NewDNSAnalyzer(5*time.Second, nil).bimiHTTPClient.Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "non-public address") {
		t.Errorf("the analyzer's HTTP client reached a loopback address, err = %v", err)
	}
}

func TestLocalPartOf(t *testing.T) {
	tests := []struct {
		address string
		want    string
	}{
		{address: "bob@example.com", want: "bob"},
		{address: "Bob Smith <bob.smith@example.com>", want: "bob.smith"},
		{address: "<bob+news@example.com>", want: "bob+news"},
		{address: `"odd@name"@example.com`, want: "odd@name"},
		// An address a strict parser rejects still plainly holds a
		// local-part, and reporting nothing would silently drop the
		// local-part selector for it.
		{address: "bob@example.com (Bob)", want: "bob"},
		{address: "not-an-address", want: ""},
		{address: "@example.com", want: ""},
		{address: "", want: ""},
	}

	for _, tt := range tests {
		if got := localPartOf(tt.address); got != tt.want {
			t.Errorf("localPartOf(%q) = %q, want %q", tt.address, got, tt.want)
		}
	}
}

func TestCheckBIMIRecordLocalPartSelector(t *testing.T) {
	txt := map[string][]string{
		"default._bimi.example.com":    {"v=BIMI1; l=https://example.com/default.svg; lps=brand-; avp=personal"},
		"brand-news._bimi.example.com": {"v=BIMI1; l=https://example.com/news.svg"},
	}

	t.Run("A matching sender is served the local-part record", func(t *testing.T) {
		rec := newMockAnalyzer(txt, nil).checkBIMIRecord("example.com", "default", "brand.news", enforcingDMARC("example.com"))

		if rec.Selector != "brand-news" {
			t.Errorf("Selector = %q, want %q", rec.Selector, "brand-news")
		}
		if rec.RequestedSelector == nil || *rec.RequestedSelector != "default" {
			t.Errorf("RequestedSelector = %v, want %q", rec.RequestedSelector, "default")
		}
		if rec.LogoUrl == nil || *rec.LogoUrl != "https://example.com/news.svg" {
			t.Errorf("LogoUrl = %v, want the local-part record's logo", rec.LogoUrl)
		}
	})

	t.Run("Without a sender the requested selector answers", func(t *testing.T) {
		rec := newMockAnalyzer(txt, nil).checkBIMIRecord("example.com", "default", "", enforcingDMARC("example.com"))

		if rec.Selector != "default" {
			t.Errorf("Selector = %q, want %q", rec.Selector, "default")
		}
		if rec.LocalPartSelector == nil || !*rec.LocalPartSelector {
			t.Error("LocalPartSelector is not reported, though the record publishes an lps= tag")
		}
		if rec.LocalPartPrefixes == nil || !slices.Equal(*rec.LocalPartPrefixes, []string{"brand-"}) {
			t.Errorf("LocalPartPrefixes = %v, want [brand-]", rec.LocalPartPrefixes)
		}
		if rec.AvatarPreference == nil || *rec.AvatarPreference != "personal" {
			t.Errorf("AvatarPreference = %v, want %q", rec.AvatarPreference, "personal")
		}
	})
}

// enforcingDMARC is the DMARC record the BIMI tests that are not about DMARC
// run under: BIMI section 7.1 refuses to display an Indicator without one, so
// every other case needs a policy that stays out of the way.
func enforcingDMARC(domain string) *model.DMARCRecord {
	return &model.DMARCRecord{
		Valid:  true,
		Domain: utils.PtrTo(domain),
		Policy: utils.PtrTo(model.DMARCRecordPolicyReject),
	}
}

// The precondition has to reach the reported record, not just the pkg/bimi
// check: a syntactically valid record under p=none is one no receiver acts on.
func TestCheckBIMIRecordDMARCEnforcement(t *testing.T) {
	txt := map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=;"},
	}

	t.Run("A policy of none fails the record", func(t *testing.T) {
		dmarc := &model.DMARCRecord{
			Valid:  true,
			Domain: utils.PtrTo("example.com"),
			Policy: utils.PtrTo(model.DMARCRecordPolicyNone),
		}
		rec := newMockAnalyzer(txt, nil).checkBIMIRecord("example.com", "default", "", dmarc)

		if rec.Valid {
			t.Error("Valid = true, want false: p=none forbids BIMI processing altogether")
		}
		if rec.RecordValid == nil || !*rec.RecordValid {
			t.Error("RecordValid = false, want true: the TXT record itself is well-formed")
		}
		check, found := findModelCheck(rec, "dmarc_enforcement")
		if !found || check.Status != model.BIMICheckStatusFail {
			t.Errorf("check dmarc_enforcement = %+v, want a failure", check)
		}
	})

	t.Run("An enforcing policy leaves the record valid", func(t *testing.T) {
		rec := newMockAnalyzer(txt, nil).checkBIMIRecord("example.com", "default", "", enforcingDMARC("example.com"))

		if !rec.Valid {
			t.Errorf("Valid = false, want true (error: %v)", rec.Error)
		}
		check, found := findModelCheck(rec, "dmarc_enforcement")
		if !found || check.Status != model.BIMICheckStatusPass {
			t.Errorf("check dmarc_enforcement = %+v, want a pass", check)
		}
	})
}

func findModelCheck(rec *model.BIMIRecord, name string) (model.BIMICheck, bool) {
	if rec.Checks == nil {
		return model.BIMICheck{}, false
	}
	for _, c := range *rec.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return model.BIMICheck{}, false
}

func TestBimiDMARCPolicy(t *testing.T) {
	t.Run("A record that was not analysed leaves the criterion unevaluated", func(t *testing.T) {
		if got := bimiDMARCPolicy(nil); got != nil {
			t.Errorf("bimiDMARCPolicy(nil) = %+v, want nil", got)
		}
	})

	t.Run("A record that did not validate is not a policy", func(t *testing.T) {
		got := bimiDMARCPolicy(&model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo("No DMARC record found"),
		})
		if got == nil || got.Found {
			t.Errorf("Found = %+v, want a non-nil policy reporting Found = false", got)
		}
	})

	t.Run("Every tag section 7.1 reads is carried over", func(t *testing.T) {
		got := bimiDMARCPolicy(&model.DMARCRecord{
			Valid:           true,
			Domain:          utils.PtrTo("example.com"),
			Policy:          utils.PtrTo(model.DMARCRecordPolicyQuarantine),
			SubdomainPolicy: utils.PtrTo(model.DMARCRecordSubdomainPolicyNone),
			Percentage:      utils.PtrTo(50),
			TestMode:        utils.PtrTo(true),
		})

		if got == nil {
			t.Fatal("bimiDMARCPolicy returned nil for a valid record")
		}
		if !got.Found || got.Domain != "example.com" {
			t.Errorf("Found = %t, Domain = %q, want true and \"example.com\"", got.Found, got.Domain)
		}
		if got.Policy != bimi.DMARCPolicyQuarantine || got.SubdomainPolicy != bimi.DMARCPolicyNone {
			t.Errorf("Policy = %q, SubdomainPolicy = %q, want quarantine and none", got.Policy, got.SubdomainPolicy)
		}
		if got.Percentage == nil || *got.Percentage != 50 {
			t.Errorf("Percentage = %v, want 50", got.Percentage)
		}
		if !got.TestMode {
			t.Error("TestMode = false, want true")
		}
	})
}

// AnalyzeBIMIOnly is what the standalone checker calls: it has no message to
// take a DMARC verdict from, so it has to look the policy up itself and feed it
// to the BIMI validation. A record checked without it would be reported as
// compliant while no receiver would act on it.
func TestAnalyzeBIMIOnly(t *testing.T) {
	txt := map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=;"},
		"brand._bimi.example.com":   {"v=BIMI1; l=;"},
	}

	t.Run("looks the DMARC policy up and applies it", func(t *testing.T) {
		withDMARC := map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}
		for k, v := range txt {
			withDMARC[k] = v
		}

		rec, dmarc := newMockAnalyzer(withDMARC, nil).AnalyzeBIMIOnly("example.com", "", "")

		if dmarc == nil || !dmarc.Valid {
			t.Fatalf("DMARC record = %+v, want a valid one", dmarc)
		}
		if rec.Selector != "default" {
			t.Errorf("Selector = %q, want %q: an empty selector means the default one", rec.Selector, "default")
		}
		if !rec.Valid {
			t.Errorf("Valid = false, want true (error: %v)", rec.Error)
		}
		check, found := findModelCheck(rec, "dmarc_enforcement")
		if !found || check.Status != model.BIMICheckStatusPass {
			t.Errorf("check dmarc_enforcement = %+v, want a pass", check)
		}
	})

	t.Run("a domain without DMARC cannot display an Indicator", func(t *testing.T) {
		rec, dmarc := newMockAnalyzer(txt, nil).AnalyzeBIMIOnly("example.com", "brand", "")

		if dmarc == nil || dmarc.Valid {
			t.Fatalf("DMARC record = %+v, want an invalid one", dmarc)
		}
		if rec.Selector != "brand" {
			t.Errorf("Selector = %q, want %q", rec.Selector, "brand")
		}
		if rec.Valid {
			t.Error("Valid = true, want false: no DMARC policy forbids BIMI processing")
		}
		check, found := findModelCheck(rec, "dmarc_enforcement")
		if !found || check.Status != model.BIMICheckStatusFail {
			t.Errorf("check dmarc_enforcement = %+v, want a failure", check)
		}
	})
}
