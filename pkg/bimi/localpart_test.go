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
	"slices"
	"strings"
	"testing"
)

func TestNormalizeLocalPart(t *testing.T) {
	tests := []struct {
		name      string
		localPart string
		want      string
		wantOK    bool
	}{
		{name: "Already a selector", localPart: "newsletter", want: "newsletter", wantOK: true},
		{name: "Subaddress extension is dropped", localPart: "bob+news", want: "bob", wantOK: true},
		{name: "Underscores and periods fold into dashes", localPart: "bob.smith_jr", want: "bob-smith-jr", wantOK: true},
		{name: "Sequential separators collapse", localPart: "bob._-.smith", want: "bob-smith", wantOK: true},
		{name: "Leading and trailing dashes are trimmed", localPart: "--bob--", want: "bob", wantOK: true},
		{name: "Case is folded", localPart: "Brand-One", want: "brand-one", wantOK: true},
		{name: "Characters outside the set are rejected", localPart: "héllo", wantOK: false},
		{name: "Longer than a selector label", localPart: strings.Repeat("a", 64), wantOK: false},
		{name: "Empty after normalization", localPart: "._-", wantOK: false},
		{name: "Empty local-part", localPart: "", wantOK: false},
		{name: "Subaddress only", localPart: "+news", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeLocalPart(tt.localPart)
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t (selector %q)", ok, tt.wantOK, got)
			}
			if got != tt.want {
				t.Errorf("selector = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRecordLocalPartAndAvatarTags(t *testing.T) {
	tests := []struct {
		name         string
		txt          string
		wantValid    bool
		wantLPS      bool
		wantPrefixes []string
		wantAvatar   string
	}{
		{
			name:       "No lps= tag at all",
			txt:        "v=BIMI1; l=https://example.com/logo.svg",
			wantValid:  true,
			wantAvatar: "",
		},
		{
			// An empty value is not the absence of the tag: it means
			// every local-part is sent to its own selector.
			name:      "Empty lps= matches every local-part",
			txt:       "v=BIMI1; l=https://example.com/logo.svg; lps=",
			wantValid: true,
			wantLPS:   true,
		},
		{
			name:         "Prefix list is split and trimmed",
			txt:          "v=BIMI1; l=https://example.com/logo.svg; lps = brand-one , brand-two ",
			wantValid:    true,
			wantLPS:      true,
			wantPrefixes: []string{"brand-one", "brand-two"},
		},
		{
			name:         "An empty entry in a list is a malformed prefix",
			txt:          "v=BIMI1; l=https://example.com/logo.svg; lps=brand-,,other",
			wantValid:    false,
			wantLPS:      true,
			wantPrefixes: []string{"brand-", "", "other"},
		},
		{
			name:         "Prefix longer than a selector label",
			txt:          "v=BIMI1; l=https://example.com/logo.svg; lps=" + strings.Repeat("a", 64),
			wantValid:    false,
			wantLPS:      true,
			wantPrefixes: []string{strings.Repeat("a", 64)},
		},
		{
			name:       "Registered avatar preference",
			txt:        "v=BIMI1; l=https://example.com/logo.svg; avp=personal",
			wantValid:  true,
			wantAvatar: "personal",
		},
		{
			// An unknown preference must be ignored, not rejected:
			// the record itself stays valid.
			name:       "Unknown avatar preference keeps the record valid",
			txt:        "v=BIMI1; l=https://example.com/logo.svg; avp=braand",
			wantValid:  true,
			wantAvatar: "braand",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := ParseRecord("example.com", "default", tt.txt)
			if rec.Valid != tt.wantValid {
				t.Errorf("Valid = %t, want %t (error: %q)", rec.Valid, tt.wantValid, rec.Error)
			}
			if rec.LocalPartSelector != tt.wantLPS {
				t.Errorf("LocalPartSelector = %t, want %t", rec.LocalPartSelector, tt.wantLPS)
			}
			if !slices.Equal(rec.LocalPartPrefixes, tt.wantPrefixes) {
				t.Errorf("LocalPartPrefixes = %q, want %q", rec.LocalPartPrefixes, tt.wantPrefixes)
			}
			if rec.AvatarPreference != tt.wantAvatar {
				t.Errorf("AvatarPreference = %q, want %q", rec.AvatarPreference, tt.wantAvatar)
			}
		})
	}
}

func TestAvatarPreferenceOrDefault(t *testing.T) {
	tests := []struct {
		published string
		want      string
	}{
		{published: "", want: AvatarPreferenceBrand},
		{published: AvatarPreferenceBrand, want: AvatarPreferenceBrand},
		{published: AvatarPreferencePersonal, want: AvatarPreferencePersonal},
		// Neither an unknown value nor a miscapitalized one is the
		// Domain Owner's preference: both are ignored.
		{published: "braand", want: AvatarPreferenceBrand},
		{published: "Personal", want: AvatarPreferenceBrand},
	}

	for _, tt := range tests {
		rec := &Record{AvatarPreference: tt.published}
		if got := rec.AvatarPreferenceOrDefault(); got != tt.want {
			t.Errorf("AvatarPreferenceOrDefault() with avp=%q = %q, want %q", tt.published, got, tt.want)
		}
	}
}

const (
	defaultLogoRecord = "v=BIMI1; l=https://example.com/default.svg"
	bobLogoRecord     = "v=BIMI1; l=https://example.com/bob.svg"
)

func TestLookupForLocalPart(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		byName       map[string][]string
		localPart    string
		wantLogoURL  string
		wantSelector string
		wantQueried  []string
	}{
		{
			name: "Matching prefix redirects to the local-part selector",
			byName: map[string][]string{
				"default._bimi.example.com":    {"v=BIMI1; l=https://example.com/default.svg; lps=brand-"},
				"brand-news._bimi.example.com": {bobLogoRecord},
			},
			localPart:    "brand.news",
			wantLogoURL:  "https://example.com/bob.svg",
			wantSelector: "brand-news",
			wantQueried:  []string{"default._bimi.example.com", "brand-news._bimi.example.com"},
		},
		{
			// Without the tag there is nothing to redirect to, and
			// no second query to pay for.
			name: "No lps= tag leaves the record alone",
			byName: map[string][]string{
				"default._bimi.example.com": {defaultLogoRecord},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com"},
		},
		{
			name: "Local-part outside the prefix list is not redirected",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps=brand-"},
				"bob._bimi.example.com":     {bobLogoRecord},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com"},
		},
		{
			// An empty prefix list sends every local-part to its own
			// selector.
			name: "Empty prefix list matches every local-part",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
				"bob._bimi.example.com":     {bobLogoRecord},
			},
			localPart:    "bob+news",
			wantLogoURL:  "https://example.com/bob.svg",
			wantSelector: "bob",
			wantQueried:  []string{"default._bimi.example.com", "bob._bimi.example.com"},
		},
		{
			name: "Empty derived location falls back to the original record",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com", "bob._bimi.example.com"},
		},
		{
			// Several records at the derived location leave it
			// unusable, but that is no reason to lose the record the
			// requested selector did publish.
			name: "Several records at the derived location fall back",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
				"bob._bimi.example.com":     {bobLogoRecord, "v=BIMI1; l=https://example.com/other.svg"},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com", "bob._bimi.example.com"},
		},
		{
			name: "Malformed record at the derived location falls back",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
				"bob._bimi.example.com":     {"v=BIMI1;"},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com", "bob._bimi.example.com"},
		},
		{
			// A local-part no selector can be derived from is an
			// expected limitation, not a failure.
			name: "Local-part that cannot become a selector",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
			},
			localPart:    "héllo",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com"},
		},
		{
			// The derived selector being the requested one already
			// means the answer is in hand: no second query.
			name: "Derived selector equals the requested one",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
			},
			localPart:    "default",
			wantLogoURL:  "https://example.com/default.svg",
			wantSelector: "default",
			wantQueried:  []string{"default._bimi.example.com"},
		},
		{
			// Discovery runs the local-part step at every location it
			// visits, the organizational domain's included.
			name: "Applied at the organizational domain after a fallback",
			byName: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
				"bob._bimi.example.com":     {bobLogoRecord},
			},
			localPart:    "bob",
			wantLogoURL:  "https://example.com/bob.svg",
			wantSelector: "bob",
			wantQueried: []string{
				"default._bimi.news.example.com",
				"default._bimi.example.com",
				"bob._bimi.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain := "example.com"
			if slices.Contains(tt.wantQueried, "default._bimi.news.example.com") {
				domain = "news.example.com"
			}

			r := &recordingResolver{stubResolver: stubResolver{byName: tt.byName}}
			v := &Validator{Resolver: r}

			rec, err := v.LookupForLocalPart(ctx, domain, "default", tt.localPart)
			if err != nil {
				t.Fatalf("LookupForLocalPart() error = %v", err)
			}
			if rec.LogoURL != tt.wantLogoURL {
				t.Errorf("LogoURL = %q, want %q", rec.LogoURL, tt.wantLogoURL)
			}
			if rec.Selector != tt.wantSelector {
				t.Errorf("Selector = %q, want %q", rec.Selector, tt.wantSelector)
			}
			if rec.RequestedSelector != "default" {
				t.Errorf("RequestedSelector = %q, want %q", rec.RequestedSelector, "default")
			}
			if want := tt.wantSelector != "default"; rec.FromLocalPartSelector() != want {
				t.Errorf("FromLocalPartSelector() = %t, want %t", rec.FromLocalPartSelector(), want)
			}
			if !slices.Equal(r.queried, tt.wantQueried) {
				t.Errorf("queried %q, want %q", r.queried, tt.wantQueried)
			}
		})
	}
}

func TestLookupIgnoresLocalPartSelectorWithoutSender(t *testing.T) {
	// Lookup has no sender to derive a selector from, so an lps= tag cannot
	// apply and must not cost an extra query.
	r := &recordingResolver{stubResolver: stubResolver{byName: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/default.svg; lps="},
		"bob._bimi.example.com":     {bobLogoRecord},
	}}}
	v := &Validator{Resolver: r}

	rec, err := v.Lookup(context.Background(), "example.com", "default")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if rec.LogoURL != "https://example.com/default.svg" {
		t.Errorf("LogoURL = %q, want the record published at the requested selector", rec.LogoURL)
	}
	if rec.FromLocalPartSelector() {
		t.Error("FromLocalPartSelector() = true, want false: no sender was given")
	}
	if want := []string{"default._bimi.example.com"}; !slices.Equal(r.queried, want) {
		t.Errorf("queried %q, want %q", r.queried, want)
	}
}

func TestCheckRecordTags(t *testing.T) {
	t.Run("Unknown avatar preference warns", func(t *testing.T) {
		check := checkRecordTags(&Record{AvatarPreference: "braand"})
		if check.Status != StatusWarning {
			t.Fatalf("Status = %s, want %s", check.Status, StatusWarning)
		}
		if !strings.Contains(strings.Join(check.MessageTexts(), " "), "braand") {
			t.Errorf("messages = %q, want them to name the published value", check.MessageTexts())
		}
	})

	t.Run("Registered preference passes", func(t *testing.T) {
		check := checkRecordTags(&Record{AvatarPreference: AvatarPreferencePersonal})
		if check.Status != StatusPass {
			t.Errorf("Status = %s, want %s", check.Status, StatusPass)
		}
		for _, msg := range check.Messages {
			if msg.Severity != SeverityInfo {
				t.Errorf("message %q severity = %s, want info", msg.Text, msg.Severity)
			}
		}
	})

	t.Run("Local-part selectors are reported", func(t *testing.T) {
		check := checkRecordTags(&Record{
			Selector:          "bob",
			RequestedSelector: "default",
			LocalPartSelector: true,
			LocalPartPrefixes: []string{"brand-one", "brand-two"},
		})
		if check.Status != StatusPass {
			t.Fatalf("Status = %s, want %s", check.Status, StatusPass)
		}
		joined := strings.Join(check.MessageTexts(), " ")
		for _, want := range []string{"brand-one", "brand-two", "derived from the sender's local-part"} {
			if !strings.Contains(joined, want) {
				t.Errorf("messages = %q, want them to contain %q", check.MessageTexts(), want)
			}
		}
	})
}
