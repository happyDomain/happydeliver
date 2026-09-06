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
	"slices"
	"strings"
	"testing"
)

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

	t.Run("Local-part prefixes are reported", func(t *testing.T) {
		check := checkRecordTags(&Record{
			LocalPartSelector: true,
			LocalPartPrefixes: []string{"brand-one", "brand-two"},
		})
		if check.Status != StatusPass {
			t.Fatalf("Status = %s, want %s", check.Status, StatusPass)
		}
		joined := strings.Join(check.MessageTexts(), " ")
		for _, want := range []string{"brand-one", "brand-two"} {
			if !strings.Contains(joined, want) {
				t.Errorf("messages = %q, want them to contain %q", check.MessageTexts(), want)
			}
		}
	})
}
