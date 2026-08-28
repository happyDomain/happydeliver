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
	"strings"
	"testing"
)

func TestDescribeMisplacedRecord(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		ownFamily string
		want      string
	}{
		{"DMARC misplaced at BIMI", "DMARC1", "BIMI", "a DMARC record"},
		{"SPF misplaced at BIMI", "spf1", "BIMI", "an SPF record"},
		{"DKIM misplaced at BIMI", "DKIM1", "BIMI", "a DKIM record"},
		{"BIMI at BIMI location is own family", "BIMI1", "BIMI", ""},
		{"BIMI misplaced elsewhere", "BIMI1", "DKIM", "a BIMI record"},
		{"Unknown version", "STSv1", "BIMI", ""},
		{"Empty version", "", "BIMI", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeMisplacedRecord(tt.version, tt.ownFamily); got != tt.want {
				t.Errorf("describeMisplacedRecord(%q, %q) = %q, want %q", tt.version, tt.ownFamily, got, tt.want)
			}
		})
	}
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		name        string
		txt         string
		wantValid   bool
		wantLogoURL string
		wantVMCURL  string
	}{
		{
			name:        "Valid record with logo and VMC",
			txt:         "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			wantValid:   true,
			wantLogoURL: "https://example.com/logo.svg",
			wantVMCURL:  "https://example.com/vmc.pem",
		},
		{
			name:        "Declination record (empty l=)",
			txt:         "v=BIMI1; l=;",
			wantValid:   true,
			wantLogoURL: "",
		},
		{
			name:        "Missing version",
			txt:         "l=https://example.com/logo.svg",
			wantValid:   false,
			wantLogoURL: "https://example.com/logo.svg",
		},
		{
			name:      "Missing l= tag",
			txt:       "v=BIMI1;",
			wantValid: false,
		},
		{
			// The tag-value syntax allows folding whitespace around
			// the tag name, the '=' and the value.
			name:        "Whitespace around the separators",
			txt:         " v = BIMI1 ; l = https://example.com/logo.svg ; a = https://example.com/vmc.pem ",
			wantValid:   true,
			wantLogoURL: "https://example.com/logo.svg",
			wantVMCURL:  "https://example.com/vmc.pem",
		},
		{
			// The version value must match precisely: "BIMI12" is
			// not a version this implementation speaks.
			name:        "Version value is not exactly BIMI1",
			txt:         "v=BIMI12; l=https://example.com/logo.svg",
			wantValid:   false,
			wantLogoURL: "https://example.com/logo.svg",
		},
		{
			name:        "Version tag is not the first one",
			txt:         "l=https://example.com/logo.svg; v=BIMI1",
			wantValid:   false,
			wantLogoURL: "https://example.com/logo.svg",
		},
		{
			// Unknown tags are ignored, and a value containing an
			// '=' is not mistaken for a tag of its own.
			name:        "Unknown tags are ignored",
			txt:         "v=BIMI1; l=https://example.com/logo.svg?html=1; avp=brand; lps=brand-",
			wantValid:   true,
			wantLogoURL: "https://example.com/logo.svg?html=1",
		},
		{
			name:        "Duplicate l= tag",
			txt:         "v=BIMI1; l=https://example.com/a.svg; l=https://example.com/b.svg",
			wantValid:   false,
			wantLogoURL: "https://example.com/a.svg",
		},
		{
			name:        "Tag without a value separator",
			txt:         "v=BIMI1; l=https://example.com/logo.svg; oops",
			wantValid:   false,
			wantLogoURL: "https://example.com/logo.svg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := ParseRecord("example.com", "default", tt.txt)
			if rec.Valid != tt.wantValid {
				t.Errorf("Valid = %t, want %t (error: %q)", rec.Valid, tt.wantValid, rec.Error)
			}
			if rec.LogoURL != tt.wantLogoURL {
				t.Errorf("LogoURL = %q, want %q", rec.LogoURL, tt.wantLogoURL)
			}
			if rec.VMCURL != tt.wantVMCURL {
				t.Errorf("VMCURL = %q, want %q", rec.VMCURL, tt.wantVMCURL)
			}
		})
	}
}

func TestParseRecordDuplicateTagError(t *testing.T) {
	rec := ParseRecord("example.com", "default",
		"v=BIMI1; l=https://example.com/a.svg; l=https://example.com/b.svg; a=https://example.com/a.pem; a=https://example.com/b.pem")
	if rec.Valid {
		t.Fatal("Valid = true, want false")
	}
	for _, want := range []string{"l=", "a=", "more than once"} {
		if !strings.Contains(rec.Error, want) {
			t.Errorf("Error = %q, want it to contain %q", rec.Error, want)
		}
	}
}

func TestParseRecordForeignRecordHint(t *testing.T) {
	// A DMARC record mistakenly published at the BIMI location must be
	// reported as "no BIMI record found" with a hint, not as a malformed
	// BIMI record.
	rec := ParseRecord("example.com", "default", "v=DMARC1;p=quarantine;rua=mailto:dmarc@example.com")
	if rec.Valid {
		t.Fatalf("Valid = true, want false")
	}
	if rec.VMCURL != "" {
		t.Errorf("VMCURL = %q, want empty (must not match DMARC's rua= as a= tag)", rec.VMCURL)
	}
	if !strings.Contains(rec.Error, "No BIMI record found") || !strings.Contains(rec.Error, "a DMARC record") {
		t.Errorf("Error = %q, want to mention the misplaced DMARC record", rec.Error)
	}
}
