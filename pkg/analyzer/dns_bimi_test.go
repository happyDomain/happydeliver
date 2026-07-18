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
	"strings"
	"testing"
	"time"
)

func TestExtractBIMITag(t *testing.T) {
	tests := []struct {
		name          string
		record        string
		tag           string
		expectedValue string
	}{
		{
			name:          "Extract logo URL (l tag)",
			record:        "v=BIMI1; l=https://example.com/logo.svg",
			tag:           "l",
			expectedValue: "https://example.com/logo.svg",
		},
		{
			name:          "Extract VMC URL (a tag)",
			record:        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			tag:           "a",
			expectedValue: "https://example.com/vmc.pem",
		},
		{
			name:          "Tag not found",
			record:        "v=BIMI1; l=https://example.com/logo.svg",
			tag:           "a",
			expectedValue: "",
		},
		{
			name:          "Tag with spaces",
			record:        "v=BIMI1; l= https://example.com/logo.svg ",
			tag:           "l",
			expectedValue: "https://example.com/logo.svg",
		},
		{
			name:          "Empty record",
			record:        "",
			tag:           "l",
			expectedValue: "",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractBIMITag(tt.record, tt.tag)
			if result != tt.expectedValue {
				t.Errorf("extractBIMITag(%q, %q) = %q, want %q", tt.record, tt.tag, result, tt.expectedValue)
			}
		})
	}
}

func TestValidateBIMI(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{
			name:     "Valid BIMI with logo URL",
			record:   "v=BIMI1; l=https://example.com/logo.svg",
			expected: true,
		},
		{
			name:     "Valid BIMI with logo and VMC",
			record:   "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			expected: true,
		},
		{
			name:     "Invalid BIMI - no version",
			record:   "l=https://example.com/logo.svg",
			expected: false,
		},
		{
			name:     "Invalid BIMI - wrong version",
			record:   "v=BIMI2; l=https://example.com/logo.svg",
			expected: false,
		},
		{
			name:     "Invalid BIMI - no logo URL",
			record:   "v=BIMI1",
			expected: false,
		},
		{
			name:     "Invalid BIMI - empty",
			record:   "",
			expected: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.validateBIMI(tt.record)
			if result != tt.expected {
				t.Errorf("validateBIMI(%q) = %v, want %v", tt.record, result, tt.expected)
			}
		})
	}
}

func TestExtractBIMITagDoesNotMatchSubstring(t *testing.T) {
	// A DMARC record mistakenly published at the BIMI location must not yield a
	// VMC URL: the "a" tag must not match the "a=" inside DMARC's "rua=".
	analyzer := NewDNSAnalyzer(5 * time.Second)
	record := "v=DMARC1;p=quarantine;rua=mailto:dmarc_rua@example.com;ruf=mailto:dmarc_ruf@example.com"

	if got := analyzer.extractBIMITag(record, "a"); got != "" {
		t.Errorf("extractBIMITag(%q, \"a\") = %q, want \"\"", record, got)
	}
	if got := analyzer.extractBIMITag(record, "l"); got != "" {
		t.Errorf("extractBIMITag(%q, \"l\") = %q, want \"\"", record, got)
	}
}

func TestIsBIMIRecord(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{"BIMI record", "v=BIMI1; l=https://example.com/logo.svg", true},
		{"BIMI record lowercase version", "v=bimi1; l=https://example.com/logo.svg", true},
		{"DMARC record at BIMI location", "v=DMARC1;p=quarantine;rua=mailto:dmarc@example.com", false},
		{"SPF record", "v=spf1 ip4:170.168.61.189 -all", false},
		{"No version tag", "l=https://example.com/logo.svg", false},
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBIMIRecord(parseBIMITags(tt.record)); got != tt.expected {
				t.Errorf("isBIMIRecord(%q) = %v, want %v", tt.record, got, tt.expected)
			}
		})
	}
}

func TestNotABIMIRecordError(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantSubstr string
	}{
		{"DMARC misconfiguration", "v=DMARC1;p=reject", "DMARC record"},
		{"SPF misconfiguration", "v=spf1 -all", "SPF record"},
		{"DKIM misconfiguration", "v=DKIM1; k=rsa; p=abc", "DKIM record"},
		{"Unknown", "garbage", "does not begin with v=BIMI1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := notABIMIRecordError(parseBIMITags(tt.record))
			if !strings.HasPrefix(got, "No BIMI record found") {
				t.Errorf("notABIMIRecordError(%q) = %q, want prefix %q", tt.record, got, "No BIMI record found")
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("notABIMIRecordError(%q) = %q, want to contain %q", tt.record, got, tt.wantSubstr)
			}
		})
	}
}
