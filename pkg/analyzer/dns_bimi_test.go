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
