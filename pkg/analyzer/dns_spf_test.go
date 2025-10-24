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

func TestValidateSPF(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{
			name:     "Valid SPF with -all",
			record:   "v=spf1 include:_spf.example.com -all",
			expected: true,
		},
		{
			name:     "Valid SPF with ~all",
			record:   "v=spf1 ip4:192.0.2.0/24 ~all",
			expected: true,
		},
		{
			name:     "Valid SPF with +all",
			record:   "v=spf1 +all",
			expected: true,
		},
		{
			name:     "Valid SPF with ?all",
			record:   "v=spf1 mx ?all",
			expected: true,
		},
		{
			name:     "Valid SPF with redirect",
			record:   "v=spf1 redirect=_spf.example.com",
			expected: true,
		},
		{
			name:     "Valid SPF with redirect and mechanisms",
			record:   "v=spf1 ip4:192.0.2.0/24 redirect=_spf.example.com",
			expected: true,
		},
		{
			name:     "Invalid SPF - no version",
			record:   "include:_spf.example.com -all",
			expected: false,
		},
		{
			name:     "Invalid SPF - no all mechanism or redirect",
			record:   "v=spf1 include:_spf.example.com",
			expected: false,
		},
		{
			name:     "Invalid SPF - wrong version",
			record:   "v=spf2 include:_spf.example.com -all",
			expected: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.validateSPF(tt.record)
			if result != tt.expected {
				t.Errorf("validateSPF(%q) = %v, want %v", tt.record, result, tt.expected)
			}
		})
	}
}

func TestExtractSPFRedirect(t *testing.T) {
	tests := []struct {
		name             string
		record           string
		expectedRedirect string
	}{
		{
			name:             "SPF with redirect",
			record:           "v=spf1 redirect=_spf.example.com",
			expectedRedirect: "_spf.example.com",
		},
		{
			name:             "SPF with redirect and other mechanisms",
			record:           "v=spf1 ip4:192.0.2.0/24 redirect=_spf.google.com",
			expectedRedirect: "_spf.google.com",
		},
		{
			name:             "SPF without redirect",
			record:           "v=spf1 include:_spf.example.com -all",
			expectedRedirect: "",
		},
		{
			name:             "SPF with only all mechanism",
			record:           "v=spf1 -all",
			expectedRedirect: "",
		},
		{
			name:             "Empty record",
			record:           "",
			expectedRedirect: "",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractSPFRedirect(tt.record)
			if result != tt.expectedRedirect {
				t.Errorf("extractSPFRedirect(%q) = %q, want %q", tt.record, result, tt.expectedRedirect)
			}
		})
	}
}
