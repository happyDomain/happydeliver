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

func TestValidateSPF(t *testing.T) {
	tests := []struct {
		name        string
		record      string
		expectError bool
		errorMsg    string // Expected error message (substring match)
	}{
		{
			name:        "Valid SPF with -all",
			record:      "v=spf1 include:_spf.example.com -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with ~all",
			record:      "v=spf1 ip4:192.0.2.0/24 ~all",
			expectError: false,
		},
		{
			name:        "Valid SPF with +all",
			record:      "v=spf1 +all",
			expectError: false,
		},
		{
			name:        "Valid SPF with ?all",
			record:      "v=spf1 mx ?all",
			expectError: false,
		},
		{
			name:        "Valid SPF with redirect",
			record:      "v=spf1 redirect=_spf.example.com",
			expectError: false,
		},
		{
			name:        "Valid SPF with redirect and mechanisms",
			record:      "v=spf1 ip4:192.0.2.0/24 redirect=_spf.example.com",
			expectError: false,
		},
		{
			name:        "Valid SPF with multiple mechanisms",
			record:      "v=spf1 a mx ip4:192.0.2.0/24 include:_spf.example.com -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with exp modifier",
			record:      "v=spf1 mx exp=explain.example.com -all",
			expectError: false,
		},
		{
			name:        "Invalid SPF - no version",
			record:      "include:_spf.example.com -all",
			expectError: true,
			errorMsg:    "must start with 'v=spf1'",
		},
		{
			name:        "Invalid SPF - no all mechanism or redirect",
			record:      "v=spf1 include:_spf.example.com",
			expectError: true,
			errorMsg:    "should end with an 'all' mechanism",
		},
		{
			name:        "Invalid SPF - wrong version",
			record:      "v=spf2 include:_spf.example.com -all",
			expectError: true,
			errorMsg:    "must start with 'v=spf1'",
		},
		{
			name:        "Invalid SPF - include= instead of include:",
			record:      "v=spf1 include=icloud.com ~all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - a= instead of a:",
			record:      "v=spf1 a=example.com -all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - mx= instead of mx:",
			record:      "v=spf1 mx=example.com -all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - unknown mechanism",
			record:      "v=spf1 foobar -all",
			expectError: true,
			errorMsg:    "unknown mechanism",
		},
		{
			name:        "Invalid SPF - unknown modifier",
			record:      "v=spf1 -all unknown=value",
			expectError: true,
			errorMsg:    "unknown modifier",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := analyzer.validateSPF(tt.record)
			if tt.expectError {
				if err == nil {
					t.Errorf("validateSPF(%q) expected error but got nil", tt.record)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateSPF(%q) error = %q, want error containing %q", tt.record, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateSPF(%q) unexpected error: %v", tt.record, err)
				}
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
