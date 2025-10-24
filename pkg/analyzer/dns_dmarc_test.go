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

	"git.happydns.org/happyDeliver/internal/api"
)

func TestExtractDMARCPolicy(t *testing.T) {
	tests := []struct {
		name           string
		record         string
		expectedPolicy string
	}{
		{
			name:           "Policy none",
			record:         "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
			expectedPolicy: "none",
		},
		{
			name:           "Policy quarantine",
			record:         "v=DMARC1; p=quarantine; pct=100",
			expectedPolicy: "quarantine",
		},
		{
			name:           "Policy reject",
			record:         "v=DMARC1; p=reject; sp=reject",
			expectedPolicy: "reject",
		},
		{
			name:           "No policy",
			record:         "v=DMARC1",
			expectedPolicy: "unknown",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCPolicy(tt.record)
			if result != tt.expectedPolicy {
				t.Errorf("extractDMARCPolicy(%q) = %q, want %q", tt.record, result, tt.expectedPolicy)
			}
		})
	}
}

func TestValidateDMARC(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{
			name:     "Valid DMARC",
			record:   "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
			expected: true,
		},
		{
			name:     "Valid DMARC minimal",
			record:   "v=DMARC1; p=none",
			expected: true,
		},
		{
			name:     "Invalid DMARC - no version",
			record:   "p=quarantine",
			expected: false,
		},
		{
			name:     "Invalid DMARC - no policy",
			record:   "v=DMARC1",
			expected: false,
		},
		{
			name:     "Invalid DMARC - wrong version",
			record:   "v=DMARC2; p=reject",
			expected: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.validateDMARC(tt.record)
			if result != tt.expected {
				t.Errorf("validateDMARC(%q) = %v, want %v", tt.record, result, tt.expected)
			}
		})
	}
}

func TestExtractDMARCSPFAlignment(t *testing.T) {
	tests := []struct {
		name              string
		record            string
		expectedAlignment string
	}{
		{
			name:              "SPF alignment - strict",
			record:            "v=DMARC1; p=quarantine; aspf=s",
			expectedAlignment: "strict",
		},
		{
			name:              "SPF alignment - relaxed (explicit)",
			record:            "v=DMARC1; p=quarantine; aspf=r",
			expectedAlignment: "relaxed",
		},
		{
			name:              "SPF alignment - relaxed (default, not specified)",
			record:            "v=DMARC1; p=quarantine",
			expectedAlignment: "relaxed",
		},
		{
			name:              "Both alignments specified - check SPF strict",
			record:            "v=DMARC1; p=quarantine; aspf=s; adkim=r",
			expectedAlignment: "strict",
		},
		{
			name:              "Both alignments specified - check SPF relaxed",
			record:            "v=DMARC1; p=quarantine; aspf=r; adkim=s",
			expectedAlignment: "relaxed",
		},
		{
			name:              "Complex record with SPF strict",
			record:            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; aspf=s; adkim=s; pct=100",
			expectedAlignment: "strict",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCSPFAlignment(tt.record)
			if result == nil {
				t.Fatalf("extractDMARCSPFAlignment(%q) returned nil, expected non-nil", tt.record)
			}
			if string(*result) != tt.expectedAlignment {
				t.Errorf("extractDMARCSPFAlignment(%q) = %q, want %q", tt.record, string(*result), tt.expectedAlignment)
			}
		})
	}
}

func TestExtractDMARCDKIMAlignment(t *testing.T) {
	tests := []struct {
		name              string
		record            string
		expectedAlignment string
	}{
		{
			name:              "DKIM alignment - strict",
			record:            "v=DMARC1; p=reject; adkim=s",
			expectedAlignment: "strict",
		},
		{
			name:              "DKIM alignment - relaxed (explicit)",
			record:            "v=DMARC1; p=reject; adkim=r",
			expectedAlignment: "relaxed",
		},
		{
			name:              "DKIM alignment - relaxed (default, not specified)",
			record:            "v=DMARC1; p=none",
			expectedAlignment: "relaxed",
		},
		{
			name:              "Both alignments specified - check DKIM strict",
			record:            "v=DMARC1; p=quarantine; aspf=r; adkim=s",
			expectedAlignment: "strict",
		},
		{
			name:              "Both alignments specified - check DKIM relaxed",
			record:            "v=DMARC1; p=quarantine; aspf=s; adkim=r",
			expectedAlignment: "relaxed",
		},
		{
			name:              "Complex record with DKIM strict",
			record:            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; aspf=r; adkim=s; pct=100",
			expectedAlignment: "strict",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCDKIMAlignment(tt.record)
			if result == nil {
				t.Fatalf("extractDMARCDKIMAlignment(%q) returned nil, expected non-nil", tt.record)
			}
			if string(*result) != tt.expectedAlignment {
				t.Errorf("extractDMARCDKIMAlignment(%q) = %q, want %q", tt.record, string(*result), tt.expectedAlignment)
			}
		})
	}
}

func TestExtractDMARCSubdomainPolicy(t *testing.T) {
	tests := []struct {
		name           string
		record         string
		expectedPolicy *string
	}{
		{
			name:           "Subdomain policy - none",
			record:         "v=DMARC1; p=quarantine; sp=none",
			expectedPolicy: api.PtrTo("none"),
		},
		{
			name:           "Subdomain policy - quarantine",
			record:         "v=DMARC1; p=reject; sp=quarantine",
			expectedPolicy: api.PtrTo("quarantine"),
		},
		{
			name:           "Subdomain policy - reject",
			record:         "v=DMARC1; p=quarantine; sp=reject",
			expectedPolicy: api.PtrTo("reject"),
		},
		{
			name:           "No subdomain policy specified (defaults to main policy)",
			record:         "v=DMARC1; p=quarantine",
			expectedPolicy: nil,
		},
		{
			name:           "Complex record with subdomain policy",
			record:         "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=100",
			expectedPolicy: api.PtrTo("quarantine"),
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCSubdomainPolicy(tt.record)
			if tt.expectedPolicy == nil {
				if result != nil {
					t.Errorf("extractDMARCSubdomainPolicy(%q) = %v, want nil", tt.record, result)
				}
			} else {
				if result == nil {
					t.Fatalf("extractDMARCSubdomainPolicy(%q) returned nil, expected %q", tt.record, *tt.expectedPolicy)
				}
				if string(*result) != *tt.expectedPolicy {
					t.Errorf("extractDMARCSubdomainPolicy(%q) = %q, want %q", tt.record, string(*result), *tt.expectedPolicy)
				}
			}
		})
	}
}

func TestExtractDMARCPercentage(t *testing.T) {
	tests := []struct {
		name               string
		record             string
		expectedPercentage *int
	}{
		{
			name:               "Percentage - 100",
			record:             "v=DMARC1; p=quarantine; pct=100",
			expectedPercentage: api.PtrTo(100),
		},
		{
			name:               "Percentage - 50",
			record:             "v=DMARC1; p=quarantine; pct=50",
			expectedPercentage: api.PtrTo(50),
		},
		{
			name:               "Percentage - 25",
			record:             "v=DMARC1; p=reject; pct=25",
			expectedPercentage: api.PtrTo(25),
		},
		{
			name:               "Percentage - 0",
			record:             "v=DMARC1; p=none; pct=0",
			expectedPercentage: api.PtrTo(0),
		},
		{
			name:               "No percentage specified (defaults to 100)",
			record:             "v=DMARC1; p=quarantine",
			expectedPercentage: nil,
		},
		{
			name:               "Complex record with percentage",
			record:             "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=75",
			expectedPercentage: api.PtrTo(75),
		},
		{
			name:               "Invalid percentage > 100 (ignored)",
			record:             "v=DMARC1; p=quarantine; pct=150",
			expectedPercentage: nil,
		},
		{
			name:               "Invalid percentage < 0 (ignored)",
			record:             "v=DMARC1; p=quarantine; pct=-10",
			expectedPercentage: nil,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCPercentage(tt.record)
			if tt.expectedPercentage == nil {
				if result != nil {
					t.Errorf("extractDMARCPercentage(%q) = %v, want nil", tt.record, *result)
				}
			} else {
				if result == nil {
					t.Fatalf("extractDMARCPercentage(%q) returned nil, expected %d", tt.record, *tt.expectedPercentage)
				}
				if *result != *tt.expectedPercentage {
					t.Errorf("extractDMARCPercentage(%q) = %d, want %d", tt.record, *result, *tt.expectedPercentage)
				}
			}
		})
	}
}
