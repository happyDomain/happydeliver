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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/utils"
)

// mockDNSResolver maps domain names to TXT records for testing.
// An entry with value nil means NXDOMAIN; an error value triggers a DNS error.
type mockDNSResolver struct {
	txt map[string][]string
	err map[string]error
}

func (m *mockDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := m.err[name]; ok {
		return nil, err
	}
	if records, ok := m.txt[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (m *mockDNSResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return nil, nil
}
func (m *mockDNSResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockDNSResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func newMockAnalyzer(txt map[string][]string, errMap map[string]error) *DNSAnalyzer {
	if errMap == nil {
		errMap = map[string]error{}
	}
	return NewDNSAnalyzerWithResolver(5*time.Second, &mockDNSResolver{txt: txt, err: errMap})
}

func TestCheckDMARCRecordFallback(t *testing.T) {
	const orgRecord = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
	const subRecord = "v=DMARC1; p=reject"
	const psdRecord = "v=DMARC1; p=none; psd=y"

	tests := []struct {
		name         string
		domain       string
		txt          map[string][]string
		errMap       map[string]error
		wantValid    bool
		wantDomain   *string
		wantErrSubst string
	}{
		{
			name:   "exact domain has DMARC record — no fallback",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.mail.example.com": {subRecord},
				"_dmarc.example.com":      {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("mail.example.com"),
		},
		{
			name:   "exact domain NXDOMAIN — falls back to org domain",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "exact domain has no v=DMARC1 TXT — falls back to org domain",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.mail.example.com": {"some-other-txt"},
				"_dmarc.example.com":      {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "both exact and org NXDOMAIN but PSD has psd=y — RFC 9091 fallback",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.com": {psdRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("com"),
		},
		{
			name:   "PSD record exists but no psd=y — no record returned",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.com": {"v=DMARC1; p=none"},
			},
			wantValid:    false,
			wantErrSubst: "No DMARC record found",
		},
		{
			name:   "no record at any level",
			domain: "mail.example.com",
			txt:    map[string][]string{},
			wantValid:    false,
			wantErrSubst: "No DMARC record found",
		},
		{
			name:   "DNS error on exact domain — no fallback, error returned",
			domain: "mail.example.com",
			errMap: map[string]error{
				"_dmarc.mail.example.com": fmt.Errorf("SERVFAIL"),
			},
			wantValid:    false,
			wantErrSubst: "SERVFAIL",
		},
		{
			name:   "domain already at org level — no redundant fallback",
			domain: "example.com",
			txt: map[string][]string{
				"_dmarc.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := newMockAnalyzer(tt.txt, tt.errMap)
			result := analyzer.checkDMARCRecord(tt.domain)

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}
			if tt.wantDomain != nil {
				if result.Domain == nil {
					t.Fatalf("Domain = nil, want %q", *tt.wantDomain)
				}
				if *result.Domain != *tt.wantDomain {
					t.Errorf("Domain = %q, want %q", *result.Domain, *tt.wantDomain)
				}
			}
			if tt.wantErrSubst != "" {
				if result.Error == nil {
					t.Fatalf("Error = nil, want substring %q", tt.wantErrSubst)
				}
				if !contains(*result.Error, tt.wantErrSubst) {
					t.Errorf("Error = %q, want substring %q", *result.Error, tt.wantErrSubst)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

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
			expectedPolicy: utils.PtrTo("none"),
		},
		{
			name:           "Subdomain policy - quarantine",
			record:         "v=DMARC1; p=reject; sp=quarantine",
			expectedPolicy: utils.PtrTo("quarantine"),
		},
		{
			name:           "Subdomain policy - reject",
			record:         "v=DMARC1; p=quarantine; sp=reject",
			expectedPolicy: utils.PtrTo("reject"),
		},
		{
			name:           "No subdomain policy specified (defaults to main policy)",
			record:         "v=DMARC1; p=quarantine",
			expectedPolicy: nil,
		},
		{
			name:           "Complex record with subdomain policy",
			record:         "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=100",
			expectedPolicy: utils.PtrTo("quarantine"),
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

func TestExtractDMARCNonexistentSubdomainPolicy(t *testing.T) {
	tests := []struct {
		name           string
		record         string
		expectedPolicy *string
	}{
		{
			name:           "Non-existent subdomain policy - none",
			record:         "v=DMARC1; p=quarantine; np=none",
			expectedPolicy: utils.PtrTo("none"),
		},
		{
			name:           "Non-existent subdomain policy - quarantine",
			record:         "v=DMARC1; p=reject; np=quarantine",
			expectedPolicy: utils.PtrTo("quarantine"),
		},
		{
			name:           "Non-existent subdomain policy - reject",
			record:         "v=DMARC1; p=quarantine; np=reject",
			expectedPolicy: utils.PtrTo("reject"),
		},
		{
			name:           "No np tag (defaults to effective sp/p policy)",
			record:         "v=DMARC1; p=quarantine",
			expectedPolicy: nil,
		},
		{
			name:           "Complex record with np and sp tags",
			record:         "v=DMARC1; p=reject; sp=quarantine; np=reject; rua=mailto:dmarc@example.com; pct=100",
			expectedPolicy: utils.PtrTo("reject"),
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDMARCNonexistentSubdomainPolicy(tt.record)
			if tt.expectedPolicy == nil {
				if result != nil {
					t.Errorf("extractDMARCNonexistentSubdomainPolicy(%q) = %v, want nil", tt.record, result)
				}
			} else {
				if result == nil {
					t.Fatalf("extractDMARCNonexistentSubdomainPolicy(%q) returned nil, expected %q", tt.record, *tt.expectedPolicy)
				}
				if string(*result) != *tt.expectedPolicy {
					t.Errorf("extractDMARCNonexistentSubdomainPolicy(%q) = %q, want %q", tt.record, string(*result), *tt.expectedPolicy)
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
			expectedPercentage: utils.PtrTo(100),
		},
		{
			name:               "Percentage - 50",
			record:             "v=DMARC1; p=quarantine; pct=50",
			expectedPercentage: utils.PtrTo(50),
		},
		{
			name:               "Percentage - 25",
			record:             "v=DMARC1; p=reject; pct=25",
			expectedPercentage: utils.PtrTo(25),
		},
		{
			name:               "Percentage - 0",
			record:             "v=DMARC1; p=none; pct=0",
			expectedPercentage: utils.PtrTo(0),
		},
		{
			name:               "No percentage specified (defaults to 100)",
			record:             "v=DMARC1; p=quarantine",
			expectedPercentage: nil,
		},
		{
			name:               "Complex record with percentage",
			record:             "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=75",
			expectedPercentage: utils.PtrTo(75),
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
