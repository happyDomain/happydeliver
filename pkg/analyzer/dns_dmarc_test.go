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
			name:   "exact domain NXDOMAIN — tree walk reaches org domain",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "exact domain has no v=DMARC1 TXT — tree walk reaches org domain",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.mail.example.com": {"some-other-txt"},
				"_dmarc.example.com":      {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "both exact and org NXDOMAIN but PSD (TLD) has psd=y — DMARCbis Tree Walk",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.com": {psdRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("com"),
		},
		{
			name:   "PSD record exists but no psd=y — TLD record ignored by Tree Walk",
			domain: "mail.example.com",
			txt: map[string][]string{
				"_dmarc.com": {"v=DMARC1; p=none"},
			},
			wantValid:    false,
			wantErrSubst: "No DMARC record found",
		},
		{
			name:         "no record at any level",
			domain:       "mail.example.com",
			txt:          map[string][]string{},
			wantValid:    false,
			wantErrSubst: "No DMARC record found",
		},
		{
			name:   "DNS error on exact domain — error returned",
			domain: "mail.example.com",
			errMap: map[string]error{
				"_dmarc.mail.example.com": fmt.Errorf("SERVFAIL"),
			},
			wantValid:    false,
			wantErrSubst: "SERVFAIL",
		},
		{
			name:   "domain already at org level — found immediately",
			domain: "example.com",
			txt: map[string][]string{
				"_dmarc.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "deep subdomain — tree walk finds record two levels up",
			domain: "a.b.example.com",
			txt: map[string][]string{
				"_dmarc.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("example.com"),
		},
		{
			name:   "8-label domain — shortcut to 7-label suffix on miss",
			domain: "a.b.c.d.e.f.example.com",
			txt: map[string][]string{
				"_dmarc.b.c.d.e.f.example.com": {orgRecord},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("b.c.d.e.f.example.com"),
		},
		{
			name:   "psd=n record stops tree walk at that level",
			domain: "mail.sub.example.com",
			txt: map[string][]string{
				"_dmarc.sub.example.com": {"v=DMARC1; p=reject; psd=n"},
			},
			wantValid:  true,
			wantDomain: utils.PtrTo("sub.example.com"),
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

func TestParseDMARCRecordPolicy(t *testing.T) {
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
			rec := analyzer.parseDMARCRecord("example.com", tt.record)
			if rec.Policy == nil {
				t.Fatalf("parseDMARCRecord(%q).Policy = nil", tt.record)
			}
			if string(*rec.Policy) != tt.expectedPolicy {
				t.Errorf("parseDMARCRecord(%q).Policy = %q, want %q", tt.record, string(*rec.Policy), tt.expectedPolicy)
			}
		})
	}
}

func TestParseDMARCRecordTestMode(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		wantMode *bool
	}{
		{
			name:     "t=y sets test mode",
			record:   "v=DMARC1; p=reject; t=y",
			wantMode: utils.PtrTo(true),
		},
		{
			name:     "t=n explicitly disables test mode",
			record:   "v=DMARC1; p=reject; t=n",
			wantMode: utils.PtrTo(false),
		},
		{
			name:     "absent t tag returns nil",
			record:   "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
			wantMode: nil,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseDMARCRecord("example.com", tt.record).TestMode
			if tt.wantMode == nil {
				if result != nil {
					t.Errorf("parseDMARCRecord(%q).TestMode = %v, want nil", tt.record, *result)
				}
			} else {
				if result == nil {
					t.Fatalf("parseDMARCRecord(%q).TestMode = nil, want %v", tt.record, *tt.wantMode)
				}
				if *result != *tt.wantMode {
					t.Errorf("parseDMARCRecord(%q).TestMode = %v, want %v", tt.record, *result, *tt.wantMode)
				}
			}
		})
	}
}

func TestParseDMARCRecordPSD(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantPSD *string
	}{
		{
			name:    "psd=y marks Public Suffix Domain",
			record:  "v=DMARC1; p=none; psd=y",
			wantPSD: utils.PtrTo("y"),
		},
		{
			name:    "psd=n marks Org Domain boundary",
			record:  "v=DMARC1; p=reject; psd=n",
			wantPSD: utils.PtrTo("n"),
		},
		{
			name:    "psd=u is explicit unknown",
			record:  "v=DMARC1; p=quarantine; psd=u",
			wantPSD: utils.PtrTo("u"),
		},
		{
			name:    "absent psd tag returns nil",
			record:  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
			wantPSD: nil,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseDMARCRecord("example.com", tt.record).Psd
			if tt.wantPSD == nil {
				if result != nil {
					t.Errorf("parseDMARCRecord(%q).Psd = %v, want nil", tt.record, *result)
				}
			} else {
				if result == nil {
					t.Fatalf("parseDMARCRecord(%q).Psd = nil, want %q", tt.record, *tt.wantPSD)
				}
				if string(*result) != *tt.wantPSD {
					t.Errorf("parseDMARCRecord(%q).Psd = %q, want %q", tt.record, string(*result), *tt.wantPSD)
				}
			}
		})
	}
}

func TestParseDMARCRecordDeprecatedTags(t *testing.T) {
	tests := []struct {
		name      string
		record    string
		wantRf    bool
		wantRi    bool
	}{
		{name: "rf tag present", record: "v=DMARC1; p=none; rf=afrf", wantRf: true, wantRi: false},
		{name: "ri tag present", record: "v=DMARC1; p=none; ri=86400", wantRf: false, wantRi: true},
		{name: "rf tag absent", record: "v=DMARC1; p=quarantine; rua=mailto:x@example.com", wantRf: false, wantRi: false},
		{name: "ri tag absent", record: "v=DMARC1; p=quarantine", wantRf: false, wantRi: false},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := analyzer.parseDMARCRecord("example.com", tt.record)
			gotRf := rec.DeprecatedRf != nil && *rec.DeprecatedRf
			gotRi := rec.DeprecatedRi != nil && *rec.DeprecatedRi
			if gotRf != tt.wantRf {
				t.Errorf("parseDMARCRecord(%q).DeprecatedRf = %v, want %v", tt.record, gotRf, tt.wantRf)
			}
			if gotRi != tt.wantRi {
				t.Errorf("parseDMARCRecord(%q).DeprecatedRi = %v, want %v", tt.record, gotRi, tt.wantRi)
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
			name:     "DMARCbis: p= absent but rua= present is valid (treated as p=none)",
			record:   "v=DMARC1; rua=mailto:dmarc@example.com",
			expected: true,
		},
		{
			name:     "Invalid DMARC - no version",
			record:   "p=quarantine",
			expected: false,
		},
		{
			name:     "Invalid DMARC - no policy and no rua",
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

func TestParseDMARCRecordAlignment(t *testing.T) {
	tests := []struct {
		name           string
		record         string
		expectedSPF    string
		expectedDKIM   string
	}{
		{
			name:         "SPF strict, DKIM relaxed",
			record:       "v=DMARC1; p=quarantine; aspf=s; adkim=r",
			expectedSPF:  "strict",
			expectedDKIM: "relaxed",
		},
		{
			name:         "SPF relaxed explicit, DKIM strict",
			record:       "v=DMARC1; p=quarantine; aspf=r; adkim=s",
			expectedSPF:  "relaxed",
			expectedDKIM: "strict",
		},
		{
			name:         "Defaults when neither specified",
			record:       "v=DMARC1; p=quarantine",
			expectedSPF:  "relaxed",
			expectedDKIM: "relaxed",
		},
		{
			name:         "Both strict in complex record",
			record:       "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; aspf=s; adkim=s; pct=100",
			expectedSPF:  "strict",
			expectedDKIM: "strict",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := analyzer.parseDMARCRecord("example.com", tt.record)
			if rec.SpfAlignment == nil {
				t.Fatalf("parseDMARCRecord(%q).SpfAlignment = nil", tt.record)
			}
			if string(*rec.SpfAlignment) != tt.expectedSPF {
				t.Errorf("SpfAlignment = %q, want %q", string(*rec.SpfAlignment), tt.expectedSPF)
			}
			if rec.DkimAlignment == nil {
				t.Fatalf("parseDMARCRecord(%q).DkimAlignment = nil", tt.record)
			}
			if string(*rec.DkimAlignment) != tt.expectedDKIM {
				t.Errorf("DkimAlignment = %q, want %q", string(*rec.DkimAlignment), tt.expectedDKIM)
			}
		})
	}
}

func TestParseDMARCRecordSubdomainPolicy(t *testing.T) {
	tests := []struct {
		name           string
		record         string
		expectedSP     *string
		expectedNP     *string
	}{
		{
			name:       "sp=none, no np",
			record:     "v=DMARC1; p=quarantine; sp=none",
			expectedSP: utils.PtrTo("none"),
			expectedNP: nil,
		},
		{
			name:       "sp=reject, np=reject",
			record:     "v=DMARC1; p=reject; sp=quarantine; np=reject; rua=mailto:dmarc@example.com; pct=100",
			expectedSP: utils.PtrTo("quarantine"),
			expectedNP: utils.PtrTo("reject"),
		},
		{
			name:       "No sp or np (both default)",
			record:     "v=DMARC1; p=quarantine",
			expectedSP: nil,
			expectedNP: nil,
		},
		{
			name:       "np=quarantine, no sp",
			record:     "v=DMARC1; p=reject; np=quarantine",
			expectedSP: nil,
			expectedNP: utils.PtrTo("quarantine"),
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := analyzer.parseDMARCRecord("example.com", tt.record)
			if tt.expectedSP == nil {
				if rec.SubdomainPolicy != nil {
					t.Errorf("parseDMARCRecord(%q).SubdomainPolicy = %v, want nil", tt.record, *rec.SubdomainPolicy)
				}
			} else {
				if rec.SubdomainPolicy == nil {
					t.Fatalf("parseDMARCRecord(%q).SubdomainPolicy = nil, want %q", tt.record, *tt.expectedSP)
				}
				if string(*rec.SubdomainPolicy) != *tt.expectedSP {
					t.Errorf("SubdomainPolicy = %q, want %q", string(*rec.SubdomainPolicy), *tt.expectedSP)
				}
			}
			if tt.expectedNP == nil {
				if rec.NonexistentSubdomainPolicy != nil {
					t.Errorf("parseDMARCRecord(%q).NonexistentSubdomainPolicy = %v, want nil", tt.record, *rec.NonexistentSubdomainPolicy)
				}
			} else {
				if rec.NonexistentSubdomainPolicy == nil {
					t.Fatalf("parseDMARCRecord(%q).NonexistentSubdomainPolicy = nil, want %q", tt.record, *tt.expectedNP)
				}
				if string(*rec.NonexistentSubdomainPolicy) != *tt.expectedNP {
					t.Errorf("NonexistentSubdomainPolicy = %q, want %q", string(*rec.NonexistentSubdomainPolicy), *tt.expectedNP)
				}
			}
		})
	}
}

func TestParseDMARCRecordPercentage(t *testing.T) {
	tests := []struct {
		name               string
		record             string
		expectedPercentage *int
	}{
		{name: "pct=100", record: "v=DMARC1; p=quarantine; pct=100", expectedPercentage: utils.PtrTo(100)},
		{name: "pct=50", record: "v=DMARC1; p=quarantine; pct=50", expectedPercentage: utils.PtrTo(50)},
		{name: "pct=0", record: "v=DMARC1; p=none; pct=0", expectedPercentage: utils.PtrTo(0)},
		{name: "no pct", record: "v=DMARC1; p=quarantine", expectedPercentage: nil},
		{name: "pct=150 ignored", record: "v=DMARC1; p=quarantine; pct=150", expectedPercentage: nil},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseDMARCRecord("example.com", tt.record).Percentage
			if tt.expectedPercentage == nil {
				if result != nil {
					t.Errorf("parseDMARCRecord(%q).Percentage = %d, want nil", tt.record, *result)
				}
			} else {
				if result == nil {
					t.Fatalf("parseDMARCRecord(%q).Percentage = nil, want %d", tt.record, *tt.expectedPercentage)
				}
				if *result != *tt.expectedPercentage {
					t.Errorf("parseDMARCRecord(%q).Percentage = %d, want %d", tt.record, *result, *tt.expectedPercentage)
				}
			}
		})
	}
}
