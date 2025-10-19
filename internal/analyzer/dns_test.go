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
	"net/mail"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

func TestNewDNSAnalyzer(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "Default timeout",
			timeout:         0,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "Custom timeout",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewDNSAnalyzer(tt.timeout)
			if analyzer.Timeout != tt.expectedTimeout {
				t.Errorf("Timeout = %v, want %v", analyzer.Timeout, tt.expectedTimeout)
			}
			if analyzer.resolver == nil {
				t.Error("Resolver should not be nil")
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name           string
		fromAddress    string
		expectedDomain string
	}{
		{
			name:           "Valid email",
			fromAddress:    "user@example.com",
			expectedDomain: "example.com",
		},
		{
			name:           "Email with subdomain",
			fromAddress:    "user@mail.example.com",
			expectedDomain: "mail.example.com",
		},
		{
			name:           "Email with uppercase",
			fromAddress:    "User@Example.COM",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid email (no @)",
			fromAddress:    "invalid-email",
			expectedDomain: "",
		},
		{
			name:           "Empty email",
			fromAddress:    "",
			expectedDomain: "",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: make(mail.Header),
			}
			if tt.fromAddress != "" {
				email.From = &mail.Address{
					Address: tt.fromAddress,
				}
			}

			domain := analyzer.extractDomain(email)
			if domain != tt.expectedDomain {
				t.Errorf("extractDomain() = %q, want %q", domain, tt.expectedDomain)
			}
		})
	}
}

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
			name:     "Invalid SPF - no version",
			record:   "include:_spf.example.com -all",
			expected: false,
		},
		{
			name:     "Invalid SPF - no all mechanism",
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

func TestValidateDKIM(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{
			name:     "Valid DKIM with version",
			record:   "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: true,
		},
		{
			name:     "Valid DKIM without version",
			record:   "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: true,
		},
		{
			name:     "Invalid DKIM - no public key",
			record:   "v=DKIM1; k=rsa",
			expected: false,
		},
		{
			name:     "Invalid DKIM - wrong version",
			record:   "v=DKIM2; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: false,
		},
		{
			name:     "Invalid DKIM - empty",
			record:   "",
			expected: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.validateDKIM(tt.record)
			if result != tt.expected {
				t.Errorf("validateDKIM(%q) = %v, want %v", tt.record, result, tt.expected)
			}
		})
	}
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

func TestGenerateMXCheck(t *testing.T) {
	tests := []struct {
		name           string
		results        *DNSResults
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid MX records",
			results: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Host: "mail.example.com", Priority: 10, Valid: true},
					{Host: "mail2.example.com", Priority: 20, Valid: true},
				},
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "No MX records",
			results: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Valid: false, Error: "No MX records found"},
				},
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
		{
			name: "MX lookup failed",
			results: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Valid: false, Error: "DNS lookup failed"},
				},
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateMXCheck(tt.results)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Dns {
				t.Errorf("Category = %v, want %v", check.Category, api.Dns)
			}
		})
	}
}

func TestGenerateSPFCheck(t *testing.T) {
	tests := []struct {
		name           string
		spf            *SPFRecord
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid SPF",
			spf: &SPFRecord{
				Record: "v=spf1 include:_spf.example.com -all",
				Valid:  true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "Invalid SPF",
			spf: &SPFRecord{
				Record: "v=spf1 invalid syntax",
				Valid:  false,
				Error:  "SPF record appears malformed",
			},
			expectedStatus: api.CheckStatusWarn,
			expectedScore:  0.5,
		},
		{
			name: "No SPF record",
			spf: &SPFRecord{
				Valid: false,
				Error: "No SPF record found",
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateSPFCheck(tt.spf)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Dns {
				t.Errorf("Category = %v, want %v", check.Category, api.Dns)
			}
		})
	}
}

func TestGenerateDKIMCheck(t *testing.T) {
	tests := []struct {
		name           string
		dkim           *DKIMRecord
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid DKIM",
			dkim: &DKIMRecord{
				Selector: "default",
				Domain:   "example.com",
				Record:   "v=DKIM1; k=rsa; p=MIGfMA0...",
				Valid:    true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "Invalid DKIM",
			dkim: &DKIMRecord{
				Selector: "default",
				Domain:   "example.com",
				Valid:    false,
				Error:    "No DKIM record found",
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateDKIMCheck(tt.dkim)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Dns {
				t.Errorf("Category = %v, want %v", check.Category, api.Dns)
			}
			if !strings.Contains(check.Name, tt.dkim.Selector) {
				t.Errorf("Check name should contain selector %s", tt.dkim.Selector)
			}
		})
	}
}

func TestGenerateDMARCCheck(t *testing.T) {
	tests := []struct {
		name           string
		dmarc          *DMARCRecord
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid DMARC - reject",
			dmarc: &DMARCRecord{
				Record: "v=DMARC1; p=reject",
				Policy: "reject",
				Valid:  true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "Valid DMARC - quarantine",
			dmarc: &DMARCRecord{
				Record: "v=DMARC1; p=quarantine",
				Policy: "quarantine",
				Valid:  true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "Valid DMARC - none",
			dmarc: &DMARCRecord{
				Record: "v=DMARC1; p=none",
				Policy: "none",
				Valid:  true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  1.0,
		},
		{
			name: "No DMARC record",
			dmarc: &DMARCRecord{
				Valid: false,
				Error: "No DMARC record found",
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateDMARCCheck(tt.dmarc)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Dns {
				t.Errorf("Category = %v, want %v", check.Category, api.Dns)
			}

			// Check that advice mentions policy for valid DMARC
			if tt.dmarc.Valid && check.Advice != nil {
				if tt.dmarc.Policy == "none" && !strings.Contains(*check.Advice, "none") {
					t.Error("Advice should mention 'none' policy")
				}
			}
		})
	}
}

func TestGenerateDNSChecks(t *testing.T) {
	tests := []struct {
		name      string
		results   *DNSResults
		minChecks int
	}{
		{
			name:      "Nil results",
			results:   nil,
			minChecks: 0,
		},
		{
			name: "Complete results",
			results: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Host: "mail.example.com", Priority: 10, Valid: true},
				},
				SPFRecord: &SPFRecord{
					Record: "v=spf1 include:_spf.example.com -all",
					Valid:  true,
				},
				DKIMRecords: []DKIMRecord{
					{
						Selector: "default",
						Domain:   "example.com",
						Valid:    true,
					},
				},
				DMARCRecord: &DMARCRecord{
					Record: "v=DMARC1; p=quarantine",
					Policy: "quarantine",
					Valid:  true,
				},
			},
			minChecks: 4, // MX, SPF, DKIM, DMARC
		},
		{
			name: "Partial results",
			results: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Host: "mail.example.com", Priority: 10, Valid: true},
				},
			},
			minChecks: 1, // Only MX
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.GenerateDNSChecks(tt.results)

			if len(checks) < tt.minChecks {
				t.Errorf("Got %d checks, want at least %d", len(checks), tt.minChecks)
			}

			// Verify all checks have the DNS category
			for _, check := range checks {
				if check.Category != api.Dns {
					t.Errorf("Check %s has category %v, want %v", check.Name, check.Category, api.Dns)
				}
			}
		})
	}
}

func TestAnalyzeDNS_NoDomain(t *testing.T) {
	analyzer := NewDNSAnalyzer(5 * time.Second)
	email := &EmailMessage{
		Header: make(mail.Header),
		// No From address
	}

	results := analyzer.AnalyzeDNS(email, nil)

	if results == nil {
		t.Fatal("Expected results, got nil")
	}

	if len(results.Errors) == 0 {
		t.Error("Expected error when no domain can be extracted")
	}
}

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

func TestGenerateBIMICheck(t *testing.T) {
	tests := []struct {
		name           string
		bimi           *BIMIRecord
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid BIMI with logo only",
			bimi: &BIMIRecord{
				Selector: "default",
				Domain:   "example.com",
				Record:   "v=BIMI1; l=https://example.com/logo.svg",
				LogoURL:  "https://example.com/logo.svg",
				Valid:    true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  0.0, // BIMI doesn't contribute to score
		},
		{
			name: "Valid BIMI with VMC",
			bimi: &BIMIRecord{
				Selector: "default",
				Domain:   "example.com",
				Record:   "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
				LogoURL:  "https://example.com/logo.svg",
				VMCURL:   "https://example.com/vmc.pem",
				Valid:    true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  0.0,
		},
		{
			name: "No BIMI record (optional)",
			bimi: &BIMIRecord{
				Selector: "default",
				Domain:   "example.com",
				Valid:    false,
				Error:    "No BIMI record found",
			},
			expectedStatus: api.CheckStatusInfo,
			expectedScore:  0.0,
		},
		{
			name: "Invalid BIMI record",
			bimi: &BIMIRecord{
				Selector: "default",
				Domain:   "example.com",
				Record:   "v=BIMI1",
				Valid:    false,
				Error:    "BIMI record appears malformed",
			},
			expectedStatus: api.CheckStatusWarn,
			expectedScore:  0.0,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateBIMICheck(tt.bimi)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Dns {
				t.Errorf("Category = %v, want %v", check.Category, api.Dns)
			}
			if check.Name != "BIMI Record" {
				t.Errorf("Name = %q, want %q", check.Name, "BIMI Record")
			}

			// Check details for valid BIMI with VMC
			if tt.bimi.Valid && tt.bimi.VMCURL != "" && check.Details != nil {
				if !strings.Contains(*check.Details, "VMC URL") {
					t.Error("Details should contain VMC URL for valid BIMI with VMC")
				}
			}
		})
	}
}
