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
	"testing"
	"time"
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
