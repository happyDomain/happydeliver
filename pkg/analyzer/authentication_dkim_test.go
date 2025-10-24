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

	"git.happydns.org/happyDeliver/internal/api"
)

func TestParseDKIMResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   api.AuthResultResult
		expectedDomain   string
		expectedSelector string
	}{
		{
			name:             "DKIM pass with domain and selector",
			part:             "dkim=pass header.d=example.com header.s=default",
			expectedResult:   api.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
		{
			name:             "DKIM fail",
			part:             "dkim=fail header.d=example.com header.s=selector1",
			expectedResult:   api.AuthResultResultFail,
			expectedDomain:   "example.com",
			expectedSelector: "selector1",
		},
		{
			name:             "DKIM with short form (d= and s=)",
			part:             "dkim=pass d=example.com s=default",
			expectedResult:   api.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseDKIMResult(tt.part)

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}
			if result.Domain == nil || *result.Domain != tt.expectedDomain {
				var gotDomain string
				if result.Domain != nil {
					gotDomain = *result.Domain
				}
				t.Errorf("Domain = %v, want %v", gotDomain, tt.expectedDomain)
			}
			if result.Selector == nil || *result.Selector != tt.expectedSelector {
				var gotSelector string
				if result.Selector != nil {
					gotSelector = *result.Selector
				}
				t.Errorf("Selector = %v, want %v", gotSelector, tt.expectedSelector)
			}
		})
	}
}

func TestParseLegacyDKIM(t *testing.T) {
	tests := []struct {
		name             string
		dkimSignatures   []string
		expectedCount    int
		expectedDomains  []string
		expectedSelector []string
	}{
		{
			name: "Single DKIM signature with domain and selector",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1; h=from:to:subject:date; bh=xyz; b=abc",
			},
			expectedCount:    1,
			expectedDomains:  []string{"example.com"},
			expectedSelector: []string{"selector1"},
		},
		{
			name: "Multiple DKIM signatures",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=example.com; s=selector1; b=abc123",
				"v=1; a=rsa-sha256; d=example.com; s=selector2; b=def456",
			},
			expectedCount:    2,
			expectedDomains:  []string{"example.com", "example.com"},
			expectedSelector: []string{"selector1", "selector2"},
		},
		{
			name: "DKIM signature with different domain",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=mail.example.org; s=default; b=xyz789",
			},
			expectedCount:    1,
			expectedDomains:  []string{"mail.example.org"},
			expectedSelector: []string{"default"},
		},
		{
			name: "DKIM signature with subdomain",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=newsletters.example.com; s=marketing; b=aaa",
			},
			expectedCount:    1,
			expectedDomains:  []string{"newsletters.example.com"},
			expectedSelector: []string{"marketing"},
		},
		{
			name: "Multiple signatures from different domains",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=example.com; s=s1; b=abc",
				"v=1; a=rsa-sha256; d=relay.com; s=s2; b=def",
			},
			expectedCount:    2,
			expectedDomains:  []string{"example.com", "relay.com"},
			expectedSelector: []string{"s1", "s2"},
		},
		{
			name:             "No DKIM signatures",
			dkimSignatures:   []string{},
			expectedCount:    0,
			expectedDomains:  []string{},
			expectedSelector: []string{},
		},
		{
			name: "DKIM signature without selector",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=example.com; b=abc123",
			},
			expectedCount:    1,
			expectedDomains:  []string{"example.com"},
			expectedSelector: []string{""},
		},
		{
			name: "DKIM signature without domain",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; s=selector1; b=abc123",
			},
			expectedCount:    1,
			expectedDomains:  []string{""},
			expectedSelector: []string{"selector1"},
		},
		{
			name: "DKIM signature with whitespace in parameters",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; d=example.com ; s=selector1 ; b=abc123",
			},
			expectedCount:    1,
			expectedDomains:  []string{"example.com"},
			expectedSelector: []string{"selector1"},
		},
		{
			name: "DKIM signature with multiline format",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n\td=example.com; s=selector1;\r\n\th=from:to:subject:date;\r\n\tb=abc123def456ghi789",
			},
			expectedCount:    1,
			expectedDomains:  []string{"example.com"},
			expectedSelector: []string{"selector1"},
		},
		{
			name: "DKIM signature with ed25519 algorithm",
			dkimSignatures: []string{
				"v=1; a=ed25519-sha256; d=example.com; s=ed25519; b=xyz",
			},
			expectedCount:    1,
			expectedDomains:  []string{"example.com"},
			expectedSelector: []string{"ed25519"},
		},
		{
			name: "Complex real-world DKIM signature",
			dkimSignatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=20230601; t=1234567890; x=1234567950; darn=example.com; h=to:subject:message-id:date:from:mime-version:from:to:cc:subject:date:message-id:reply-to; bh=abc123def456==; b=longsignaturehere==",
			},
			expectedCount:    1,
			expectedDomains:  []string{"google.com"},
			expectedSelector: []string{"20230601"},
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock email message with DKIM-Signature headers
			email := &EmailMessage{
				Header: make(map[string][]string),
			}
			if len(tt.dkimSignatures) > 0 {
				email.Header["Dkim-Signature"] = tt.dkimSignatures
			}

			results := analyzer.parseLegacyDKIM(email)

			// Check count
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d results, got %d", tt.expectedCount, len(results))
				return
			}

			// Check each result
			for i, result := range results {
				// All legacy DKIM results should have Result = none
				if result.Result != api.AuthResultResultNone {
					t.Errorf("Result[%d].Result = %v, want %v", i, result.Result, api.AuthResultResultNone)
				}

				// Check domain
				if i < len(tt.expectedDomains) {
					expectedDomain := tt.expectedDomains[i]
					if expectedDomain != "" {
						if result.Domain == nil {
							t.Errorf("Result[%d].Domain = nil, want %v", i, expectedDomain)
						} else if strings.TrimSpace(*result.Domain) != expectedDomain {
							t.Errorf("Result[%d].Domain = %v, want %v", i, *result.Domain, expectedDomain)
						}
					}
				}

				// Check selector
				if i < len(tt.expectedSelector) {
					expectedSelector := tt.expectedSelector[i]
					if expectedSelector != "" {
						if result.Selector == nil {
							t.Errorf("Result[%d].Selector = nil, want %v", i, expectedSelector)
						} else if strings.TrimSpace(*result.Selector) != expectedSelector {
							t.Errorf("Result[%d].Selector = %v, want %v", i, *result.Selector, expectedSelector)
						}
					}
				}

				// Check that Details is set
				if result.Details == nil {
					t.Errorf("Result[%d].Details = nil, expected non-nil", i)
				} else {
					expectedDetails := "DKIM signature present (verification status unknown)"
					if *result.Details != expectedDetails {
						t.Errorf("Result[%d].Details = %v, want %v", i, *result.Details, expectedDetails)
					}
				}
			}
		})
	}
}

func TestParseLegacyDKIM_Integration(t *testing.T) {
	// Test that parseLegacyDKIM is properly integrated into AnalyzeAuthentication
	t.Run("Legacy DKIM is used when no Authentication-Results", func(t *testing.T) {
		analyzer := NewAuthenticationAnalyzer()
		email := &EmailMessage{
			Header: make(map[string][]string),
		}
		email.Header["Dkim-Signature"] = []string{
			"v=1; a=rsa-sha256; d=example.com; s=selector1; b=abc",
		}

		results := analyzer.AnalyzeAuthentication(email)

		if results.Dkim == nil {
			t.Fatal("Expected DKIM results, got nil")
		}
		if len(*results.Dkim) != 1 {
			t.Errorf("Expected 1 DKIM result, got %d", len(*results.Dkim))
		}
		if (*results.Dkim)[0].Result != api.AuthResultResultNone {
			t.Errorf("Expected DKIM result to be 'none', got %v", (*results.Dkim)[0].Result)
		}
		if (*results.Dkim)[0].Domain == nil || *(*results.Dkim)[0].Domain != "example.com" {
			t.Error("Expected domain to be 'example.com'")
		}
	})

	t.Run("Legacy DKIM is NOT used when Authentication-Results present", func(t *testing.T) {
		analyzer := NewAuthenticationAnalyzer()
		email := &EmailMessage{
			Header: make(map[string][]string),
		}
		// Both Authentication-Results and DKIM-Signature headers
		email.Header["Authentication-Results"] = []string{
			"mx.example.com; dkim=pass header.d=verified.com header.s=s1",
		}
		email.Header["Dkim-Signature"] = []string{
			"v=1; a=rsa-sha256; d=example.com; s=selector1; b=abc",
		}

		results := analyzer.AnalyzeAuthentication(email)

		// Should use the Authentication-Results DKIM (pass from verified.com), not the legacy signature
		if results.Dkim == nil {
			t.Fatal("Expected DKIM results, got nil")
		}
		if len(*results.Dkim) != 1 {
			t.Errorf("Expected 1 DKIM result, got %d", len(*results.Dkim))
		}
		if (*results.Dkim)[0].Result != api.AuthResultResultPass {
			t.Errorf("Expected DKIM result to be 'pass', got %v", (*results.Dkim)[0].Result)
		}
		if (*results.Dkim)[0].Domain == nil || *(*results.Dkim)[0].Domain != "verified.com" {
			t.Error("Expected domain to be 'verified.com' from Authentication-Results, not 'example.com' from legacy")
		}
	})
}
