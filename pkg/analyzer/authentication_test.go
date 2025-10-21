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

	"git.happydns.org/happyDeliver/internal/api"
)

func TestParseSPFResult(t *testing.T) {
	tests := []struct {
		name           string
		part           string
		expectedResult api.AuthResultResult
		expectedDomain string
	}{
		{
			name:           "SPF pass with domain",
			part:           "spf=pass smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF fail",
			part:           "spf=fail smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultFail,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF neutral",
			part:           "spf=neutral smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultNeutral,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF softfail",
			part:           "spf=softfail smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultSoftfail,
			expectedDomain: "example.com",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseSPFResult(tt.part)

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
		})
	}
}

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

func TestParseDMARCResult(t *testing.T) {
	tests := []struct {
		name           string
		part           string
		expectedResult api.AuthResultResult
		expectedDomain string
	}{
		{
			name:           "DMARC pass",
			part:           "dmarc=pass action=none header.from=example.com",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: "example.com",
		},
		{
			name:           "DMARC fail",
			part:           "dmarc=fail action=quarantine header.from=example.com",
			expectedResult: api.AuthResultResultFail,
			expectedDomain: "example.com",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseDMARCResult(tt.part)

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
		})
	}
}

func TestParseBIMIResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   api.AuthResultResult
		expectedDomain   string
		expectedSelector string
	}{
		{
			name:             "BIMI pass with domain and selector",
			part:             "bimi=pass header.d=example.com header.selector=default",
			expectedResult:   api.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
		{
			name:             "BIMI fail",
			part:             "bimi=fail header.d=example.com header.selector=default",
			expectedResult:   api.AuthResultResultFail,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
		{
			name:             "BIMI with short form (d= and selector=)",
			part:             "bimi=pass d=example.com selector=v1",
			expectedResult:   api.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "v1",
		},
		{
			name:           "BIMI none",
			part:           "bimi=none header.d=example.com",
			expectedResult: api.AuthResultResultNone,
			expectedDomain: "example.com",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseBIMIResult(tt.part)

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
			if tt.expectedSelector != "" {
				if result.Selector == nil || *result.Selector != tt.expectedSelector {
					var gotSelector string
					if result.Selector != nil {
						gotSelector = *result.Selector
					}
					t.Errorf("Selector = %v, want %v", gotSelector, tt.expectedSelector)
				}
			}
		})
	}
}

func TestGetAuthenticationScore(t *testing.T) {
	tests := []struct {
		name          string
		results       *api.AuthenticationResults
		expectedScore int
	}{
		{
			name: "Perfect authentication (SPF + DKIM + DMARC)",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
				Dkim: &[]api.AuthResult{
					{Result: api.AuthResultResultPass},
				},
				Dmarc: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
			},
			expectedScore: 30,
		},
		{
			name: "SPF and DKIM only",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
				Dkim: &[]api.AuthResult{
					{Result: api.AuthResultResultPass},
				},
			},
			expectedScore: 20,
		},
		{
			name: "SPF fail, DKIM pass",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultFail,
				},
				Dkim: &[]api.AuthResult{
					{Result: api.AuthResultResultPass},
				},
			},
			expectedScore: 10,
		},
		{
			name: "SPF softfail",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultSoftfail,
				},
			},
			expectedScore: 5,
		},
		{
			name:          "No authentication",
			results:       &api.AuthenticationResults{},
			expectedScore: 0,
		},
		{
			name: "BIMI doesn't affect score",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
				Bimi: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
			},
			expectedScore: 10, // Only SPF counted, not BIMI
		},
	}

	scorer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scorer.CalculateAuthenticationScore(tt.results)

			if score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}

func TestParseARCResult(t *testing.T) {
	tests := []struct {
		name           string
		part           string
		expectedResult api.ARCResultResult
	}{
		{
			name:           "ARC pass",
			part:           "arc=pass",
			expectedResult: api.ARCResultResultPass,
		},
		{
			name:           "ARC fail",
			part:           "arc=fail",
			expectedResult: api.ARCResultResultFail,
		},
		{
			name:           "ARC none",
			part:           "arc=none",
			expectedResult: api.ARCResultResultNone,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseARCResult(tt.part)

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}
		})
	}
}

func TestValidateARCChain(t *testing.T) {
	tests := []struct {
		name           string
		arcAuthResults []string
		arcMessageSig  []string
		arcSeal        []string
		expectedValid  bool
	}{
		{
			name:           "Empty chain is valid",
			arcAuthResults: []string{},
			arcMessageSig:  []string{},
			arcSeal:        []string{},
			expectedValid:  true,
		},
		{
			name: "Valid chain with single hop",
			arcAuthResults: []string{
				"i=1; example.com; spf=pass",
			},
			arcMessageSig: []string{
				"i=1; a=rsa-sha256; d=example.com",
			},
			arcSeal: []string{
				"i=1; a=rsa-sha256; s=arc; d=example.com",
			},
			expectedValid: true,
		},
		{
			name: "Valid chain with two hops",
			arcAuthResults: []string{
				"i=1; example.com; spf=pass",
				"i=2; relay.com; arc=pass",
			},
			arcMessageSig: []string{
				"i=1; a=rsa-sha256; d=example.com",
				"i=2; a=rsa-sha256; d=relay.com",
			},
			arcSeal: []string{
				"i=1; a=rsa-sha256; s=arc; d=example.com",
				"i=2; a=rsa-sha256; s=arc; d=relay.com",
			},
			expectedValid: true,
		},
		{
			name: "Invalid chain - missing one header type",
			arcAuthResults: []string{
				"i=1; example.com; spf=pass",
			},
			arcMessageSig: []string{
				"i=1; a=rsa-sha256; d=example.com",
			},
			arcSeal:       []string{},
			expectedValid: false,
		},
		{
			name: "Invalid chain - non-sequential instances",
			arcAuthResults: []string{
				"i=1; example.com; spf=pass",
				"i=3; relay.com; arc=pass",
			},
			arcMessageSig: []string{
				"i=1; a=rsa-sha256; d=example.com",
				"i=3; a=rsa-sha256; d=relay.com",
			},
			arcSeal: []string{
				"i=1; a=rsa-sha256; s=arc; d=example.com",
				"i=3; a=rsa-sha256; s=arc; d=relay.com",
			},
			expectedValid: false,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := analyzer.validateARCChain(tt.arcAuthResults, tt.arcMessageSig, tt.arcSeal)

			if valid != tt.expectedValid {
				t.Errorf("validateARCChain() = %v, want %v", valid, tt.expectedValid)
			}
		})
	}
}
