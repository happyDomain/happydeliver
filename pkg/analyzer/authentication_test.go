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
			expectedScore: 75, // SPF=25 + DKIM=25 + DMARC=25
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
			expectedScore: 50, // SPF=25 + DKIM=25
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
			expectedScore: 25, // SPF=0 + DKIM=25
		},
		{
			name: "SPF softfail",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultSoftfail,
				},
			},
			expectedScore: 4,
		},
		{
			name:          "No authentication",
			results:       &api.AuthenticationResults{},
			expectedScore: 0,
		},
		{
			name: "BIMI adds to score",
			results: &api.AuthenticationResults{
				Spf: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
				Bimi: &api.AuthResult{
					Result: api.AuthResultResultPass,
				},
			},
			expectedScore: 35, // SPF (25) + BIMI (10)
		},
	}

	scorer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _ := scorer.CalculateAuthenticationScore(tt.results)

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

func TestParseAuthenticationResultsHeader(t *testing.T) {
	tests := []struct {
		name                string
		header              string
		expectedSPFResult   *api.AuthResultResult
		expectedSPFDomain   *string
		expectedDKIMCount   int
		expectedDKIMResult  *api.AuthResultResult
		expectedDMARCResult *api.AuthResultResult
		expectedDMARCDomain *string
		expectedBIMIResult  *api.AuthResultResult
		expectedARCResult   *api.ARCResultResult
	}{
		{
			name:                "Complete authentication results",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com header.s=default; dmarc=pass action=none header.from=example.com",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultPass),
			expectedSPFDomain:   api.PtrTo("example.com"),
			expectedDKIMCount:   1,
			expectedDKIMResult:  api.PtrTo(api.AuthResultResultPass),
			expectedDMARCResult: api.PtrTo(api.AuthResultResultPass),
			expectedDMARCDomain: api.PtrTo("example.com"),
		},
		{
			name:                "SPF only",
			header:              "mail.example.com; spf=pass smtp.mailfrom=user@domain.com",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultPass),
			expectedSPFDomain:   api.PtrTo("domain.com"),
			expectedDKIMCount:   0,
			expectedDMARCResult: nil,
		},
		{
			name:               "DKIM only",
			header:             "mail.example.com; dkim=pass header.d=example.com header.s=selector1",
			expectedSPFResult:  nil,
			expectedDKIMCount:  1,
			expectedDKIMResult: api.PtrTo(api.AuthResultResultPass),
		},
		{
			name:                "Multiple DKIM signatures",
			header:              "mail.example.com; dkim=pass header.d=example.com header.s=s1; dkim=pass header.d=example.com header.s=s2",
			expectedSPFResult:   nil,
			expectedDKIMCount:   2,
			expectedDKIMResult:  api.PtrTo(api.AuthResultResultPass),
			expectedDMARCResult: nil,
		},
		{
			name:                "SPF fail with DKIM pass",
			header:              "mail.example.com; spf=fail smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com header.s=default",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultFail),
			expectedSPFDomain:   api.PtrTo("example.com"),
			expectedDKIMCount:   1,
			expectedDKIMResult:  api.PtrTo(api.AuthResultResultPass),
			expectedDMARCResult: nil,
		},
		{
			name:                "SPF softfail",
			header:              "mail.example.com; spf=softfail smtp.mailfrom=sender@example.com",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultSoftfail),
			expectedSPFDomain:   api.PtrTo("example.com"),
			expectedDKIMCount:   0,
			expectedDMARCResult: nil,
		},
		{
			name:                "DMARC fail",
			header:              "mail.example.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com header.s=default; dmarc=fail action=quarantine header.from=example.com",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultPass),
			expectedDKIMCount:   1,
			expectedDKIMResult:  api.PtrTo(api.AuthResultResultPass),
			expectedDMARCResult: api.PtrTo(api.AuthResultResultFail),
			expectedDMARCDomain: api.PtrTo("example.com"),
		},
		{
			name:               "BIMI pass",
			header:             "mail.example.com; spf=pass smtp.mailfrom=sender@example.com; bimi=pass header.d=example.com header.selector=default",
			expectedSPFResult:  api.PtrTo(api.AuthResultResultPass),
			expectedSPFDomain:  api.PtrTo("example.com"),
			expectedDKIMCount:  0,
			expectedBIMIResult: api.PtrTo(api.AuthResultResultPass),
		},
		{
			name:              "ARC pass",
			header:            "mail.example.com; arc=pass",
			expectedSPFResult: nil,
			expectedDKIMCount: 0,
			expectedARCResult: api.PtrTo(api.ARCResultResultPass),
		},
		{
			name:                "All authentication methods",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com header.s=default; dmarc=pass action=none header.from=example.com; bimi=pass header.d=example.com header.selector=v1; arc=pass",
			expectedSPFResult:   api.PtrTo(api.AuthResultResultPass),
			expectedSPFDomain:   api.PtrTo("example.com"),
			expectedDKIMCount:   1,
			expectedDKIMResult:  api.PtrTo(api.AuthResultResultPass),
			expectedDMARCResult: api.PtrTo(api.AuthResultResultPass),
			expectedDMARCDomain: api.PtrTo("example.com"),
			expectedBIMIResult:  api.PtrTo(api.AuthResultResultPass),
			expectedARCResult:   api.PtrTo(api.ARCResultResultPass),
		},
		{
			name:              "Empty header (authserv-id only)",
			header:            "mx.google.com",
			expectedSPFResult: nil,
			expectedDKIMCount: 0,
		},
		{
			name:              "Empty parts with semicolons",
			header:            "mx.google.com; ; ; spf=pass smtp.mailfrom=sender@example.com; ;",
			expectedSPFResult: api.PtrTo(api.AuthResultResultPass),
			expectedSPFDomain: api.PtrTo("example.com"),
			expectedDKIMCount: 0,
		},
		{
			name:               "DKIM with short form parameters",
			header:             "mail.example.com; dkim=pass d=example.com s=selector1",
			expectedSPFResult:  nil,
			expectedDKIMCount:  1,
			expectedDKIMResult: api.PtrTo(api.AuthResultResultPass),
		},
		{
			name:              "SPF neutral",
			header:            "mail.example.com; spf=neutral smtp.mailfrom=sender@example.com",
			expectedSPFResult: api.PtrTo(api.AuthResultResultNeutral),
			expectedSPFDomain: api.PtrTo("example.com"),
			expectedDKIMCount: 0,
		},
		{
			name:              "SPF none",
			header:            "mail.example.com; spf=none",
			expectedSPFResult: api.PtrTo(api.AuthResultResultNone),
			expectedDKIMCount: 0,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &api.AuthenticationResults{}
			analyzer.parseAuthenticationResultsHeader(tt.header, results)

			// Check SPF
			if tt.expectedSPFResult != nil {
				if results.Spf == nil {
					t.Errorf("Expected SPF result, got nil")
				} else {
					if results.Spf.Result != *tt.expectedSPFResult {
						t.Errorf("SPF Result = %v, want %v", results.Spf.Result, *tt.expectedSPFResult)
					}
					if tt.expectedSPFDomain != nil {
						if results.Spf.Domain == nil || *results.Spf.Domain != *tt.expectedSPFDomain {
							var gotDomain string
							if results.Spf.Domain != nil {
								gotDomain = *results.Spf.Domain
							}
							t.Errorf("SPF Domain = %v, want %v", gotDomain, *tt.expectedSPFDomain)
						}
					}
				}
			} else {
				if results.Spf != nil {
					t.Errorf("Expected no SPF result, got %+v", results.Spf)
				}
			}

			// Check DKIM count and result
			if results.Dkim == nil {
				if tt.expectedDKIMCount != 0 {
					t.Errorf("Expected %d DKIM results, got nil", tt.expectedDKIMCount)
				}
			} else {
				if len(*results.Dkim) != tt.expectedDKIMCount {
					t.Errorf("DKIM count = %d, want %d", len(*results.Dkim), tt.expectedDKIMCount)
				}
				if tt.expectedDKIMResult != nil && len(*results.Dkim) > 0 {
					if (*results.Dkim)[0].Result != *tt.expectedDKIMResult {
						t.Errorf("DKIM Result = %v, want %v", (*results.Dkim)[0].Result, *tt.expectedDKIMResult)
					}
				}
			}

			// Check DMARC
			if tt.expectedDMARCResult != nil {
				if results.Dmarc == nil {
					t.Errorf("Expected DMARC result, got nil")
				} else {
					if results.Dmarc.Result != *tt.expectedDMARCResult {
						t.Errorf("DMARC Result = %v, want %v", results.Dmarc.Result, *tt.expectedDMARCResult)
					}
					if tt.expectedDMARCDomain != nil {
						if results.Dmarc.Domain == nil || *results.Dmarc.Domain != *tt.expectedDMARCDomain {
							var gotDomain string
							if results.Dmarc.Domain != nil {
								gotDomain = *results.Dmarc.Domain
							}
							t.Errorf("DMARC Domain = %v, want %v", gotDomain, *tt.expectedDMARCDomain)
						}
					}
				}
			} else {
				if results.Dmarc != nil {
					t.Errorf("Expected no DMARC result, got %+v", results.Dmarc)
				}
			}

			// Check BIMI
			if tt.expectedBIMIResult != nil {
				if results.Bimi == nil {
					t.Errorf("Expected BIMI result, got nil")
				} else {
					if results.Bimi.Result != *tt.expectedBIMIResult {
						t.Errorf("BIMI Result = %v, want %v", results.Bimi.Result, *tt.expectedBIMIResult)
					}
				}
			} else {
				if results.Bimi != nil {
					t.Errorf("Expected no BIMI result, got %+v", results.Bimi)
				}
			}

			// Check ARC
			if tt.expectedARCResult != nil {
				if results.Arc == nil {
					t.Errorf("Expected ARC result, got nil")
				} else {
					if results.Arc.Result != *tt.expectedARCResult {
						t.Errorf("ARC Result = %v, want %v", results.Arc.Result, *tt.expectedARCResult)
					}
				}
			} else {
				if results.Arc != nil {
					t.Errorf("Expected no ARC result, got %+v", results.Arc)
				}
			}
		})
	}
}

func TestParseAuthenticationResultsHeader_OnlyFirstResultParsed(t *testing.T) {
	// This test verifies that only the first occurrence of each auth method is parsed
	analyzer := NewAuthenticationAnalyzer()

	t.Run("Multiple SPF results - only first is parsed", func(t *testing.T) {
		header := "mail.example.com; spf=pass smtp.mailfrom=first@example.com; spf=fail smtp.mailfrom=second@example.com"
		results := &api.AuthenticationResults{}
		analyzer.parseAuthenticationResultsHeader(header, results)

		if results.Spf == nil {
			t.Fatal("Expected SPF result, got nil")
		}
		if results.Spf.Result != api.AuthResultResultPass {
			t.Errorf("Expected first SPF result (pass), got %v", results.Spf.Result)
		}
		if results.Spf.Domain == nil || *results.Spf.Domain != "example.com" {
			t.Errorf("Expected domain from first SPF result")
		}
	})

	t.Run("Multiple DMARC results - only first is parsed", func(t *testing.T) {
		header := "mail.example.com; dmarc=pass header.from=first.com; dmarc=fail header.from=second.com"
		results := &api.AuthenticationResults{}
		analyzer.parseAuthenticationResultsHeader(header, results)

		if results.Dmarc == nil {
			t.Fatal("Expected DMARC result, got nil")
		}
		if results.Dmarc.Result != api.AuthResultResultPass {
			t.Errorf("Expected first DMARC result (pass), got %v", results.Dmarc.Result)
		}
		if results.Dmarc.Domain == nil || *results.Dmarc.Domain != "first.com" {
			t.Errorf("Expected domain from first DMARC result")
		}
	})

	t.Run("Multiple ARC results - only first is parsed", func(t *testing.T) {
		header := "mail.example.com; arc=pass; arc=fail"
		results := &api.AuthenticationResults{}
		analyzer.parseAuthenticationResultsHeader(header, results)

		if results.Arc == nil {
			t.Fatal("Expected ARC result, got nil")
		}
		if results.Arc.Result != api.ARCResultResultPass {
			t.Errorf("Expected first ARC result (pass), got %v", results.Arc.Result)
		}
	})

	t.Run("Multiple BIMI results - only first is parsed", func(t *testing.T) {
		header := "mail.example.com; bimi=pass header.d=first.com; bimi=fail header.d=second.com"
		results := &api.AuthenticationResults{}
		analyzer.parseAuthenticationResultsHeader(header, results)

		if results.Bimi == nil {
			t.Fatal("Expected BIMI result, got nil")
		}
		if results.Bimi.Result != api.AuthResultResultPass {
			t.Errorf("Expected first BIMI result (pass), got %v", results.Bimi.Result)
		}
		if results.Bimi.Domain == nil || *results.Bimi.Domain != "first.com" {
			t.Errorf("Expected domain from first BIMI result")
		}
	})

	t.Run("Multiple DKIM results - all are parsed", func(t *testing.T) {
		// DKIM is special - multiple signatures should all be collected
		header := "mail.example.com; dkim=pass header.d=first.com header.s=s1; dkim=fail header.d=second.com header.s=s2"
		results := &api.AuthenticationResults{}
		analyzer.parseAuthenticationResultsHeader(header, results)

		if results.Dkim == nil {
			t.Fatal("Expected DKIM results, got nil")
		}
		if len(*results.Dkim) != 2 {
			t.Errorf("Expected 2 DKIM results, got %d", len(*results.Dkim))
		}
		if (*results.Dkim)[0].Result != api.AuthResultResultPass {
			t.Errorf("Expected first DKIM result to be pass, got %v", (*results.Dkim)[0].Result)
		}
		if (*results.Dkim)[1].Result != api.AuthResultResultFail {
			t.Errorf("Expected second DKIM result to be fail, got %v", (*results.Dkim)[1].Result)
		}
	})
}

func TestParseLegacySPF(t *testing.T) {
	tests := []struct {
		name           string
		receivedSPF    string
		expectedResult api.AuthResultResult
		expectedDomain *string
		expectNil      bool
	}{
		{
			name: "SPF pass with envelope-from",
			receivedSPF: `pass
    (mail.example.com: 192.0.2.10 is authorized to use 'user@example.com' in 'mfrom' identity (mechanism 'ip4:192.0.2.10' matched))
    receiver=mx.receiver.com;
    identity=mailfrom;
    envelope-from="user@example.com";
    helo=smtp.example.com;
    client-ip=192.0.2.10`,
			expectedResult: api.AuthResultResultPass,
			expectedDomain: api.PtrTo("example.com"),
		},
		{
			name: "SPF fail with sender",
			receivedSPF: `fail
    (mail.example.com: domain of sender@test.com does not designate 192.0.2.20 as permitted sender)
    receiver=mx.receiver.com;
    identity=mailfrom;
    sender="sender@test.com";
    helo=smtp.test.com;
    client-ip=192.0.2.20`,
			expectedResult: api.AuthResultResultFail,
			expectedDomain: api.PtrTo("test.com"),
		},
		{
			name:           "SPF softfail",
			receivedSPF:    "softfail (example.com: transitioning domain of admin@example.org does not designate 192.0.2.30 as permitted sender) envelope-from=\"admin@example.org\"",
			expectedResult: api.AuthResultResultSoftfail,
			expectedDomain: api.PtrTo("example.org"),
		},
		{
			name:           "SPF neutral",
			receivedSPF:    "neutral (example.com: 192.0.2.40 is neither permitted nor denied by domain of info@domain.net) envelope-from=\"info@domain.net\"",
			expectedResult: api.AuthResultResultNeutral,
			expectedDomain: api.PtrTo("domain.net"),
		},
		{
			name:           "SPF none",
			receivedSPF:    "none (example.com: domain of noreply@company.io has no SPF record) envelope-from=\"noreply@company.io\"",
			expectedResult: api.AuthResultResultNone,
			expectedDomain: api.PtrTo("company.io"),
		},
		{
			name:           "SPF temperror",
			receivedSPF:    "temperror (example.com: error in processing SPF record) envelope-from=\"support@shop.example\"",
			expectedResult: api.AuthResultResultTemperror,
			expectedDomain: api.PtrTo("shop.example"),
		},
		{
			name:           "SPF permerror",
			receivedSPF:    "permerror (example.com: domain of contact@invalid.test has invalid SPF record) envelope-from=\"contact@invalid.test\"",
			expectedResult: api.AuthResultResultPermerror,
			expectedDomain: api.PtrTo("invalid.test"),
		},
		{
			name:           "SPF pass without domain extraction",
			receivedSPF:    "pass (example.com: 192.0.2.50 is authorized)",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: nil,
		},
		{
			name:        "Empty Received-SPF header",
			receivedSPF: "",
			expectNil:   true,
		},
		{
			name:           "SPF with unquoted envelope-from",
			receivedSPF:    "pass (example.com: sender SPF authorized) envelope-from=postmaster@mail.example.net",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: api.PtrTo("mail.example.net"),
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock email message with Received-SPF header
			email := &EmailMessage{
				Header: make(map[string][]string),
			}
			if tt.receivedSPF != "" {
				email.Header["Received-Spf"] = []string{tt.receivedSPF}
			}

			result := analyzer.parseLegacySPF(email)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result, got nil")
			}

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}

			if tt.expectedDomain != nil {
				if result.Domain == nil {
					t.Errorf("Domain = nil, want %v", *tt.expectedDomain)
				} else if *result.Domain != *tt.expectedDomain {
					t.Errorf("Domain = %v, want %v", *result.Domain, *tt.expectedDomain)
				}
			} else {
				if result.Domain != nil {
					t.Errorf("Domain = %v, want nil", *result.Domain)
				}
			}

			if result.Details == nil {
				t.Error("Expected Details to be set, got nil")
			} else if *result.Details != tt.receivedSPF {
				t.Errorf("Details = %v, want %v", *result.Details, tt.receivedSPF)
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

func TestParseIPRevResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   api.IPRevResultResult
		expectedIP       *string
		expectedHostname *string
	}{
		{
			name:             "IPRev pass with IP and hostname",
			part:             "iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("195.110.101.58"),
			expectedHostname: api.PtrTo("authsmtp74.register.it"),
		},
		{
			name:             "IPRev pass without smtp prefix",
			part:             "iprev=pass remote-ip=192.0.2.1 (mail.example.com)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.1"),
			expectedHostname: api.PtrTo("mail.example.com"),
		},
		{
			name:             "IPRev fail",
			part:             "iprev=fail smtp.remote-ip=198.51.100.42 (unknown.host.com)",
			expectedResult:   api.Fail,
			expectedIP:       api.PtrTo("198.51.100.42"),
			expectedHostname: api.PtrTo("unknown.host.com"),
		},
		{
			name:             "IPRev temperror",
			part:             "iprev=temperror smtp.remote-ip=203.0.113.1",
			expectedResult:   api.Temperror,
			expectedIP:       api.PtrTo("203.0.113.1"),
			expectedHostname: nil,
		},
		{
			name:             "IPRev permerror",
			part:             "iprev=permerror smtp.remote-ip=192.0.2.100",
			expectedResult:   api.Permerror,
			expectedIP:       api.PtrTo("192.0.2.100"),
			expectedHostname: nil,
		},
		{
			name:           "IPRev with IPv6",
			part:           "iprev=pass smtp.remote-ip=2001:db8::1 (ipv6.example.com)",
			expectedResult: api.Pass,
			expectedIP:     api.PtrTo("2001:db8::1"),
			expectedHostname: api.PtrTo("ipv6.example.com"),
		},
		{
			name:             "IPRev with subdomain hostname",
			part:             "iprev=pass smtp.remote-ip=192.0.2.50 (mail.subdomain.example.com)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.50"),
			expectedHostname: api.PtrTo("mail.subdomain.example.com"),
		},
		{
			name:             "IPRev pass without parentheses",
			part:             "iprev=pass smtp.remote-ip=192.0.2.200",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.200"),
			expectedHostname: nil,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseIPRevResult(tt.part)

			// Check result
			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}

			// Check IP
			if tt.expectedIP != nil {
				if result.Ip == nil {
					t.Errorf("IP = nil, want %v", *tt.expectedIP)
				} else if *result.Ip != *tt.expectedIP {
					t.Errorf("IP = %v, want %v", *result.Ip, *tt.expectedIP)
				}
			} else {
				if result.Ip != nil {
					t.Errorf("IP = %v, want nil", *result.Ip)
				}
			}

			// Check hostname
			if tt.expectedHostname != nil {
				if result.Hostname == nil {
					t.Errorf("Hostname = nil, want %v", *tt.expectedHostname)
				} else if *result.Hostname != *tt.expectedHostname {
					t.Errorf("Hostname = %v, want %v", *result.Hostname, *tt.expectedHostname)
				}
			} else {
				if result.Hostname != nil {
					t.Errorf("Hostname = %v, want nil", *result.Hostname)
				}
			}

			// Check details
			if result.Details == nil {
				t.Error("Expected Details to be set, got nil")
			}
		})
	}
}

func TestParseXGoogleDKIMResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   api.AuthResultResult
		expectedDomain   string
		expectedSelector string
	}{
		{
			name:           "x-google-dkim pass with domain",
			part:           "x-google-dkim=pass (2048-bit rsa key) header.d=1e100.net header.i=@1e100.net header.b=fauiPVZ6",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: "1e100.net",
		},
		{
			name:           "x-google-dkim pass with short form",
			part:           "x-google-dkim=pass d=gmail.com",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: "gmail.com",
		},
		{
			name:           "x-google-dkim fail",
			part:           "x-google-dkim=fail header.d=example.com",
			expectedResult: api.AuthResultResultFail,
			expectedDomain: "example.com",
		},
		{
			name:           "x-google-dkim with minimal info",
			part:           "x-google-dkim=pass",
			expectedResult: api.AuthResultResultPass,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseXGoogleDKIMResult(tt.part)

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}
			if tt.expectedDomain != "" {
				if result.Domain == nil || *result.Domain != tt.expectedDomain {
					var gotDomain string
					if result.Domain != nil {
						gotDomain = *result.Domain
					}
					t.Errorf("Domain = %v, want %v", gotDomain, tt.expectedDomain)
				}
			}
		})
	}
}

func TestParseAuthenticationResultsHeader_IPRev(t *testing.T) {
	tests := []struct {
		name              string
		header            string
		expectedIPRevResult *api.IPRevResultResult
		expectedIP        *string
		expectedHostname  *string
	}{
		{
			name:                "IPRev pass in Authentication-Results",
			header:              "mx.google.com; iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("195.110.101.58"),
			expectedHostname:    api.PtrTo("authsmtp74.register.it"),
		},
		{
			name:                "IPRev with other authentication methods",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com; iprev=pass smtp.remote-ip=192.0.2.1 (mail.example.com); dkim=pass header.d=example.com",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("192.0.2.1"),
			expectedHostname:    api.PtrTo("mail.example.com"),
		},
		{
			name:                "IPRev fail",
			header:              "mx.google.com; iprev=fail smtp.remote-ip=198.51.100.42",
			expectedIPRevResult: api.PtrTo(api.Fail),
			expectedIP:          api.PtrTo("198.51.100.42"),
			expectedHostname:    nil,
		},
		{
			name:                "No IPRev in header",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com",
			expectedIPRevResult: nil,
		},
		{
			name:                "Multiple IPRev results - only first is parsed",
			header:              "mx.google.com; iprev=pass smtp.remote-ip=192.0.2.1 (first.com); iprev=fail smtp.remote-ip=192.0.2.2 (second.com)",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("192.0.2.1"),
			expectedHostname:    api.PtrTo("first.com"),
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &api.AuthenticationResults{}
			analyzer.parseAuthenticationResultsHeader(tt.header, results)

			// Check IPRev
			if tt.expectedIPRevResult != nil {
				if results.Iprev == nil {
					t.Errorf("Expected IPRev result, got nil")
				} else {
					if results.Iprev.Result != *tt.expectedIPRevResult {
						t.Errorf("IPRev Result = %v, want %v", results.Iprev.Result, *tt.expectedIPRevResult)
					}
					if tt.expectedIP != nil {
						if results.Iprev.Ip == nil || *results.Iprev.Ip != *tt.expectedIP {
							var gotIP string
							if results.Iprev.Ip != nil {
								gotIP = *results.Iprev.Ip
							}
							t.Errorf("IPRev IP = %v, want %v", gotIP, *tt.expectedIP)
						}
					}
					if tt.expectedHostname != nil {
						if results.Iprev.Hostname == nil || *results.Iprev.Hostname != *tt.expectedHostname {
							var gotHostname string
							if results.Iprev.Hostname != nil {
								gotHostname = *results.Iprev.Hostname
							}
							t.Errorf("IPRev Hostname = %v, want %v", gotHostname, *tt.expectedHostname)
						}
					}
				}
			} else {
				if results.Iprev != nil {
					t.Errorf("Expected no IPRev result, got %+v", results.Iprev)
				}
			}
		})
	}
}
