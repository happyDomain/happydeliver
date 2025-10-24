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
			expectedScore: 73, // SPF=25 + DKIM=23 + DMARC=25
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
			expectedScore: 48, // SPF=25 + DKIM=23
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
			expectedScore: 23, // SPF=0 + DKIM=23
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
