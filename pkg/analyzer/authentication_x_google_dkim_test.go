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

	"git.happydns.org/happyDeliver/internal/model"
)

func TestParseXGoogleDKIMResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   model.AuthResultResult
		expectedDomain   string
		expectedSelector string
	}{
		{
			name:           "x-google-dkim pass with domain",
			part:           "x-google-dkim=pass (2048-bit rsa key) header.d=1e100.net header.i=@1e100.net header.b=fauiPVZ6",
			expectedResult: model.AuthResultResultPass,
			expectedDomain: "1e100.net",
		},
		{
			name:           "x-google-dkim pass with short form",
			part:           "x-google-dkim=pass d=gmail.com",
			expectedResult: model.AuthResultResultPass,
			expectedDomain: "gmail.com",
		},
		{
			name:           "x-google-dkim fail",
			part:           "x-google-dkim=fail header.d=example.com",
			expectedResult: model.AuthResultResultFail,
			expectedDomain: "example.com",
		},
		{
			name:           "x-google-dkim with minimal info",
			part:           "x-google-dkim=pass",
			expectedResult: model.AuthResultResultPass,
		},
	}

	analyzer := NewAuthenticationAnalyzer("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseXGoogleDKIMResult(readMethod(t, tt.part))

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

// Only a signature that fails or cannot be evaluated costs points: Google
// reporting nothing about its own signature says nothing of the message.
func TestCalculateXGoogleDKIMScore(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	for result, want := range map[model.AuthResultResult]int{
		model.AuthResultResultPass:      0,
		model.AuthResultResultFail:      -100,
		model.AuthResultResultPermerror: -100,
		model.AuthResultResultNone:      0,
		model.AuthResultResultNeutral:   0,
		model.AuthResultResultTemperror: 0,
	} {
		results := &model.AuthenticationResults{
			Spf:         &model.AuthResult{Result: model.AuthResultResultPass},
			XGoogleDkim: &model.AuthResult{Result: result},
		}
		if got := a.calculateXGoogleDKIMScore(results); got != want {
			t.Errorf("calculateXGoogleDKIMScore(%s) = %d, want %d", result, got, want)
		}

		a.ReportIssues(results, nil, model.ReportSourceUploaded)
		if issues := *results.Issues.XGoogleDkim; (len(issues) > 0) != (want != 0) {
			t.Errorf("%s: issues = %v, want one only when it costs points", result, issues)
		}
	}
}
