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
