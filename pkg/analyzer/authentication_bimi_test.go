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
