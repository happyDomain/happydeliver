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
