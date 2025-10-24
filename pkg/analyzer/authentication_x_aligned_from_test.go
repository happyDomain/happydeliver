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

func TestParseXAlignedFromResult(t *testing.T) {
	tests := []struct {
		name           string
		part           string
		expectedResult api.AuthResultResult
		expectedDetail string
	}{
		{
			name:           "x-aligned-from pass with details",
			part:           "x-aligned-from=pass (Address match)",
			expectedResult: api.AuthResultResultPass,
			expectedDetail: "pass (Address match)",
		},
		{
			name:           "x-aligned-from fail with reason",
			part:           "x-aligned-from=fail (Address mismatch)",
			expectedResult: api.AuthResultResultFail,
			expectedDetail: "fail (Address mismatch)",
		},
		{
			name:           "x-aligned-from pass minimal",
			part:           "x-aligned-from=pass",
			expectedResult: api.AuthResultResultPass,
			expectedDetail: "pass",
		},
		{
			name:           "x-aligned-from neutral",
			part:           "x-aligned-from=neutral (No alignment check performed)",
			expectedResult: api.AuthResultResultNeutral,
			expectedDetail: "neutral (No alignment check performed)",
		},
		{
			name:           "x-aligned-from none",
			part:           "x-aligned-from=none",
			expectedResult: api.AuthResultResultNone,
			expectedDetail: "none",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseXAlignedFromResult(tt.part)

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}

			if result.Details == nil {
				t.Errorf("Details = nil, want %v", tt.expectedDetail)
			} else if *result.Details != tt.expectedDetail {
				t.Errorf("Details = %v, want %v", *result.Details, tt.expectedDetail)
			}
		})
	}
}

func TestCalculateXAlignedFromScore(t *testing.T) {
	tests := []struct {
		name          string
		result        *api.AuthResult
		expectedScore int
	}{
		{
			name: "pass result gives positive score",
			result: &api.AuthResult{
				Result: api.AuthResultResultPass,
			},
			expectedScore: 100,
		},
		{
			name: "fail result gives zero score",
			result: &api.AuthResult{
				Result: api.AuthResultResultFail,
			},
			expectedScore: 0,
		},
		{
			name: "neutral result gives zero score",
			result: &api.AuthResult{
				Result: api.AuthResultResultNeutral,
			},
			expectedScore: 0,
		},
		{
			name: "none result gives zero score",
			result: &api.AuthResult{
				Result: api.AuthResultResultNone,
			},
			expectedScore: 0,
		},
		{
			name:          "nil result gives zero score",
			result:        nil,
			expectedScore: 0,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &api.AuthenticationResults{
				XAlignedFrom: tt.result,
			}

			score := analyzer.calculateXAlignedFromScore(results)

			if score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}
