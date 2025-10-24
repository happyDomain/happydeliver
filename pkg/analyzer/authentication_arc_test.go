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
