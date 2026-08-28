// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

package bimi

import (
	"strings"
	"testing"
)

const validTinyPSSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40" fill="#123456"/>
</svg>`

func TestCheckLogoXML(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedStatus CheckStatus
		expectedInMsg  string
	}{
		{
			name:           "Well-formed SVG",
			content:        validTinyPSSVG,
			expectedStatus: StatusPass,
		},
		{
			name:           "Unclosed element",
			content:        `<svg xmlns="http://www.w3.org/2000/svg"><title>x</title>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "not well-formed",
		},
		{
			name:           "Mismatched tags",
			content:        `<svg><title>x</circle></svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "line 1",
		},
		{
			name:           "Not XML at all",
			content:        `PNG binary content`,
			expectedStatus: StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := CheckLogoXML([]byte(tt.content))
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s", check.Status, tt.expectedStatus)
			}
			if tt.expectedInMsg != "" {
				if !strings.Contains(strings.Join(check.MessageTexts(), " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}
