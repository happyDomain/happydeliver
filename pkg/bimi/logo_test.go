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
				if !strings.Contains(strings.Join(check.Messages, " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}

func TestCheckLogoSVGTinyPS(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		expectedStatus CheckStatus
		expectedInMsg  string
	}{
		{
			name:           "Valid SVG Tiny P/S",
			content:        validTinyPSSVG,
			expectedStatus: StatusPass,
		},
		{
			name: "Missing baseProfile",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "baseProfile",
		},
		{
			name: "Wrong baseProfile",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  `baseProfile="tiny-ps"`,
		},
		{
			name: "Missing version",
			content: `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  `version="1.2"`,
		},
		{
			name: "Missing title",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <circle cx="50" cy="50" r="40"/>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "<title>",
		},
		{
			name: "Script element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <script>alert(1)</script>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "scripting",
		},
		{
			name: "Animation element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40"><animate attributeName="r" from="40" to="10" dur="1s"/></circle>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "animation",
		},
		{
			name: "Image element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <image href="https://example.com/photo.png" width="10" height="10"/>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "image",
		},
		{
			name: "Event attribute",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40" onclick="alert(1)"/>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "onclick",
		},
		{
			name: "External reference",
			content: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <use xlink:href="https://example.com/shape.svg#circle"/>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "External reference",
		},
		{
			name: "Local reference is allowed",
			content: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <defs><circle id="c" cx="50" cy="50" r="40"/></defs>
  <use xlink:href="#c"/>
</svg>`,
			expectedStatus: StatusPass,
		},
		{
			name: "x/y on root element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" x="10" y="10">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "must not have",
		},
		{
			name: "DOCTYPE declaration",
			content: `<?xml version="1.0"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  "DOCTYPE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := CheckLogoSVGTinyPS([]byte(tt.content))
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s (messages: %v)", check.Status, tt.expectedStatus, check.Messages)
			}
			if tt.expectedInMsg != "" {
				if !strings.Contains(strings.Join(check.Messages, " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}
