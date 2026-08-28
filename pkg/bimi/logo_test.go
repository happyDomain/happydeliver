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
	"fmt"
	"strings"
	"testing"
)

// validTinyPSSVG is a fully compliant logo. It paints in two colours because
// the profile requires at least two.
const validTinyPSSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Example Corp</title>
  <circle cx="50" cy="50" r="40" fill="#123456"/>
  <rect x="10" y="10" width="20" height="20" fill="#abcdef"/>
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
		{
			// encoding/xml reads UTF-8 only; the check has to say
			// which encoding it turned away, not how it is built.
			name:           "Encoding other than UTF-8",
			content:        `<?xml version="1.0" encoding="ISO-8859-1"?><svg xmlns="http://www.w3.org/2000/svg"><title>x</title></svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  `"ISO-8859-1"`,
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

// TestCheckLogoSVGTinyPS covers the translation from a profile problem to an
// evidence check. The profile rules themselves are exercised exhaustively in
// pkg/bimi/svgps; what matters here is the status, the severity of each message
// and the way a problem is rendered.
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
			expectedInMsg:  `baseProfile="tiny"`,
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
			expectedInMsg:  "only references inside the document",
		},
		{
			name: "Local reference is allowed",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>Example Corp</title>
  <defs><circle id="c" cx="50" cy="50" r="40" fill="#123456"/></defs>
  <use href="#c"/>
  <rect x="10" y="10" width="20" height="20" fill="#abcdef"/>
</svg>`,
			expectedStatus: StatusPass,
		},
		{
			name: "x/y on root element",
			content: `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" x="10" y="10">
  <title>Example Corp</title>
</svg>`,
			expectedStatus: StatusFail,
			expectedInMsg:  `Attribute "x" is not allowed on <svg>`,
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
		{
			name: "Recommendation not followed leaves the logo compliant",
			content: strings.Replace(validTinyPSSVG, `baseProfile="tiny-ps"`,
				`baseProfile="tiny-ps" zoomAndPan="disable"`, 1),
			expectedStatus: StatusWarning,
			expectedInMsg:  "should not be present",
		},
		{
			name:           "Malformed XML is left to the well-formedness check",
			content:        `<svg><title>x</circle></svg>`,
			expectedStatus: StatusSkipped,
			expectedInMsg:  "could not be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := CheckLogoSVGTinyPS([]byte(tt.content))
			if check.Status != tt.expectedStatus {
				t.Errorf("status = %s, want %s (messages: %v)", check.Status, tt.expectedStatus, check.Messages)
			}
			if tt.expectedInMsg != "" {
				if !strings.Contains(strings.Join(check.MessageTexts(), " "), tt.expectedInMsg) {
					t.Errorf("messages %v do not contain %q", check.Messages, tt.expectedInMsg)
				}
			}
		})
	}
}

// TestCheckLogoSVGTinyPSMessageSeverities checks that a document breaking both a
// MUST and a SHOULD reports each at its own severity, so the interface can tell
// the reason the check failed from the advice that came with it.
func TestCheckLogoSVGTinyPSMessageSeverities(t *testing.T) {
	content := strings.Replace(validTinyPSSVG, `baseProfile="tiny-ps"`,
		`baseProfile="tiny-ps" zoomAndPan="disable" onload="go()"`, 1)

	check := CheckLogoSVGTinyPS([]byte(content))
	if check.Status != StatusFail {
		t.Fatalf("status = %s, want %s", check.Status, StatusFail)
	}

	var errors, warnings int
	for _, message := range check.Messages {
		switch message.Severity {
		case SeverityError:
			errors++
		case SeverityWarning:
			warnings++
		}
	}
	if errors != 1 || warnings != 1 {
		t.Errorf("got %d errors and %d warnings, want 1 and 1: %v", errors, warnings, check.Messages)
	}
}

// TestCheckLogoSVGTinyPSFoldsRepeats checks that a rule broken throughout the
// document yields one message carrying the number of occurrences, rather than
// hundreds of identical lines.
func TestCheckLogoSVGTinyPSFoldsRepeats(t *testing.T) {
	content := strings.Replace(validTinyPSSVG, `<circle cx="50" cy="50" r="40" fill="#123456"/>`,
		strings.Repeat(`<circle cx="50" cy="50" r="40" fill="#123456" style="fill:red"/>`, 30), 1)

	check := CheckLogoSVGTinyPS([]byte(content))
	if check.Status != StatusFail {
		t.Fatalf("status = %s, want %s", check.Status, StatusFail)
	}
	if len(check.Messages) != 1 {
		t.Fatalf("got %d messages, want 1: %v", len(check.Messages), check.Messages)
	}

	text := check.Messages[0].Text
	if !strings.Contains(text, "(30 occurrences)") {
		t.Errorf("message %q does not carry the occurrence count", text)
	}
	if !strings.HasPrefix(text, "line ") {
		t.Errorf("message %q does not locate the problem in the file", text)
	}
}

// TestCheckLogoSVGTinyPSCapsProblems checks that a document violating far more
// rules than a reader can use is summarised instead of listed in full.
func TestCheckLogoSVGTinyPSCapsProblems(t *testing.T) {
	var unknown strings.Builder
	for i := 0; i < maxLogoProblems+5; i++ {
		fmt.Fprintf(&unknown, "<unknown%d/>", i)
	}
	content := strings.Replace(validTinyPSSVG, "</svg>", unknown.String()+"</svg>", 1)

	check := CheckLogoSVGTinyPS([]byte(content))
	if len(check.Messages) != maxLogoProblems+1 {
		t.Fatalf("got %d messages, want %d", len(check.Messages), maxLogoProblems+1)
	}

	last := check.Messages[len(check.Messages)-1]
	if !strings.Contains(last.Text, "5 further problems are not listed") {
		t.Errorf("last message %q does not summarise what was left out", last.Text)
	}
	if last.Severity != SeverityError {
		t.Errorf("summary severity = %s, want %s", last.Severity, SeverityError)
	}
}
