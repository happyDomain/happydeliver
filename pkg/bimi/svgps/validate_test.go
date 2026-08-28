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

package svgps

import (
	"strings"
	"testing"
)

// A compliant document, split so a test case can insert content into it or
// replace one part. It paints in two colours, which the profile requires.
const (
	svgOpen   = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 64 64">`
	svgTitle  = `<title>Example Corp</title>`
	svgShapes = `<circle cx="32" cy="32" r="30" fill="#123456"/><rect x="0" y="0" width="8" height="8" fill="#abcdef"/>`
	svgClose  = `</svg>`
)

// doc wraps content in an otherwise compliant document.
func doc(content string) string {
	return svgOpen + svgTitle + svgShapes + content + svgClose
}

// messages returns the texts of the problems of the given severity.
func messages(problems []Problem, severity Severity) []string {
	var out []string
	for _, p := range problems {
		if p.Severity == severity {
			out = append(out, p.Text)
		}
	}
	return out
}

// contains reports whether any of the texts holds the substring.
func contains(texts []string, substring string) bool {
	for _, text := range texts {
		if strings.Contains(text, substring) {
			return true
		}
	}
	return false
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		// wantError and wantWarning are substrings expected in a problem of
		// that severity; an empty string means none of that severity is
		// expected at all.
		wantError   string
		wantWarning string
	}{
		{
			name: "Compliant document",
			doc:  doc(""),
		},

		// Elements outside the profile. The blocklist the validator
		// replaced missed every one of these but <image>.
		{
			name:      "Script element",
			doc:       doc(`<script>alert(1)</script>`),
			wantError: "scripting is not allowed",
		},
		{
			name:      "Switch element",
			doc:       doc(`<switch><rect/></switch>`),
			wantError: "conditional processing is not allowed",
		},
		{
			name:      "Anchor element",
			doc:       doc(`<a><rect/></a>`),
			wantError: "linking is not allowed",
		},
		{
			name:      "Style element",
			doc:       doc(`<style>@import url(https://example.com/x.css);</style>`),
			wantError: "stylesheets are not allowed",
		},
		{
			name:      "Animation element",
			doc:       doc(`<animation/>`),
			wantError: "multimedia content is not allowed",
		},
		{
			name:      "Image element",
			doc:       doc(`<image href="x.png"/>`),
			wantError: "raster and external images are not allowed",
		},
		{
			name:      "Filter element",
			doc:       doc(`<filter id="f"/>`),
			wantError: "filters are not part of SVG Tiny",
		},
		{
			name:      "Unknown element",
			doc:       doc(`<sparkle/>`),
			wantError: "Element <sparkle> is not part of the SVG Tiny P/S profile",
		},
		{
			name:      "Foreign namespace element",
			doc:       doc(`<h:div xmlns:h="http://www.w3.org/1999/xhtml"/>`),
			wantError: `belongs to the namespace "http://www.w3.org/1999/xhtml"`,
		},
		{
			name:      "Element misplaced in the profile",
			doc:       doc(`<stop offset="0"/>`),
			wantError: "Element <stop> is not allowed as a child of <svg>",
		},
		{
			name:      "Subtree of a rejected element is not re-reported",
			doc:       doc(`<switch><sparkle/><sparkle/></switch>`),
			wantError: "conditional processing is not allowed",
		},

		// The <title> element.
		{
			name:      "Title is not the first child",
			doc:       svgOpen + svgShapes + svgTitle + svgClose,
			wantError: "<title> must be the first child of <svg>",
		},
		{
			name:      "Title is empty",
			doc:       svgOpen + `<title></title>` + svgShapes + svgClose,
			wantError: "The <title> element must not be empty",
		},
		{
			name:      "Title appears twice",
			doc:       svgOpen + svgTitle + `<title>Other</title>` + svgShapes + svgClose,
			wantError: "must contain exactly one <title>",
		},
		{
			name:      "Title is missing",
			doc:       svgOpen + svgShapes + svgClose,
			wantError: "<svg> must contain a <title> element",
		},
		{
			name:      "Title nested in a group",
			doc:       svgOpen + `<g><title>Example Corp</title></g>` + svgShapes + svgClose,
			wantError: "Element <title> is not allowed as a child of <g>",
		},
		{
			name:        "Title longer than the recommended length",
			doc:         svgOpen + `<title>` + strings.Repeat("Example Corporation ", 5) + `</title>` + svgShapes + svgClose,
			wantWarning: "should be no more than 64 characters",
		},
		{
			name:      "Empty description",
			doc:       doc(`<desc>  </desc>`),
			wantError: "The <desc> element must not be empty",
		},

		// Attributes with a constrained value.
		{
			name:      "Wrong zoomAndPan value",
			doc:       strings.Replace(doc(""), svgOpen, strings.Replace(svgOpen, `viewBox`, `zoomAndPan="magnify" viewBox`, 1), 1),
			wantError: `zoomAndPan="magnify"`,
		},
		{
			name:        "Discouraged attribute with the right value",
			doc:         strings.Replace(doc(""), svgOpen, strings.Replace(svgOpen, `viewBox`, `zoomAndPan="disable" viewBox`, 1), 1),
			wantWarning: `Attribute "zoomAndPan" should not be present`,
		},
		{
			name:      "Wrong externalResourcesRequired value",
			doc:       strings.Replace(doc(""), svgOpen, strings.Replace(svgOpen, `viewBox`, `externalResourcesRequired="true" viewBox`, 1), 1),
			wantError: `externalResourcesRequired="true"`,
		},
		{
			name:      "Wrong preserveAspectRatio value",
			doc:       strings.Replace(doc(""), svgOpen, strings.Replace(svgOpen, `viewBox`, `preserveAspectRatio="xMinYMin slice" viewBox`, 1), 1),
			wantError: "does not match the required form",
		},
		{
			name:      "Missing version",
			doc:       strings.Replace(doc(""), ` version="1.2"`, "", 1),
			wantError: `missing the required version="1.2" attribute`,
		},
		{
			name:      "Missing baseProfile",
			doc:       strings.Replace(doc(""), ` baseProfile="tiny-ps"`, "", 1),
			wantError: `missing the required baseProfile="tiny-ps" attribute`,
		},
		{
			name:      "Wrong baseProfile",
			doc:       strings.Replace(doc(""), `baseProfile="tiny-ps"`, `baseProfile="tiny"`, 1),
			wantError: "is not one of the permitted values",
		},

		// Attributes outside the profile.
		{
			name:      "Coordinates on the root element",
			doc:       strings.Replace(doc(""), svgOpen, strings.Replace(svgOpen, `viewBox`, `x="0" y="0" viewBox`, 1), 1),
			wantError: `Attribute "x" is not allowed on <svg>`,
		},
		{
			name:      "Event attribute",
			doc:       doc(`<rect onclick="alert(1)"/>`),
			wantError: "event attributes enable scripting",
		},
		{
			name:      "Style attribute",
			doc:       doc(`<rect style="fill:url(https://example.com/x)"/>`),
			wantError: "styling must use presentation attributes, not CSS",
		},
		{
			name:      "Attribute in a foreign namespace",
			doc:       doc(`<rect xmlns:h="http://www.w3.org/1999/xhtml" h:title="x"/>`),
			wantError: "it belongs to a namespace the profile does not define",
		},

		// References.
		{
			name: "Local reference",
			doc:  doc(`<defs><rect id="r"/></defs><use href="#r"/>`),
		},
		{
			name:      "External reference",
			doc:       doc(`<use href="https://example.com/logo.svg#r"/>`),
			wantError: "only references inside the document (#id) are permitted",
		},
		{
			name: "Local paint server reference",
			doc:  svgOpen + svgTitle + `<defs><linearGradient id="g"><stop stop-color="#123456"/><stop stop-color="#abcdef"/></linearGradient></defs><rect fill="url(#g)"/>` + svgClose,
		},
		{
			name:      "External paint server reference",
			doc:       doc(`<rect fill="url(https://example.com/paint.svg#g)"/>`),
			wantError: `Reference "https://example.com/paint.svg#g" in fill on <rect>`,
		},
		{
			name:      "External paint server reference, quoted and spaced",
			doc:       doc(`<rect stroke="url( 'https://example.com/paint.svg#g' ) #123456"/>`),
			wantError: `Reference "https://example.com/paint.svg#g" in stroke on <rect>`,
		},

		// Document-level constructs.
		{
			name:      "DOCTYPE declaration",
			doc:       `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">` + doc(""),
			wantError: "DOCTYPE declaration",
		},
		{
			name:      "Processing instruction",
			doc:       `<?xml-stylesheet href="https://example.com/x.css"?>` + doc(""),
			wantError: "Processing instruction <?xml-stylesheet?> is not allowed",
		},
		{
			name:      "Root element is not svg",
			doc:       `<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`,
			wantError: "The root element is <html>, expected <svg>",
		},
		{
			name:      "Missing SVG namespace",
			doc:       strings.Replace(doc(""), ` xmlns="http://www.w3.org/2000/svg"`, "", 1),
			wantError: `declares the namespace "", expected "http://www.w3.org/2000/svg"`,
		},
		{
			name:      "Text outside a textual element",
			doc:       doc(`<g>free text</g>`),
			wantError: "Text is not allowed inside <g>",
		},
		{
			name:        "Single colour",
			doc:         svgOpen + svgTitle + `<circle cx="32" cy="32" r="30" fill="#123456"/>` + svgClose,
			wantWarning: "fewer than two distinct colours",
		},

		// The three points where the schema and the prose of the draft
		// disagree: tolerated, but reported.
		{
			name:        "Metadata holding RDF",
			doc:         doc(`<metadata><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description/></rdf:RDF></metadata>`),
			wantWarning: "<metadata> holds elements",
		},
		{
			name:      "Metadata hiding an SVG element",
			doc:       doc(`<metadata><script>alert(1)</script></metadata>`),
			wantError: "scripting is not allowed",
		},
		{
			name:      "Metadata hiding a misplaced SVG element",
			doc:       doc(`<metadata><rect/></metadata>`),
			wantError: "Element <rect> is not allowed as a child of <metadata>",
		},
		{
			name:        "Embedded font",
			doc:         doc(`<defs><font><font-face/></font></defs>`),
			wantWarning: "Element <font> is unreachable in the profile schema",
		},
		{
			name:        "xlink:href on use",
			doc:         doc(`<defs><rect id="r"/></defs><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#r"/>`),
			wantWarning: "should be written href",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, err := Validate([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Validate returned an error: %s", err)
			}

			errors := messages(problems, SeverityError)
			warnings := messages(problems, SeverityWarning)

			if tt.wantError == "" {
				if len(errors) > 0 {
					t.Errorf("unexpected errors: %v", errors)
				}
			} else if !contains(errors, tt.wantError) {
				t.Errorf("errors %v do not contain %q", errors, tt.wantError)
			}

			if tt.wantWarning == "" {
				if len(warnings) > 0 {
					t.Errorf("unexpected warnings: %v", warnings)
				}
			} else if !contains(warnings, tt.wantWarning) {
				t.Errorf("warnings %v do not contain %q", warnings, tt.wantWarning)
			}
		})
	}
}

// TestValidateAggregatesRepeats checks that a document breaking the same rule
// throughout is reported once, with a count: an editor export can carry the
// offending attribute on every node.
func TestValidateAggregatesRepeats(t *testing.T) {
	problems, err := Validate([]byte(doc(strings.Repeat(`<rect style="fill:red"/>`, 50))))
	if err != nil {
		t.Fatalf("Validate returned an error: %s", err)
	}

	if len(problems) != 1 {
		t.Fatalf("got %d problems, want 1: %v", len(problems), messages(problems, SeverityError))
	}
	if problems[0].Count != 50 {
		t.Errorf("count = %d, want 50", problems[0].Count)
	}
	if problems[0].Line == 0 {
		t.Error("the problem carries no line number")
	}
}

// TestValidateReportsLine checks that a problem points at where it occurs.
func TestValidateReportsLine(t *testing.T) {
	document := svgOpen + "\n" + svgTitle + "\n" + svgShapes + "\n<script/>\n" + svgClose
	problems, err := Validate([]byte(document))
	if err != nil {
		t.Fatalf("Validate returned an error: %s", err)
	}
	if len(problems) != 1 {
		t.Fatalf("got %d problems, want 1: %v", len(problems), problems)
	}
	if problems[0].Line != 4 {
		t.Errorf("line = %d, want 4", problems[0].Line)
	}
}

// TestValidateRejectsUnparsableInput checks that malformed markup is handed back
// as an error rather than reported as a profile violation: the caller has a
// dedicated well-formedness check with a better diagnostic.
func TestValidateRejectsUnparsableInput(t *testing.T) {
	if _, err := Validate([]byte("<svg><title>x</circle></svg>")); err == nil {
		t.Error("expected an error for malformed XML")
	}
}

// TestValidateDraftExample runs the example document of
// draft-svg-tiny-ps-abrotman section 5. It carries zoomAndPan and
// externalResourcesRequired with their mandated values, so it must come out
// compliant with warnings only.
func TestValidateDraftExample(t *testing.T) {
	const example = `<?xml version="1.0"?>
<svg width="400px" height="400px" xmlns="http://www.w3.org/2000/svg"
    version="1.2" baseProfile="tiny-ps"
    zoomAndPan="disable" externalResourcesRequired="false">
  <title>Example, Inc.</title>
  <desc>Logo for Example, Inc.</desc>
  <rect x="1" y="1" width="399" height="399" fill="teal"
     stroke="gray" stroke-width="9"/>
  <circle cx="200" cy="200" r="125" fill="white"
     stroke="black" stroke-width="2"/>
  <polyline fill="gray" stroke="silver" stroke-width="9"
     points="40,30 25,40 100,330 310,270 290,250 120,300 40,26"/>
</svg>`

	problems, err := Validate([]byte(example))
	if err != nil {
		t.Fatalf("Validate returned an error: %s", err)
	}

	if errors := messages(problems, SeverityError); len(errors) > 0 {
		t.Errorf("unexpected errors: %v", errors)
	}
	if warnings := messages(problems, SeverityWarning); len(warnings) != 2 {
		t.Errorf("got %d warnings, want 2 (zoomAndPan, externalResourcesRequired): %v", len(warnings), warnings)
	}
}
