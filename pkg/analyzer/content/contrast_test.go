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

package content

import (
	"math"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// findingsOnMarkup runs the contrast reading over a body fragment.
func findingsOnMarkup(t *testing.T, body string) []reading.Finding {
	t.Helper()

	document, err := parseHTML("<html><body>" + body + "</body></html>")
	if err != nil {
		t.Fatalf("the fixture does not parse: %v", err)
	}

	return lowContrastFindings(document)
}

// TestLowContrastFindsThePairsItCanSee is the case the check exists for: a
// button carrying both its colours in one attribute, which is the element whose
// contrast matters most and the one that needs no cascade at all.
func TestLowContrastFindsThePairsItCanSee(t *testing.T) {
	findings := findingsOnMarkup(t,
		`<a href="https://example.com" style="background-color:#007bff;color:#ffffff;padding:12px">Book a place</a>`)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1", len(findings))
	}

	finding := findings[0]
	for _, want := range []string{"#ffffff", "#007bff", "3.98:1", "4.5:1"} {
		if !strings.Contains(finding.Message, want) {
			t.Errorf("the message reads %q, which does not mention %q", finding.Message, want)
		}
	}
	if finding.Defect != defectLowContrast {
		t.Errorf("the finding is priced as %v, want the contrast defect", finding.Defect)
	}
	if finding.Type != model.IssueTypeLowContrast {
		t.Errorf("the finding is typed %q, want low_contrast", finding.Type)
	}
	if finding.Location == nil || !strings.Contains(*finding.Location, "Book a place") {
		t.Errorf("the location is %v, want it to quote the text so the sender can find it", finding.Location)
	}
}

// TestLowContrastInheritsTheColourAndFindsTheBackground holds the one asymmetry
// the walk rests on: a colour is inherited from wherever it was declared, while
// a background is whatever the nearest ancestor paints.
func TestLowContrastInheritsTheColourAndFindsTheBackground(t *testing.T) {
	findings := findingsOnMarkup(t,
		`<div style="color:#999999">
			<table bgcolor="#ffffff"><tr><td><p>Inherited colour, background from the table</p></td></tr></table>
		</div>`)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1: %v", len(findings), messagesOf(findings))
	}
	if !strings.Contains(findings[0].Message, "#999999 on #ffffff") {
		t.Errorf("the message reads %q, want the inherited colour against the table's bgcolor", findings[0].Message)
	}
}

// TestLowContrastSaysNothingWithoutBothColours is the rule that makes the rest
// trustworthy: an absent contrast is not a passing one, and a colour belonging
// to the client is not the sender's to answer for.
func TestLowContrastSaysNothingWithoutBothColours(t *testing.T) {
	tests := map[string]string{
		"no colour at all":              `<p>Just text</p>`,
		"a background but no colour":    `<p style="background-color:#f0f0f0">Only a background</p>`,
		"a colour the client decides":   `<p style="background-color:#777777">Only a background, dark</p>`,
		"a colour deferred to the tree": `<p style="color:inherit;background-color:#777777">Deferred</p>`,
		"transparent is not a colour":   `<p style="color:transparent;background-color:#ffffff">Invisible</p>`,
		// A message that paints a background somewhere has a background here
		// that we did not find, rather than none: a stylesheet may be painting
		// it, and those are not read.
		"a background elsewhere in the message": `<div style="background-color:#333333">dark</div><p style="color:#eeeeee">Pale on what?</p>`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if findings := findingsOnMarkup(t, body); len(findings) != 0 {
				t.Errorf("reported %v, want nothing", messagesOf(findings))
			}
		})
	}
}

// TestLowContrastAssumesWhiteOnlyWhenNothingIsPainted holds the one assumption
// the check makes, and holds it to being declared in the finding.
func TestLowContrastAssumesWhiteOnlyWhenNothingIsPainted(t *testing.T) {
	findings := findingsOnMarkup(t, `<p style="color:#999999">Pale grey on the client's own white</p>`)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1: %v", len(findings), messagesOf(findings))
	}
	if !strings.Contains(findings[0].Message, "#999999 on #ffffff") {
		t.Errorf("the message reads %q, want the pair measured against white", findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "measured against the white") {
		t.Errorf("the message reads %q, want it to state the assumption it rests on", findings[0].Message)
	}
}

// TestLowContrastRefusesWhatItCannotMeasure keeps the check off the cases where
// a ratio would be invented rather than computed.
func TestLowContrastRefusesWhatItCannotMeasure(t *testing.T) {
	tests := map[string]string{
		"an image behind the text":             `<div style="background-image:url(https://example.com/bg.jpg)"><p style="color:#999999">Over a photo</p></div>`,
		"a gradient behind the text":           `<div style="background:linear-gradient(#fff,#eee)"><p style="color:#999999">Over a gradient</p></div>`,
		"an image on the background shorthand": `<p style="background:#ffffff url(https://example.com/bg.jpg);color:#999999">Over both</p>`,
		"a foreground that is not opaque":      `<p style="color:rgba(0,0,0,0.2);background-color:#ffffff">Faint but composited</p>`,
		"a background that is not opaque":      `<p style="color:#999999;background-color:rgba(255,255,255,0.5)">Through it</p>`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if findings := findingsOnMarkup(t, body); len(findings) != 0 {
				t.Errorf("reported %v, want nothing: the ratio would be invented", messagesOf(findings))
			}
		})
	}
}

// TestLowContrastThresholdFollowsTheTextSize holds the term that decides which
// bar applies. Getting it wrong is how a true finding becomes a false one.
func TestLowContrastThresholdFollowsTheTextSize(t *testing.T) {
	// #007bff on white is 3.98:1: below the 4.5 asked of normal text, above the
	// 3 asked of large text. It is therefore reported at one size and not at the
	// other, which is exactly what the size is read for.
	tests := []struct {
		name     string
		body     string
		reported bool
	}{
		{
			name:     "normal text misses the bar",
			body:     `<p style="color:#007bff;background-color:#ffffff;font-size:16px">Small</p>`,
			reported: true,
		},
		{
			name:     "text at 18pt clears the lower bar",
			body:     `<p style="color:#007bff;background-color:#ffffff;font-size:18pt">Large</p>`,
			reported: false,
		},
		{
			name:     "bold text at 14pt clears it too",
			body:     `<p style="color:#007bff;background-color:#ffffff;font-size:14pt;font-weight:bold">Large and bold</p>`,
			reported: false,
		},
		{
			name:     "bold text at 14pt that is not bold does not",
			body:     `<p style="color:#007bff;background-color:#ffffff;font-size:14pt">Not bold</p>`,
			reported: true,
		},
		{
			name: "a size in a relative unit is judged as normal text",
			// 1.5em may well be large, but nothing here establishes it, and the
			// stricter bar is the safe answer.
			body:     `<p style="color:#007bff;background-color:#ffffff;font-size:1.5em">Relative</p>`,
			reported: true,
		},
		{
			name:     "a heading is bold without saying so",
			body:     `<h1 style="color:#007bff;background-color:#ffffff;font-size:14pt">Heading</h1>`,
			reported: false,
		},
		{
			name: "a heading with no size declared renders at the client's default",
			// An h2 is 24px and bold by default, so the lower bar is the one it
			// was ever held to. Reading it as normal text would report it for
			// missing a threshold that never applied.
			body:     `<h2 style="color:#007bff;background-color:#ffffff">Heading</h2>`,
			reported: false,
		},
		{
			name: "a heading whose ancestor sets a size is not assumed",
			// The default is a multiple of the inherited size, so once an
			// ancestor declares one the heading's own is no longer known.
			body:     `<div style="font-size:10px"><h2 style="color:#007bff;background-color:#ffffff">Heading</h2></div>`,
			reported: true,
		},
		{
			name:     "an h4 is not large text by any threshold",
			body:     `<h4 style="color:#007bff;background-color:#ffffff">Small heading</h4>`,
			reported: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := findingsOnMarkup(t, tt.body)

			if tt.reported && len(findings) == 0 {
				t.Fatal("reported nothing, want the pair reported at the normal-text threshold")
			}
			if !tt.reported && len(findings) != 0 {
				t.Fatalf("reported %v, want nothing: the text is large enough for the lower bar", messagesOf(findings))
			}
		})
	}
}

// TestLowContrastAggregatesByPair holds one finding per colour pair: a palette
// applied to forty paragraphs is one decision the sender made.
func TestLowContrastAggregatesByPair(t *testing.T) {
	body := strings.Repeat(`<p style="color:#999999;background-color:#ffffff">Pale</p>`, 12) +
		`<p style="color:#28a745;background-color:#ffffff">Green</p>`

	findings := findingsOnMarkup(t, body)

	if len(findings) != 2 {
		t.Fatalf("%d findings reported, want 2 (one per pair): %v", len(findings), messagesOf(findings))
	}

	// Worst first, whatever order they were met in: #999999 measures 2.85:1 and
	// #28a745 measures 3.13:1.
	if !strings.Contains(findings[0].Message, "#999999") {
		t.Errorf("the first finding reads %q, want the worse pair first", findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "(12 places)") {
		t.Errorf("the message reads %q, which does not count the twelve paragraphs", findings[0].Message)
	}
	if strings.Contains(findings[1].Message, "places") {
		t.Errorf("the message reads %q, want no count where there is only one place", findings[1].Message)
	}
}

// TestLowContrastSeverity holds the weighing: below three to one no size of text
// carries, which is graver than a pair that only misses its own bar.
func TestLowContrastSeverity(t *testing.T) {
	// #999999 on white is 2.85:1, under every threshold there is.
	illegible := findingsOnMarkup(t, `<p style="color:#999999;background-color:#ffffff">Pale</p>`)
	if len(illegible) != 1 || illegible[0].Severity != model.IssueSeverityHigh {
		t.Errorf("a pair under 3:1 is reported at %v, want high", severitiesOf(illegible))
	}

	// #007bff on white is 3.98:1: lost to some readers, legible to most.
	marginal := findingsOnMarkup(t, `<p style="color:#007bff;background-color:#ffffff">Blue</p>`)
	if len(marginal) != 1 || marginal[0].Severity != model.IssueSeverityMedium {
		t.Errorf("a pair between 3:1 and its threshold is reported at %v, want medium", severitiesOf(marginal))
	}
}

// TestLowContrastSharesTheFilterConcern keeps our finding and rspamd's
// R_WHITE_ON_WHITE recognised as one defect, ours being the one that carries the
// colours and the ratio.
func TestLowContrastSharesTheFilterConcern(t *testing.T) {
	findings := findingsOnMarkup(t, `<p style="color:#ffffff;background-color:#fefefe">Invisible</p>`)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1", len(findings))
	}
	if findings[0].Concern != "low_contrast" {
		t.Errorf("the finding is keyed %q, want the key R_WHITE_ON_WHITE also carries", findings[0].Concern)
	}
	if rspamdFindingCatalog["R_WHITE_ON_WHITE"].Concern != findings[0].Concern {
		t.Errorf("the filter's symbol is keyed %q and ours %q, so the two would be reported twice",
			rspamdFindingCatalog["R_WHITE_ON_WHITE"].Concern, findings[0].Concern)
	}
}

// TestLowContrastSaysNothingWithoutMarkup keeps the check quiet on a message it
// has nothing to read.
func TestLowContrastSaysNothingWithoutMarkup(t *testing.T) {
	findings, err := lowContrastCheck.Run(t.Context(), &contentInput{Results: &Results{}})
	if err != nil {
		t.Fatalf("the check could not answer: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("reported %d findings on a message carrying no HTML at all", len(findings))
	}
}

// TestDirectTextIsTheElementsOwn keeps a wrapper from being credited with the
// text of what it wraps, which would report one run as two.
func TestDirectTextIsTheElementsOwn(t *testing.T) {
	// The div declares the failing colour and holds no text of its own; the
	// paragraph holds the text and inherits the colour. One run, one finding.
	findings := findingsOnMarkup(t,
		`<div style="color:#999999;background-color:#ffffff"><p>The text lives here</p></div>`)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1: %v", len(findings), messagesOf(findings))
	}
	if !strings.Contains(*findings[0].Location, "The text lives here") {
		t.Errorf("the location reads %q, want the paragraph's own text", *findings[0].Location)
	}
}

// severitiesOf makes a failing test say what severity was reported.
func severitiesOf(findings []reading.Finding) []model.IssueSeverity {
	severities := make([]model.IssueSeverity, 0, len(findings))
	for _, finding := range findings {
		severities = append(severities, finding.Severity)
	}

	return severities
}

// TestParseAbsoluteLength holds the reading of a font size to the units that
// mean the same thing wherever they are written.
func TestParseAbsoluteLength(t *testing.T) {
	tests := map[string]float64{
		"16px":  16,
		" 24PX": 24,
		"12pt":  16,     // 12pt is 16px at the 96dpi the web assumes
		"18pt":  24,     // WCAG's large text
		"14pt":  18.667, // WCAG's large bold text
		"1in":   96,
	}

	for value, want := range tests {
		got, ok := parseAbsoluteLength(value)
		if !ok {
			t.Errorf("%q does not read as a length", value)
			continue
		}
		if math.Abs(got-want) > 0.01 {
			t.Errorf("%q reads %.3f px, want %.3f", value, got, want)
		}
	}

	// The relative units are refused on purpose: resolving them takes the
	// computed size of an ancestor, which is the cascade this does not do.
	for _, value := range []string{"1.2em", "120%", "1rem", "larger", "medium", "", "16"} {
		if size, ok := parseAbsoluteLength(value); ok {
			t.Errorf("%q read as %.2f px, want it refused so the stricter threshold applies", value, size)
		}
	}
}
