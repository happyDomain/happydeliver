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

package csscolor

import (
	"math"
	"testing"

	"golang.org/x/image/colornames"
)

// TestParseCSSColor exercises the notations a message may write a colour in.
func TestParseCSSColor(t *testing.T) {
	tests := []struct {
		value string
		want  string // the colour as hex, empty when none was read
		alpha float64
	}{
		{value: "#fff", want: "#ffffff", alpha: 1},
		{value: "#FFF", want: "#ffffff", alpha: 1},
		{value: "#007bff", want: "#007bff", alpha: 1},
		{value: "  #28A745  ", want: "#28a745", alpha: 1},
		{value: "#0000", want: "#000000", alpha: 0},
		{value: "#ff000080", want: "#ff0000", alpha: 128.0 / 255},
		{value: "rgb(255, 0, 0)", want: "#ff0000", alpha: 1},
		{value: "rgb(255 0 0)", want: "#ff0000", alpha: 1},
		{value: "RGB(100%, 0%, 0%)", want: "#ff0000", alpha: 1},
		{value: "rgba(255, 0, 0, 0.5)", want: "#ff0000", alpha: 0.5},
		{value: "rgb(255 0 0 / 50%)", want: "#ff0000", alpha: 0.5},
		{value: "hsl(0, 100%, 50%)", want: "#ff0000", alpha: 1},
		{value: "hsl(120deg 100% 50%)", want: "#00ff00", alpha: 1},
		{value: "hsla(0, 100%, 50%, 0.25)", want: "#ff0000", alpha: 0.25},
		{value: "gray", want: "#808080", alpha: 1},
		{value: "GREY", want: "#808080", alpha: 1},
		{value: "rebeccapurple", want: "#663399", alpha: 1},
		// Channels CSS says are clipped rather than refused.
		{value: "rgb(300, -20, 0)", want: "#ff0000", alpha: 1},

		// What names no colour of its own. Each of these must read as unread, so
		// that the caller keeps looking instead of measuring against a guess.
		{value: "transparent"},
		{value: "currentColor"},
		{value: "inherit"},
		{value: ""},
		{value: "   "},
		{value: "notacolour"},
		{value: "#12345"},
		{value: "rgb(1, 2)"},
		{value: "rgb(a, b, c)"},
		{value: "rgb(1, 2, 3"},
		{value: "url(https://example.com/bg.png)"},
		{value: "linear-gradient(#fff, #000)"},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			colour, ok := Parse(tt.value)

			if tt.want == "" {
				if ok {
					t.Fatalf("read %s, want no colour at all", colour.Hex())
				}
				return
			}

			if !ok {
				t.Fatalf("read no colour, want %s", tt.want)
			}
			if got := colour.Hex(); got != tt.want {
				t.Errorf("read %s, want %s", got, tt.want)
			}
			if math.Abs(colour.Alpha-tt.alpha) > 0.01 {
				t.Errorf("alpha is %.3f, want %.3f", colour.Alpha, tt.alpha)
			}
		})
	}
}

// TestNamedCSSColorsAreComplete guards the keyword table, whose absences are
// silent: a name it lacks reads as no colour, and the text painted with it is
// never measured. The table is borrowed, so this also catches the day the
// borrowed one changes shape under us.
func TestNamedCSSColorsAreComplete(t *testing.T) {
	// The CSS colour keywords number 148, the 147 of CSS 3 plus rebeccapurple.
	if count := len(colornames.Map) + 1; count != 148 {
		t.Errorf("the table holds %d names, want 148", count)
	}

	// A handful whose absence would be felt at once, with the values the
	// specification fixes.
	for name, want := range map[string]string{
		"white": "#ffffff", "black": "#000000", "gray": "#808080", "grey": "#808080",
		"silver": "#c0c0c0", "lightgray": "#d3d3d3", "darkgray": "#a9a9a9",
		"red": "#ff0000", "lime": "#00ff00", "blue": "#0000ff", "rebeccapurple": "#663399",
	} {
		colour, known := Parse(name)
		if !known {
			t.Errorf("%q is not a colour the table knows", name)
			continue
		}
		if got := colour.Hex(); got != want {
			t.Errorf("%q reads %s, want %s", name, got, want)
		}
	}
}

// TestContrastRatio holds the arithmetic to WCAG's own numbers.
//
// The pairs are the standard's anchors and colours taken off real messages; the
// expected ratios come from the formula, not from this implementation, so a
// mistake in it shows here rather than being blessed.
func TestContrastRatio(t *testing.T) {
	tests := []struct {
		foreground, background string
		want                   float64
	}{
		// The two extremes the scale is defined by.
		{"#000000", "#ffffff", 21},
		{"#ffffff", "#ffffff", 1},
		// Symmetry: which of the two is the text makes no difference.
		{"#ffffff", "#000000", 21},
		// Colours a newsletter is actually written with.
		{"#333333", "#ffffff", 12.63},
		{"#777777", "#ffffff", 4.48},
		{"#007bff", "#ffffff", 3.98},
		{"#28a745", "#ffffff", 3.13},
		{"#999999", "#ffffff", 2.85},
		{"#666666", "#f8f9fa", 5.45},
	}

	for _, tt := range tests {
		t.Run(tt.foreground+" on "+tt.background, func(t *testing.T) {
			foreground, ok := Parse(tt.foreground)
			if !ok {
				t.Fatalf("the foreground %q does not read", tt.foreground)
			}
			background, ok := Parse(tt.background)
			if !ok {
				t.Fatalf("the background %q does not read", tt.background)
			}

			got := ContrastRatio(foreground, background)
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("ratio is %.2f:1, want %.2f:1", got, tt.want)
			}
		})
	}
}
