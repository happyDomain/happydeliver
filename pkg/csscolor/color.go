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

// Package csscolor reads a colour as CSS writes it, and answers the one
// question WCAG asks of a pair of them: how far apart they are.
//
// It knows nothing of email. What a message does with a colour, and how much
// of a reader's sight a poor contrast costs, is a judgement made elsewhere.
package csscolor

import (
	"math"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/image/colornames"
)

// Color is a colour as it was written in the message, before any light is made
// of it.
//
// Alpha is kept because a colour that is not opaque is not a colour a contrast
// can be computed from on its own: it would have to be composited over whatever
// is behind it, which is a question this file does not answer.
type Color struct {
	R, G, B uint8

	// Alpha is 1 for an opaque colour, and below it for one written with a
	// fourth component.
	Alpha float64
}

// Opaque says whether this colour can be reasoned about without knowing what is
// behind it.
func (c Color) Opaque() bool {
	return c.Alpha >= 1
}

// Hex writes the colour back as a reader of the message would recognise it,
// which is what a finding quotes.
func (c Color) Hex() string {
	const digits = "0123456789abcdef"

	return string([]byte{
		'#',
		digits[c.R>>4], digits[c.R&0xf],
		digits[c.G>>4], digits[c.G&0xf],
		digits[c.B>>4], digits[c.B&0xf],
	})
}

// RelativeLuminance is the light a colour carries, as WCAG 2 defines it in its
// "relative luminance" formula.
//
// The numbers are the standard's own and are not to be tuned: a contrast ratio
// is only comparable to the 4.5 and 3 thresholds because both sides compute
// luminance this way.
func (c Color) RelativeLuminance() float64 {
	linear := func(channel uint8) float64 {
		value := float64(channel) / 255
		if value <= 0.03928 {
			return value / 12.92
		}

		return math.Pow((value+0.055)/1.055, 2.4)
	}

	return 0.2126*linear(c.R) + 0.7152*linear(c.G) + 0.0722*linear(c.B)
}

// ContrastRatio is the ratio between two colours, from 1 (the same colour) to
// 21 (black against white).
func ContrastRatio(a, b Color) float64 {
	lighter, darker := a.RelativeLuminance(), b.RelativeLuminance()
	if lighter < darker {
		lighter, darker = darker, lighter
	}

	return (lighter + 0.05) / (darker + 0.05)
}

// Parse reads a colour as CSS lets it be written, and says whether it
// read one at all.
//
// What it refuses is as important as what it accepts. "transparent",
// "currentColor" and "inherit" name no colour of their own: they defer to
// something this file cannot see, and are reported as unread so that the caller
// keeps looking rather than computing a ratio against a guess.
func Parse(value string) (Color, bool) {
	value = strings.ToLower(strings.TrimSpace(value))

	switch value {
	case "", "transparent", "currentcolor", "inherit", "initial", "unset", "revert", "none", "auto":
		return Color{}, false
	}

	if strings.HasPrefix(value, "#") {
		return parseHexColor(value)
	}

	if open := strings.IndexByte(value, '('); open >= 0 {
		// A function whose parenthesis never closes is malformed CSS, of which
		// an email carries its share. It names no colour, and reading to the end
		// of the string instead would invent one.
		close := strings.LastIndexByte(value, ')')
		if close < open {
			return Color{}, false
		}

		return parseFunctionalColor(value[:open], value[open+1:close])
	}

	if named, known := namedColor(value); known {
		return named, true
	}

	return Color{}, false
}

// parseHexColor reads #rgb, #rgba, #rrggbb and #rrggbbaa.
func parseHexColor(value string) (Color, bool) {
	digits := strings.TrimPrefix(value, "#")

	// The short forms repeat each digit: #abc is #aabbcc.
	if len(digits) == 3 || len(digits) == 4 {
		var doubled strings.Builder
		for _, digit := range digits {
			doubled.WriteRune(digit)
			doubled.WriteRune(digit)
		}
		digits = doubled.String()
	}

	if len(digits) != 6 && len(digits) != 8 {
		return Color{}, false
	}

	channels := make([]uint8, 0, 4)
	for i := 0; i < len(digits); i += 2 {
		channel, err := strconv.ParseUint(digits[i:i+2], 16, 8)
		if err != nil {
			return Color{}, false
		}
		channels = append(channels, uint8(channel))
	}

	colour := Color{R: channels[0], G: channels[1], B: channels[2], Alpha: 1}
	if len(channels) == 4 {
		colour.Alpha = float64(channels[3]) / 255
	}

	return colour, true
}

// parseFunctionalColor reads rgb(), rgba(), hsl() and hsla(), in both the comma
// syntax email is written in and the space syntax CSS now prefers.
func parseFunctionalColor(function, arguments string) (Color, bool) {
	function = strings.TrimSpace(function)

	// Both syntaxes are read the same way: the separators are thrown away and
	// the components taken in order. An alpha written after a slash lands as the
	// fourth component, which is where it belongs.
	arguments = strings.NewReplacer(",", " ", "/", " ").Replace(arguments)
	components := strings.Fields(arguments)

	if len(components) < 3 {
		return Color{}, false
	}

	alpha := 1.0
	if len(components) >= 4 {
		parsed, ok := parseColorComponent(components[3], 1)
		if !ok {
			return Color{}, false
		}
		alpha = parsed
	}

	switch function {
	case "rgb", "rgba":
		channels := make([]uint8, 0, 3)
		for _, component := range components[:3] {
			value, ok := parseColorComponent(component, 255)
			if !ok {
				return Color{}, false
			}
			channels = append(channels, clampChannel(value))
		}

		return Color{R: channels[0], G: channels[1], B: channels[2], Alpha: alpha}, true

	case "hsl", "hsla":
		hue, ok := parseAngle(components[0])
		if !ok {
			return Color{}, false
		}
		saturation, ok := parseColorComponent(components[1], 1)
		if !ok {
			return Color{}, false
		}
		lightness, ok := parseColorComponent(components[2], 1)
		if !ok {
			return Color{}, false
		}

		// The conversion is the CSS parser's own, so that two ways of writing
		// one colour cannot disagree here.
		red, green, blue := css.HSL2RGB(hue, saturation, lightness)

		return Color{
			R:     clampChannel(red * 255),
			G:     clampChannel(green * 255),
			B:     clampChannel(blue * 255),
			Alpha: alpha,
		}, true
	}

	return Color{}, false
}

// parseColorComponent reads one component, which may be written as a number or
// as a percentage of full. The scale says what full is: 255 for an RGB channel,
// 1 for a saturation or an alpha.
func parseColorComponent(component string, scale float64) (float64, bool) {
	if percentage, found := strings.CutSuffix(component, "%"); found {
		value, err := strconv.ParseFloat(percentage, 64)
		if err != nil {
			return 0, false
		}

		return value / 100 * scale, true
	}

	value, err := strconv.ParseFloat(component, 64)
	if err != nil {
		return 0, false
	}

	return value, true
}

// parseAngle reads a hue, in the turns CSS lets it be written in. The parser's
// HSL2RGB wants it as a fraction of a turn.
func parseAngle(component string) (float64, bool) {
	// The units are tried longest first, and from a slice rather than a map:
	// "grad" ends in "rad", so an order the language leaves to chance would
	// read one turn of gradians as a turn of radians on some runs and not
	// others.
	units := []struct {
		Name    string
		PerTurn float64
	}{
		{"turn", 1},
		{"grad", 400},
		{"deg", 360},
		{"rad", 2 * math.Pi},
	}

	for _, unit := range units {
		if number, found := strings.CutSuffix(component, unit.Name); found {
			value, err := strconv.ParseFloat(number, 64)
			if err != nil {
				return 0, false
			}

			return value / unit.PerTurn, true
		}
	}

	// A bare number is degrees, as it is everywhere in CSS.
	value, err := strconv.ParseFloat(component, 64)
	if err != nil {
		return 0, false
	}

	return value / 360, true
}

// clampChannel brings a computed channel back into the byte a colour is made
// of: CSS allows the arithmetic to overshoot, and says the result is clipped.
func clampChannel(value float64) uint8 {
	return uint8(math.Round(math.Min(math.Max(value, 0), 255)))
}

// namedColor reads one of the CSS colour keywords, which a message is as likely
// to be written with as with a hex code: "color: gray" must not read as no
// colour at all.
//
// The table is the SVG 1.1 one, which CSS inherited whole and which x/image
// already carries. Only rebeccapurple, added to CSS after that spec was
// written, has to be named here.
func namedColor(name string) (Color, bool) {
	if name == "rebeccapurple" {
		return Color{R: 102, G: 51, B: 153, Alpha: 1}, true
	}

	named, known := colornames.Map[name]
	if !known {
		return Color{}, false
	}

	return Color{R: named.R, G: named.G, B: named.B, Alpha: 1}, true
}
