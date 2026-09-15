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
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/csscolor"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// The WCAG 2 level AA thresholds for text against its background.
//
// Which one applies is decided by the size of the text, not by its importance:
// large text carries its shape at a lower contrast, so the standard asks less of
// it. Getting the size wrong therefore moves the bar, which is why an unreadable
// size is treated as normal text below rather than assumed to be large.
const (
	contrastThresholdNormal = 4.5
	contrastThresholdLarge  = 3.0

	// largeTextPx and largeBoldTextPx are WCAG's 18pt and 14pt, in the pixels
	// CSS is written in at the 96dpi the web assumes.
	//
	// They are written as the conversion rather than as its result, because a
	// rounded literal loses the boundary: 14pt converts to 18.666…px, which is
	// below a constant written 18.667, so text at exactly the size the standard
	// names would be judged by the wrong threshold.
	pxPerPt         = 96.0 / 72.0
	largeTextPx     = 18 * pxPerPt
	largeBoldTextPx = 14 * pxPerPt
)

// textStyle is what one element declares about the text it holds, read off its
// style attribute alone.
type textStyle struct {
	// Foreground is the colour the text is painted in, and Background what is
	// painted behind it. Either may be unset, which is what keeps a ratio from
	// being computed against a colour nobody wrote.
	Foreground    *csscolor.Color
	Background    *csscolor.Color
	HasForeground bool
	HasBackground bool

	// BackgroundIsImage says the element paints something behind its text that
	// is not a colour. There is no ratio to compute then, and no point looking
	// further up the tree: whatever an ancestor paints, this covers it.
	BackgroundIsImage bool

	// FontSizePx is the size in pixels when the element declares one in a unit
	// that means the same thing everywhere, and Bold whether it declares a
	// weight that reads as bold.
	FontSizePx  float64
	HasFontSize bool
	Bold        bool
}

// parseInlineDeclarations reads a style attribute into the values it declares,
// by property.
//
// It asks a different question of the CSS than observeCSS does, which is why it
// is a second reader rather than a use of the first: the compatibility check
// asks which features appear anywhere in a stylesheet, and this asks what one
// element declares for one property. The last declaration of a property wins,
// as the cascade says it does within a block.
func parseInlineDeclarations(style string) map[string]string {
	if strings.TrimSpace(style) == "" {
		return nil
	}

	declarations := make(map[string]string)

	parser := css.NewParser(parse.NewInputString(style), true)
	for {
		grammar, _, data := parser.Next()
		if grammar == css.ErrorGrammar {
			// The parser reports the end of the input and a declaration it
			// could not read the same way, and recovers from the second at the
			// next semicolon. A style attribute that opens with an Outlook hack
			// still declares the colours written after it, so only the end
			// stops the reading.
			if errors.Is(parser.Err(), io.EOF) {
				return declarations
			}

			continue
		}
		if grammar != css.DeclarationGrammar {
			continue
		}

		var value strings.Builder
		for _, token := range parser.Values() {
			value.WriteString(string(token.Data))
		}

		property := unprefixCSSName(strings.ToLower(string(data)))
		declarations[property] = withoutImportant(value.String())
	}
}

// withoutImportant takes the priority off a declared value. The tokens are
// concatenated without the spacing that separated them, so a value written
// "#1a1a1a !important" arrives here as "#1a1a1a!important", which no colour or
// length parser would read.
func withoutImportant(value string) string {
	value = strings.TrimSpace(value)
	if trimmed, found := cutSuffixFold(value, "!important"); found {
		value = strings.TrimSpace(trimmed)
	}

	return value
}

// cutSuffixFold is strings.CutSuffix, reading the suffix as CSS does: without
// regard to case.
func cutSuffixFold(value, suffix string) (string, bool) {
	if len(value) < len(suffix) || !strings.EqualFold(value[len(value)-len(suffix):], suffix) {
		return value, false
	}

	return value[:len(value)-len(suffix)], true
}

// readTextStyle takes off one element what it says about its own text.
//
// The bgcolor attribute is read alongside background-color because email is
// written that way: a table cell painted with bgcolor is the most common
// background in a newsletter, and ignoring it would leave the colours of half
// the messages unpaired.
func readTextStyle(n *html.Node) textStyle {
	var style textStyle

	declarations := parseInlineDeclarations(getAttrOf(n, "style"))

	if colour, ok := csscolor.Parse(declarations["color"]); ok {
		style.Foreground, style.HasForeground = &colour, true
	}

	// background-color first, then the shorthand, then the attribute: the more
	// specific statement of the same thing wins.
	background, found := csscolor.Parse(declarations["background-color"])
	switch {
	case found:
		style.Background, style.HasBackground = &background, true
	case declarations["background"] != "":
		if shorthand, ok := csscolor.Parse(backgroundShorthandColor(declarations["background"])); ok {
			style.Background, style.HasBackground = &shorthand, true
		}
	}

	// A shorthand that paints an image hides whatever colour was declared
	// beside it, whichever of the two the branch above read: the declarations
	// are a map, so which was written last is not ours to know.
	if backgroundPaintsAnImage(declarations["background"]) {
		style.BackgroundIsImage = true
	}

	if declarations["background-image"] != "" && declarations["background-image"] != "none" {
		style.BackgroundIsImage = true
	}

	if !style.HasBackground {
		if colour, ok := csscolor.Parse(getAttrOf(n, "bgcolor")); ok {
			style.Background, style.HasBackground = &colour, true
		}
	}

	if size, ok := parseAbsoluteLength(declarations["font-size"]); ok {
		style.FontSizePx, style.HasFontSize = size, true
	}
	// A tag that reads as bold says so until the element says otherwise: a
	// heading that declares font-weight:normal is set in normal weight, and
	// must be held to the threshold normal text is held to.
	if weight := declarations["font-weight"]; weight != "" {
		style.Bold = readsAsBold(weight)
	} else {
		style.Bold = readsAsBoldTag(n.Data)
	}

	return style
}

// backgroundShorthandColor picks the colour out of a background shorthand,
// which may carry a position, a repeat and an image alongside it.
func backgroundShorthandColor(shorthand string) string {
	for _, part := range strings.Fields(shorthand) {
		if _, ok := csscolor.Parse(part); ok {
			return part
		}
	}

	// A functional colour survives the split into fields as several pieces, so
	// the whole is tried once before giving up.
	if _, ok := csscolor.Parse(shorthand); ok {
		return shorthand
	}

	return ""
}

// backgroundPaintsAnImage says whether a background declaration puts something
// other than a flat colour behind the text.
func backgroundPaintsAnImage(value string) bool {
	lowered := strings.ToLower(value)

	return strings.Contains(lowered, "url(") || strings.Contains(lowered, "gradient(")
}

// parseAbsoluteLength reads a length in a unit that means the same thing
// wherever it is written.
//
// em, rem, % and the keywords are refused on purpose: resolving them takes the
// computed size of an ancestor, which is the cascade this check does not do.
// Refusing them leaves the text judged as normal text, which is the stricter
// threshold and so the safe answer.
func parseAbsoluteLength(value string) (float64, bool) {
	value = strings.ToLower(strings.TrimSpace(value))

	for unit, perUnitPx := range map[string]float64{"px": 1, "pt": pxPerPt, "pc": 16, "in": 96, "cm": 96 / 2.54, "mm": 9.6 / 2.54} {
		number, found := strings.CutSuffix(value, unit)
		if !found {
			continue
		}

		size, err := strconv.ParseFloat(strings.TrimSpace(number), 64)
		if err != nil {
			return 0, false
		}

		return size * perUnitPx, true
	}

	return 0, false
}

// readsAsBoldTag says whether an element is set in bold by the tag it is
// written as, absent a weight of its own.
func readsAsBoldTag(tag string) bool {
	switch tag {
	case "b", "strong", "h1", "h2", "h3", "h4", "h5", "h6":
		return true
	}

	return false
}

// readsAsBold says whether a font-weight is one a reader would call bold, which
// is what WCAG's "14pt bold" means.
func readsAsBold(weight string) bool {
	weight = strings.ToLower(strings.TrimSpace(weight))

	switch weight {
	case "bold", "bolder", "600", "700", "800", "900":
		return true
	}

	return false
}

// textRun is a piece of text the message paints, with the colours it is painted
// with once the tree has been walked for them.
type textRun struct {
	Foreground csscolor.Color
	Background csscolor.Color

	// Threshold is the ratio WCAG AA asks of this run, which depends on how
	// large its text is.
	Threshold float64

	// BackgroundAssumed says the message painted no background anywhere, so the
	// client's own is what this was measured against. It is carried into the
	// finding, because a reader is owed the assumption it rests on.
	BackgroundAssumed bool

	// Text is what the run says, cut short, so the sender can find it.
	Text string
}

// contrastRuns finds the text the message paints and the colours it paints it
// with.
//
// Only what is declared inline is read. That is the whole scope of this check,
// and the reason it can be trusted: pairing a colour from a <style> block with
// the text it lands on would take selector matching and specificity, which is a
// cascade this does not implement, and a wrong pairing is a finding that accuses
// a sender of something they did not write.
//
// A run whose foreground or background was never written is not reported. An
// absent contrast is not a passing one, and saying nothing is the only honest
// answer when the colour belongs to the client rather than to the message.
func contrastRuns(root *html.Node) []textRun {
	if root == nil {
		return nil
	}

	// Whether the message paints any background at all decides what an element
	// with no background of its own is measured against. It is answered over the
	// whole tree first, because the answer is about the message and not about
	// the element.
	paintsABackground := false
	forEachElement(root, func(n *html.Node) {
		if style := readTextStyle(n); style.HasBackground || style.BackgroundIsImage {
			paintsABackground = true
		}
	})

	var runs []textRun

	forEachElement(root, func(n *html.Node) {
		text := directText(n)
		if text == "" {
			return
		}

		foreground, background, assumed, ok := resolveColors(n, paintsABackground)
		if !ok {
			return
		}

		runs = append(runs, textRun{
			Foreground:        foreground,
			Background:        background,
			Threshold:         thresholdFor(n),
			BackgroundAssumed: assumed,
			Text:              text,
		})
	})

	return runs
}

// resolveColors walks up from an element for the colours its text is painted
// with, and says whether both were found.
//
// The two are looked for differently because CSS treats them differently: a
// colour is inherited, so the nearest ancestor that declares one decides, while
// a background is not, so what shows through is the nearest ancestor that paints
// one. The walk is the same; what it means is not, and it is the only reason
// this can be done without a cascade.
func resolveColors(n *html.Node, messagePaintsABackground bool) (foreground, background csscolor.Color, assumed, ok bool) {
	var foundForeground, foundBackground bool

	for node := n; node != nil && node.Type == html.ElementNode; node = node.Parent {
		style := readTextStyle(node)

		if !foundForeground && style.HasForeground {
			foreground, foundForeground = *style.Foreground, true
		}

		if !foundBackground {
			// Something that is not a colour is painted here, and it hides
			// whatever any ancestor paints. There is no ratio to compute.
			if style.BackgroundIsImage {
				return csscolor.Color{}, csscolor.Color{}, false, false
			}
			if style.HasBackground {
				background, foundBackground = *style.Background, true
			}
		}

		if foundForeground && foundBackground {
			break
		}
	}

	if !foundForeground {
		// The text is painted in the client's own colour, which is not the
		// sender's to answer for.
		return csscolor.Color{}, csscolor.Color{}, false, false
	}

	if !foundBackground {
		// A message that paints a background somewhere and not here has a
		// background we did not find rather than none: a <style> rule may be
		// painting it, and this check does not read those. Only a message that
		// paints nothing anywhere is measured against the white every client
		// puts behind an email.
		if messagePaintsABackground {
			return csscolor.Color{}, csscolor.Color{}, false, false
		}

		background, assumed = csscolor.Color{R: 255, G: 255, B: 255, Alpha: 1}, true
	}

	// A colour that is not opaque would have to be composited with what is
	// behind it, which needs the stack of backgrounds this does not build.
	if !foreground.Opaque() || !background.Opaque() {
		return csscolor.Color{}, csscolor.Color{}, false, false
	}

	return foreground, background, assumed, true
}

// thresholdFor is the ratio WCAG AA asks of an element's text.
//
// The size is looked for up the tree, as the size is inherited. A size written
// in a relative unit is no size at all here, so the text is judged as normal
// text: that is the stricter of the two thresholds, and the one that cannot
// excuse a contrast by a size nobody established.
func thresholdFor(n *html.Node) float64 {
	bold := false
	size := 0.0
	found := false

	for node := n; node != nil && node.Type == html.ElementNode; node = node.Parent {
		style := readTextStyle(node)

		if style.Bold {
			bold = true
		}
		if !found && style.HasFontSize {
			size, found = style.FontSizePx, true
		}
	}

	if !found {
		// Nothing on the way up declared a size, so the client's own defaults
		// are what renders this, and for a heading those are known: the default
		// stylesheet every client inherits from sizes h1 at 2em and h2 at 1.5em,
		// both of them bold. Reading them as normal text would report a heading
		// for missing a bar the standard never held it to.
		//
		// It is only safe because nothing declared a size: had an ancestor set
		// one, the heading's em would be a multiple of that and not of 16px.
		if defaultSize, isHeading := defaultHeadingSizePx[n.Data]; isHeading {
			size, found, bold = defaultSize, true, true
		}
	}

	if !found {
		return contrastThresholdNormal
	}

	if atLeastPx(size, largeTextPx) || (bold && atLeastPx(size, largeBoldTextPx)) {
		return contrastThresholdLarge
	}

	return contrastThresholdNormal
}

// defaultHeadingSizePx is what a heading renders at when nothing says otherwise,
// from the default stylesheet, in the pixels a 16px root gives.
//
// h4 and below are left out because they are not large text by any threshold:
// h4 renders at 16px, under the 18.67px even bold text needs, so the ordinary
// bar applies to them and there is nothing to record here.
var defaultHeadingSizePx = map[string]float64{
	"h1": 32,    // 2em
	"h2": 24,    // 1.5em
	"h3": 18.72, // 1.17em
}

// atLeastPx compares two lengths in pixels, tolerating the last bit of floating
// point.
//
// The thresholds above are constant expressions, which the compiler evaluates
// exactly before rounding once; converting the same 14pt at run time rounds at
// every step and lands one bit below. Without the tolerance, text written at
// exactly the size the standard names falls on the wrong side of its own bar.
func atLeastPx(size, threshold float64) bool {
	return size >= threshold-1e-9
}

// directText is the text an element holds itself, as opposed to the text of its
// descendants, cut short for a finding to quote.
//
// It is the element's own text that its declared colour paints: a <div> wrapping
// a paragraph paints nothing, and attributing the paragraph's text to it would
// report one run as two.
func directText(n *html.Node) string {
	if n.Data == "style" || n.Data == "script" || n.Data == "title" {
		return ""
	}

	var written strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			written.WriteString(child.Data)
		}
	}

	text := strings.Join(strings.Fields(written.String()), " ")
	if !strings.ContainsFunc(text, unicode.IsLetter) && !strings.ContainsFunc(text, unicode.IsDigit) {
		// Punctuation and spacing carry no text a reader has to make out.
		return ""
	}

	if utf8.RuneCountInString(text) > 60 {
		text = strings.TrimSpace(string([]rune(text)[:57])) + "..."
	}

	return text
}

// contrastFinding is one colour pair the message failed on, and where.
type contrastFinding struct {
	Run textRun

	// Ratio is what the pair measures, and Occurrences how many runs were
	// painted with it.
	Ratio       float64
	Occurrences int
}

// lowContrastFindings reports the colour pairs the message paints text with that
// WCAG AA refuses.
//
// One finding per pair, not per run: a stylesheet's grey is one decision the
// sender made, however many paragraphs it was applied to, and a finding per
// paragraph would bury the rest of the report.
func lowContrastFindings(root *html.Node) []reading.Finding {
	type pair struct {
		foreground, background string
		threshold              float64
	}

	failures := make(map[pair]*contrastFinding)
	var order []pair

	for _, run := range contrastRuns(root) {
		ratio := csscolor.ContrastRatio(run.Foreground, run.Background)
		if ratio >= run.Threshold {
			continue
		}

		key := pair{foreground: run.Foreground.Hex(), background: run.Background.Hex(), threshold: run.Threshold}
		failure, seen := failures[key]
		if !seen {
			failures[key] = &contrastFinding{Run: run, Ratio: ratio, Occurrences: 1}
			order = append(order, key)
			continue
		}
		failure.Occurrences++
	}

	// Worst first, and the order the runs were met in to settle a tie: the
	// report must read the same way twice over one message.
	slices.SortStableFunc(order, func(a, b pair) int {
		if failures[a].Ratio < failures[b].Ratio {
			return -1
		}
		if failures[a].Ratio > failures[b].Ratio {
			return 1
		}

		return 0
	})

	findings := make([]reading.Finding, 0, len(order))
	for _, key := range order {
		findings = append(findings, contrastContentFinding(*failures[key]))
	}

	return findings
}

// contrastContentFinding writes up one colour pair.
func contrastContentFinding(failure contrastFinding) reading.Finding {
	run := failure.Run

	message := fmt.Sprintf("Text in %s on %s measures %.2f:1, below the %.1f:1 WCAG AA asks of it",
		run.Foreground.Hex(), run.Background.Hex(), failure.Ratio, run.Threshold)
	if failure.Occurrences > 1 {
		message += fmt.Sprintf(" (%d places)", failure.Occurrences)
	}
	if run.BackgroundAssumed {
		message += ", measured against the white a client paints behind a message that sets no background of its own"
	}
	message += "."

	advice := "Darken the text or lighten what is behind it until the pair reaches " +
		fmt.Sprintf("%.1f:1", run.Threshold)
	if run.Threshold == contrastThresholdLarge {
		advice += "; this text is large enough for the lower WCAG AA bar and misses it even so"
	}

	return reading.Finding{
		Defect: defectLowContrast,
		Issue: model.Issue{
			Type:     model.IssueTypeLowContrast,
			Severity: contrastSeverity(failure.Ratio),
			Message:  message,
			Advice:   utils.PtrTo(advice),
			Location: utils.PtrTo(fmt.Sprintf("%q", run.Text)),
		},
		// The spam filter reports the extreme of this as R_WHITE_ON_WHITE.
		// Sharing a key lets the two be read as one defect, ours carrying the
		// ratio and the colours it measured, and the filter's agreement noted
		// on it.
		Concern: "low_contrast",
	}
}

// contrastSeverity weighs a pair by how far below the bar it falls.
//
// Below three to one, no size of text carries: that is a pair WCAG refuses
// outright, and the reader who cannot make it out cannot ask their client to
// help. Above it, the text is readable by most and lost to some, which is the
// medium of this scale.
func contrastSeverity(ratio float64) model.IssueSeverity {
	if ratio < contrastThresholdLarge {
		return model.IssueSeverityHigh
	}

	return model.IssueSeverityMedium
}
