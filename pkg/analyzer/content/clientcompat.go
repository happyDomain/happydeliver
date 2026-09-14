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
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/emaildata/caniemail"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// cssOrigin says where in the message a style was written, which is what a
// finding's location quotes: the same property is a different thing to fix in a
// stylesheet the sender controls and in an attribute their template generates.
type cssOrigin uint8

const (
	// originStyleElement is inside a <style> element.
	originStyleElement cssOrigin = iota

	// originStyleAttribute is in a style="…" attribute.
	originStyleAttribute

	// originStylesheetLink is a <link rel="stylesheet"> that serves the styles
	// rather than writing them. Nothing of its content is read: it is named for
	// what the URL says it is.
	originStylesheetLink
)

func (o cssOrigin) String() string {
	switch o {
	case originStyleElement:
		return "<style> element"
	case originStyleAttribute:
		return "style attribute"
	case originStylesheetLink:
		return "linked stylesheet"
	default:
		return "markup"
	}
}

// markupHarvest is everything the compatibility check reads off the tree,
// gathered in one walk.
//
// It is collected here rather than during Analyzer.traverseHTML because
// nothing else in the analysis needs the vocabulary of CSS: the declarations,
// the at-rules and the stylesheet hrefs are this check's business alone, and
// Results is no poorer for not learning them.
type markupHarvest struct {
	// Sheets is the text of every <style> element, and Inline every style
	// attribute, one entry per element carrying one.
	//
	// Identical attribute values are deliberately not folded together: what a
	// finding reports is how many places a feature was written, and forty cells
	// sharing one style are forty places a reader looks at.
	Sheets []string
	Inline []string

	// StylesheetHrefs is every <link rel="stylesheet"> href. Only the web font
	// services are recognised among them: an external stylesheet as such is
	// htmlRemarkCheck's finding, not ours, and reporting it twice would say the
	// same thing to the sender in two places.
	StylesheetHrefs []string

	// Viewport is the content of the <meta name="viewport">, and HasViewport
	// whether the message carried one at all: no viewport and an empty one are
	// two different mistakes, and only the first has an excuse.
	Viewport    string
	HasViewport bool

	// Handlers is every on* attribute found, named with the element it was
	// written on, as in "onclick on <a>".
	Handlers []string

	// HasBody says the walk saw a <body>, so that a fragment carrying no
	// document structure is not told its viewport is missing.
	HasBody bool

	// StyleInBody says a <style> element was written under the <body> rather
	// than in the head, which is a thing of its own: a client that reads
	// stylesheets at all may still refuse one it finds there.
	StyleInBody bool

	// Tags counts the elements the message is built from, so that the features
	// the dataset tracks by element can be looked up without a second walk.
	// Only the ones a table names are kept.
	Tags map[string]int

	// AnchorHrefs is every href pointing inside the message itself. A bare "#"
	// is left out: it designates nothing, and a link to nowhere is a defect the
	// link checks answer for, not this one.
	AnchorHrefs []string
}

// eventHandlerAttribute matches an on* attribute name.
//
// It is deliberately broader than a list of the known events: an invented
// "onwhatever" is markup no client runs either, and a list of events would be
// one more thing to keep up with the web platform for no gain.
var eventHandlerAttribute = regexp.MustCompile(`^on[a-z]{2,}$`)

// harvestMarkup reads the tree once for everything the check looks at.
func harvestMarkup(root *html.Node) markupHarvest {
	var harvest markupHarvest

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			harvest.readElement(n)
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)

	return harvest
}

// readElement takes off one element what the harvest keeps.
func (h *markupHarvest) readElement(n *html.Node) {
	if _, named := markupTagIndex()[n.Data]; named {
		if h.Tags == nil {
			h.Tags = make(map[string]int)
		}
		h.Tags[n.Data]++
	}

	switch n.Data {
	case "body":
		h.HasBody = true

	case "a":
		// A destination inside the message itself, which is not a destination
		// every client can reach.
		if href := strings.TrimSpace(getAttrOf(n, "href")); len(href) > 1 && strings.HasPrefix(href, "#") {
			h.AnchorHrefs = append(h.AnchorHrefs, href)
		}

	case "style":
		// Where the element sits decides part of its fate, so the walk notes it
		// on the way past rather than looking the element up again later.
		if hasAncestorElement(n, "body") {
			h.StyleInBody = true
		}
		// A <style> element holds text, not children: what it says is the
		// concatenation of the text nodes under it.
		var declarations strings.Builder
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if child.Type == html.TextNode {
				declarations.WriteString(child.Data)
			}
		}
		if text := strings.TrimSpace(declarations.String()); text != "" {
			h.Sheets = append(h.Sheets, text)
		}

	case "link":
		rel := strings.ToLower(getAttrOf(n, "rel"))
		href := getAttrOf(n, "href")
		if strings.Contains(rel, "stylesheet") && href != "" {
			h.StylesheetHrefs = append(h.StylesheetHrefs, href)
		}

	case "meta":
		if strings.EqualFold(getAttrOf(n, "name"), "viewport") {
			h.HasViewport = true
			h.Viewport = strings.TrimSpace(getAttrOf(n, "content"))
		}
	}

	for _, attr := range n.Attr {
		key := strings.ToLower(attr.Key)

		if key == "style" {
			if declarations := strings.TrimSpace(attr.Val); declarations != "" {
				h.Inline = append(h.Inline, declarations)
			}
			continue
		}

		if eventHandlerAttribute.MatchString(key) {
			h.Handlers = append(h.Handlers, fmt.Sprintf("%s on <%s>", key, n.Data))
		}
	}
}

// hasAncestorElement says whether a node sits anywhere under an element of the
// given name.
func hasAncestorElement(n *html.Node, name string) bool {
	for parent := n.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == name {
			return true
		}
	}

	return false
}

// cssObservation is one thing found in the message's styles that the table
// below names.
type cssObservation struct {
	// Slug is the Can I email feature this is an instance of.
	Slug string

	// Origin is where it was written, and Text how it read, for the location.
	Origin cssOrigin
	Text   string

	// URL is the font's address, for the features that name one. It is empty
	// for everything else.
	URL string
}

// observeCSS reads a stylesheet or a style attribute and reports the features
// of the table it contains.
//
// Malformed CSS is not an error here. The CSS of an email is broken often
// enough that refusing to answer on it would silence the check on the very
// messages that most need it; the parser has already yielded everything it
// could read by the time it stops, and markup that does not read is what
// brokenHTMLCheck answers for.
func observeCSS(source string, origin cssOrigin, inline bool) []cssObservation {
	features := compatIndex()

	var observed []cssObservation

	parser := css.NewParser(parse.NewInputString(source), inline)

	// The at-rule we are inside of, and where its observation sits, so that the
	// "src" of an @font-face is attributed to the font rather than reported as
	// a property of its own.
	var openAtRules []string
	fontFaceAt := -1

	for {
		grammar, _, data := parser.Next()

		switch grammar {
		case css.ErrorGrammar:
			return observed

		case css.AtRuleGrammar, css.BeginAtRuleGrammar:
			keyword := unprefixCSSName(strings.TrimPrefix(strings.ToLower(string(data)), "@"))

			if grammar == css.BeginAtRuleGrammar {
				openAtRules = append(openAtRules, keyword)
			}

			feature, known := features.atRules[keyword]
			if !known {
				continue
			}

			observation := cssObservation{
				Slug:   feature.Slug,
				Origin: origin,
				Text:   "@" + keyword,
				URL:    firstURLIn(parser.Values()),
			}

			if keyword == "font-face" {
				fontFaceAt = len(observed)
			}

			observed = append(observed, observation)

		case css.EndAtRuleGrammar:
			if len(openAtRules) > 0 {
				if openAtRules[len(openAtRules)-1] == "font-face" {
					fontFaceAt = -1
				}
				openAtRules = openAtRules[:len(openAtRules)-1]
			}

		case css.DeclarationGrammar:
			property := unprefixCSSName(strings.ToLower(string(data)))
			values := parser.Values()

			// The address an @font-face downloads is the font's, and belongs to
			// the finding about the font.
			if property == "src" && fontFaceAt >= 0 {
				if fontURL := firstURLIn(values); fontURL != "" && observed[fontFaceAt].URL == "" {
					observed[fontFaceAt].URL = fontURL
				}
				continue
			}

			for _, feature := range features.properties[property] {
				if !feature.matches(values) {
					continue
				}

				observed = append(observed, cssObservation{
					Slug:   feature.Slug,
					Origin: origin,
					Text:   declarationText(property, values),
				})
			}
		}
	}
}

// compatFeature maps something written in a message's styles to the Can I email
// feature that says who will not render it.
//
// It is a curated list, not the whole dataset. Of the three hundred features
// upstream tracks, the ones worth a sender's attention are those they reach for
// and a client drops silently; confronting every property a message writes with
// the data would report border-radius and box-shadow on nearly every message,
// which is noise wearing the clothes of coverage. Growing it is a matter of
// adding a row, and every Slug here must exist in the data, which
// TestCompatFeatureSlugsAreKnown holds it to.
type compatFeature struct {
	// Slug is the Can I email feature, and no two rows name the same one: a row
	// is what a finding is written from, so two rows sharing a slug would be two
	// pieces of advice for one finding, and only one of them would be read.
	Slug string

	// Properties are the declaration names, lowercased and with any vendor
	// prefix removed, that this one feature is written as. There is more than
	// one where the dataset tracks them together: grid-template-columns, -rows
	// and -areas are one thing to report and one thing to do instead.
	//
	// It is empty for a feature written as an at-rule.
	Properties []string

	// Values narrows the match, because a property alone often says nothing:
	// "display" is universal, "display:flex" is not. Empty matches any value,
	// which is the explicit statement that the property itself is the risk.
	Values []string

	// AtRule is the at-keyword without its "@", for a feature written as one.
	AtRule string

	// Impact is the worst this feature's loss can be said to be, and so the
	// severity a finding about it reaches when a major client drops it.
	//
	// It is declared per row because breadth alone cannot decide it. Every
	// feature in this table is dropped by Gmail or by Outlook, which is what
	// earned it a row, so a severity read off the client list alone would
	// mark all of them equally grave, and a typeface falling back to Arial
	// would be reported beside a layout collapsing into one column. What
	// differs between them is not who fails but what the reader loses.
	//
	// Nothing here reaches "critical" or "high": those say the message did not
	// arrive as a message, and a dropped property never does that.
	Impact model.ContentIssueSeverity

	// Advice is what the sender is to do instead. It is written here rather
	// than taken from the dataset, whose descriptions document a feature for a
	// browser-minded reader and advise nothing.
	Advice string
}

// matches says whether a declaration's value is one this row narrows to.
func (f compatFeature) matches(values []css.Token) bool {
	if len(f.Values) == 0 {
		return true
	}

	return slices.Contains(f.Values, firstIdentifierIn(values))
}

// compatFeatures is what the check looks for. The order is the order the
// findings are read in, so the layout properties come before the fonts: a
// message whose columns collapse has a worse problem than one whose typeface
// falls back.
var compatFeatures = []compatFeature{
	{
		Slug:       "css-position",
		Properties: []string{"position"},
		// Not "relative", which is written constantly and behaves where it is
		// supported at all. What breaks a layout is taking an element out of
		// the flow and expecting it to stay where it was put.
		Values: []string{"absolute", "fixed", "sticky"},
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Place the element with nested tables, cell padding and spacer rows instead; where position is dropped the element falls back into the document flow",
	},
	{
		Slug:       "css-display-flex",
		Properties: []string{"display"},
		Values:     []string{"flex", "inline-flex"},
		Impact:     model.ContentIssueSeverityMedium,
		Advice:     "Lay the row out as a table with one cell per column; flexbox is dropped rather than approximated, so its children stack into a single column",
	},
	{
		Slug:       "css-display-grid",
		Properties: []string{"display"},
		Values:     []string{"grid", "inline-grid"},
		Impact:     model.ContentIssueSeverityMedium,
		Advice:     "Lay the grid out as a table, one row per row and one cell per cell; a client that does not know grid keeps the children and loses their positions",
	},
	{
		Slug:       "css-flex-direction",
		Properties: []string{"flex-direction"},
		Impact:     model.ContentIssueSeverityLow,
		Advice:     "Decide the order in the markup rather than in the styles; where flex-direction is dropped the children appear in the order they are written",
	},
	{
		Slug: "css-grid-template",
		// The dataset tracks the three of them as one feature, and so does the
		// advice: whichever is written, what to do instead is the same.
		Properties: []string{"grid-template-columns", "grid-template-rows", "grid-template-areas"},
		Impact:     model.ContentIssueSeverityMedium,
		Advice:     "Give the rows and cells their sizes as a table instead; where the grid template is dropped, every child sizes and places itself",
	},
	{
		Slug:   "css-at-font-face",
		AtRule: "font-face",
		Impact: model.ContentIssueSeverityLow,
		Advice: "Name a web-safe font first in every font-family and treat the downloaded one as a bonus; a client that ignores @font-face falls back to a font of its own choosing",
	},
	{
		Slug:   "css-at-import",
		AtRule: "import",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Inline the imported rules instead; an @import is a second fetch, and the clients that strip it render the message without those rules",
	},
}

// markupFeature maps an element the message is built from to the Can I email
// feature that says who will not render it.
//
// It is a table apart from compatFeatures because it matches on something else
// entirely: a tag name, which the walk has in hand, rather than a declaration
// the CSS parser had to read. What is done with the two is the same, and the
// writing of a finding is shared.
type markupFeature struct {
	// Slug is the Can I email feature, and Tag the element it is written as.
	Slug string
	Tag  string

	// Impact and Advice mean what they mean in compatFeature.
	Impact model.ContentIssueSeverity
	Advice string
}

// markupFeatures is the elements worth reporting. The rule for a row here is
// the rule for the CSS table: a sender reaches for it and a client drops it
// silently. Which is why <div> and <table> are absent and <marquee> is not.
var markupFeatures = []markupFeature{
	{
		Slug:   "html-video",
		Tag:    "video",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Show a still image linking to the video on a page instead, and keep the <video> only for the clients that support it; where the element is dropped, so is everything inside it",
	},
	{
		Slug:   "html-audio",
		Tag:    "audio",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Link to the recording on a page rather than embedding it; where the element is dropped the recipient has no way to reach it",
	},
	{
		Slug:   "html-picture",
		Tag:    "picture",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Serve one image an <img> can show, sized for the smallest screen; a client that does not know <picture> keeps only the <img> inside it, and nothing if there is none",
	},
	{
		Slug:   "html-svg",
		Tag:    "svg",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Export the drawing as a PNG and reference it with <img>; most clients strip inline SVG, leaving the space it occupied empty",
	},
	{
		Slug:   "html-marquee",
		Tag:    "marquee",
		Impact: model.ContentIssueSeverityLow,
		Advice: "Say it in text that stays still; the element is obsolete, and a client that keeps it prints its content where it stands",
	},
}

// markupTagIndex is markupFeatures keyed by tag, built once. The walk consults
// it on every element, so it must not be a scan of the table.
var markupTagIndex = sync.OnceValue(func() map[string]markupFeature {
	index := make(map[string]markupFeature, len(markupFeatures))
	for _, feature := range markupFeatures {
		index[feature.Tag] = feature
	}

	return index
})

// imageFormatFeature maps the format an image is served in to the Can I email
// feature that says who will not display it.
//
// An image that does not display is the same hole in the message as one that
// never answered, which the images criterion already grades. The difference is
// that the server answered perfectly well here: nothing but this says the
// recipient sees an empty box.
type imageFormatFeature struct {
	// Slug is the Can I email feature, and Name the format as a sender knows it.
	Slug string
	Name string

	// Suffixes are the extensions the source may end in, and Scheme the URL
	// scheme that is the format, as a data: URI is.
	Suffixes []string
	Scheme   string

	// Impact and Advice mean what they mean in compatFeature.
	Impact model.ContentIssueSeverity
	Advice string
}

// imageFormatFeatures is the formats worth reporting. PNG, JPEG and GIF are
// absent because no client the dataset knows refuses them, which is the same
// reason they would report nothing if they were here.
//
// What is read is what the message claims: the scheme of a source, or the
// extension it ends in. A server is free to answer a .png URL with WebP, and
// that goes unnoticed here; the mistake it makes is silence, not a false
// report, and the response's own Content-Type is what would close it.
var imageFormatFeatures = []imageFormatFeature{
	{
		Slug:   "image-base64",
		Name:   "an inline data: URI",
		Scheme: "data",
		Impact: model.ContentIssueSeverityMedium,
		Advice: "Host the image and reference it by URL; a client that refuses a data: URI rewrites the src into nosrc, so nothing is displayed and nothing can be loaded",
	},
	{
		Slug:     "image-avif",
		Name:     "AVIF",
		Suffixes: []string{".avif"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Serve PNG or JPEG instead, and keep AVIF for the web; a client that cannot decode it shows an empty box",
	},
	{
		Slug:     "image-webp",
		Name:     "WebP",
		Suffixes: []string{".webp"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Serve PNG or JPEG instead; a client that does not decode WebP shows an empty box",
	},
	{
		Slug:     "image-svg",
		Name:     "SVG",
		Suffixes: []string{".svg"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Export the drawing as a PNG at twice the size it is displayed at; a client that does not support SVG displays nothing rather than rasterising it",
	},
	{
		Slug:     "image-heif",
		Name:     "HEIF",
		Suffixes: []string{".heif", ".heic"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Convert to PNG or JPEG; HEIF is a camera format that email clients do not display",
	},
	{
		Slug:     "image-tiff",
		Name:     "TIFF",
		Suffixes: []string{".tiff", ".tif"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Convert to PNG or JPEG; most clients do not display TIFF",
	},
	{
		Slug:     "image-mp4",
		Name:     "an MP4 video",
		Suffixes: []string{".mp4"},
		Impact:   model.ContentIssueSeverityMedium,
		Advice:   "Use an animated GIF for the motion, or a still image linking to the video; an <img> pointed at an MP4 shows nothing in the clients that do not play it",
	},
	{
		Slug:     "image-bmp",
		Name:     "BMP",
		Suffixes: []string{".bmp"},
		Impact:   model.ContentIssueSeverityLow,
		Advice:   "Convert to PNG, which is also lossless and much smaller",
	},
	{
		Slug:     "image-ico",
		Name:     "an icon file",
		Suffixes: []string{".ico"},
		Impact:   model.ContentIssueSeverityLow,
		Advice:   "Reference a PNG instead; a client that does not display an .ico leaves a gap",
	},
	{
		Slug:     "image-apng",
		Name:     "APNG",
		Suffixes: []string{".apng"},
		Impact:   model.ContentIssueSeverityLow,
		Advice:   "Use an animated GIF, or a still PNG if the motion is decorative; a client that does not know APNG shows the first frame at best",
	},
}

// compatIndexes is compatFeatures arranged for lookup: by property for a
// declaration, by at-keyword for an at-rule.
type compatIndexes struct {
	properties map[string][]compatFeature
	atRules    map[string]compatFeature
}

// compatIndex is the table indexed once. It is built lazily like the dataset it
// is read against, so that a message carrying no styles pays for neither.
var compatIndex = sync.OnceValue(func() compatIndexes {
	indexes := compatIndexes{
		properties: make(map[string][]compatFeature),
		atRules:    make(map[string]compatFeature),
	}

	for _, feature := range compatFeatures {
		if feature.AtRule != "" {
			indexes.atRules[feature.AtRule] = feature
			continue
		}
		for _, property := range feature.Properties {
			indexes.properties[property] = append(indexes.properties[property], feature)
		}
	}

	return indexes
})

// webFontHosts are the services that serve a downloaded font behind a
// stylesheet link. A message linking one is asking for a web font as surely as
// one writing @font-face, and is answered for by the same feature: what the
// client does not do is fetch the font.
var webFontHosts = []string{
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"fonts.bunny.net",
	"use.typekit.net",
	"use.typography.com",
	"fast.fonts.net",
	"cloud.typography.com",
	"fonts.adobe.com",
}

// isWebFontStylesheet says whether a stylesheet link serves a font rather than
// a design. A host nobody recognises is not one: an ordinary external
// stylesheet is htmlRemarkCheck's finding.
func isWebFontStylesheet(href string) bool {
	parsed, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())

	return slices.Contains(webFontHosts, host)
}

// firstIdentifierIn is the first identifier of a declaration's value, which is
// what a row's Values are compared against: "flex" of "flex", and of
// "flex !important".
func firstIdentifierIn(values []css.Token) string {
	for _, value := range values {
		if value.TokenType == css.IdentToken {
			return strings.ToLower(string(value.Data))
		}
	}

	return ""
}

// firstURLIn is the first address a value names, whether it was written as
// url(…) or as a bare string, as an @import may.
func firstURLIn(values []css.Token) string {
	for _, value := range values {
		switch value.TokenType {
		case css.URLToken:
			// The token is the whole "url(…)" construct.
			raw := string(value.Data)
			if open := strings.IndexByte(raw, '('); open >= 0 {
				raw = raw[open+1:]
			}
			raw = strings.TrimSuffix(raw, ")")

			return strings.Trim(strings.TrimSpace(raw), `"'`)
		case css.StringToken:
			return strings.Trim(string(value.Data), `"'`)
		}
	}

	return ""
}

// declarationText writes a declaration back out for the location to quote,
// space collapsed and cut short: the point is to recognise the line in the
// source, not to reproduce it.
func declarationText(property string, values []css.Token) string {
	var written strings.Builder
	for _, value := range values {
		written.WriteString(string(value.Data))
	}

	return truncate(property+": "+strings.Join(strings.Fields(written.String()), " "), 80)
}

// truncate cuts a quoted text short without splitting a character in two: the
// location is read by a person and written out as JSON, and half a character is
// neither.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}

	cut := limit - len("...")
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}

	return text[:cut] + "..."
}

// unprefixCSSName drops a vendor prefix, so that -webkit-flex-direction is read
// as the property it is a dialect of. A prefixed property is no better
// supported than the one it prefixes, and often worse.
func unprefixCSSName(name string) string {
	for _, prefix := range []string{"-webkit-", "-moz-", "-ms-", "-o-"} {
		if trimmed, found := strings.CutPrefix(name, prefix); found {
			return trimmed
		}
	}

	return name
}

// compatOccurrence is every place one feature was written.
type compatOccurrence struct {
	// Count is how many declarations named it, and Origins where they were.
	Count   int
	Origins []cssOrigin

	// Text is how the first of them read, and URL the address the first one
	// that named one gave.
	Text string
	URL  string
}

// clientCompatFindings is what the check reports: one finding per feature the
// message uses and some client drops, plus the two rules the dataset does not
// cover.
//
// The images are handed in rather than harvested: the analysis already read
// every one of them off the message, and reading them again here would be a
// second list of the same thing to keep in step with the first.
func clientCompatFindings(harvest markupHarvest, images []ImageCheck) []reading.Finding {
	observed := make([]cssObservation, 0, len(harvest.Sheets)+len(harvest.Inline))

	for _, sheet := range harvest.Sheets {
		observed = append(observed, observeCSS(sheet, originStyleElement, false)...)
	}
	for _, declarations := range harvest.Inline {
		observed = append(observed, observeCSS(declarations, originStyleAttribute, true)...)
	}
	for _, href := range harvest.StylesheetHrefs {
		if isWebFontStylesheet(href) {
			observed = append(observed, cssObservation{
				Slug:   "css-at-font-face",
				Origin: originStylesheetLink,
				Text:   href,
				URL:    href,
			})
		}
	}

	findings := make([]reading.Finding, 0, len(compatFeatures))

	// What the styles say first, then what the markup is made of, then what the
	// message asks a client to fetch, and our own two rules last: the order is
	// the report's argument, from what was written to what was linked.
	findings = append(findings, featureFindings(observed)...)
	findings = append(findings, styleElementFindings(harvest)...)
	findings = append(findings, markupTagFindings(harvest)...)
	findings = append(findings, imageFormatFindings(images)...)

	// The rules that report at most one finding say a message is fine by
	// reporting none.
	for _, finding := range []*reading.Finding{
		anchorLinkFinding(harvest),
		viewportFinding(harvest),
		eventHandlerFinding(harvest),
	} {
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// styleElementFindings reports what the <style> element itself risks.
//
// It is the gravest thing in this file and the least visible. Six clients drop
// the element, Gmail among them, and the dataset's own notes say exactly when:
// "not supported with non Google accounts", and "not supported inside the
// <body>". A message whose whole design lives in a <style> block therefore
// arrives at those readers as unstyled text, not as a message missing one
// property.
//
// Which is why this asks a different question from every other rule here: not
// "is this feature used" but "is anything else holding the design up".
func styleElementFindings(harvest markupHarvest) []reading.Finding {
	if len(harvest.Sheets) == 0 {
		return nil
	}

	verdict, reported := reportableVerdict("html-style")
	if !reported {
		return nil
	}

	var findings []reading.Finding

	// Nothing inline means nothing survives the element being dropped. A message
	// that also inlines its styles loses the refinements and keeps the design,
	// which is the difference worth reporting on.
	if len(harvest.Inline) == 0 {
		findings = append(findings, verdictFinding(
			fmt.Sprintf("The whole design is in %s and nothing is inlined",
				counted(len(harvest.Sheets), "a <style> element", "<style> elements")),
			model.ContentIssueSeverityMedium,
			"Inline the styles that carry the layout onto the elements themselves, and keep the <style> element for what only it can do, such as media queries; a client that drops it then costs the message its refinements rather than all of its design",
			verdict, "<style> element"))
	}

	if harvest.StyleInBody {
		findings = append(findings, verdictFinding(
			"A <style> element is written inside the body",
			model.ContentIssueSeverityLow,
			"Move the element into the <head>: a client that accepts a stylesheet at all may still refuse one it finds in the body, and there is nothing to gain by putting it there",
			verdict, "<body>"))
	}

	return findings
}

// markupTagFindings reports the elements the message is built from that the
// dataset says are dropped.
func markupTagFindings(harvest markupHarvest) []reading.Finding {
	var findings []reading.Finding
	// The table's order, so that one message reads the same way twice.
	for _, feature := range markupFeatures {
		count := harvest.Tags[feature.Tag]
		if count == 0 {
			continue
		}

		verdict, reported := reportableVerdict(feature.Slug)
		if !reported {
			continue
		}

		findings = append(findings, verdictFinding(
			fmt.Sprintf("The HTML uses <%s> in %s", feature.Tag, counted(count, "one place", "places")),
			feature.Impact, feature.Advice, verdict, fmt.Sprintf("<%s>", feature.Tag)))
	}

	return findings
}

// imageFormatFindings reports the images served in a format some client will not
// display.
//
// An image is fetched the moment the message is opened, with no click, so a
// format a client cannot decode is a hole the recipient sees straight away,
// exactly as a source that never answered is. The difference is that here the
// server answered.
func imageFormatFindings(images []ImageCheck) []reading.Finding {
	if len(images) == 0 {
		return nil
	}

	var findings []reading.Finding
	// The table's order again, and the sources within a format in the order the
	// message wrote them.
	for _, feature := range imageFormatFeatures {
		var matched []string
		for _, image := range images {
			if feature.matchesSource(image.Src) {
				matched = append(matched, image.Src)
			}
		}
		if len(matched) == 0 {
			continue
		}

		verdict, reported := reportableVerdict(feature.Slug)
		if !reported {
			continue
		}

		subject := fmt.Sprintf("%s %s served as %s",
			counted(len(matched), "One image", "images"), agree(len(matched), "is", "are"), feature.Name)

		finding := verdictFinding(subject, feature.Impact, feature.Advice, verdict, shortSource(matched[0]))

		// Scoped to the source, so that anything else observing the same image
		// is recognised as observing the same defect.
		finding.Concern = concernForURL("image_format", matched[0])

		findings = append(findings, finding)
	}

	return findings
}

// matchesSource says whether an image source is written in this format, as far
// as the message itself says so.
func (f imageFormatFeature) matchesSource(src string) bool {
	src = strings.TrimSpace(src)
	if src == "" {
		return false
	}

	if f.Scheme != "" {
		return strings.HasPrefix(strings.ToLower(src), f.Scheme+":")
	}

	// The path decides, not the query: a URL may carry anything after the "?",
	// including another URL's extension.
	path := strings.ToLower(src)
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}

	return slices.ContainsFunc(f.Suffixes, func(suffix string) bool {
		return strings.HasSuffix(path, suffix)
	})
}

// shortSource is an image source as a location quotes it: a data: URI is named
// rather than reproduced, being as long as the image it holds.
func shortSource(src string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(src)), "data:") {
		return "an inline data: URI"
	}

	return truncate(src, 80)
}

// anchorLinkFinding reports the links that point inside the message.
//
// It is the one finding here a sender is least likely to expect, the table of
// contents at the top of a long newsletter being a thing that plainly works
// everywhere else. The dataset's notes are worth the reading: one client adds
// target=_blank so the anchor opens a window, and another sends the reader back
// to the webmail's own home page, its navigation using anchors too.
func anchorLinkFinding(harvest markupHarvest) *reading.Finding {
	if len(harvest.AnchorHrefs) == 0 {
		return nil
	}

	verdict, reported := reportableVerdict("html-anchor-links")
	if !reported {
		return nil
	}

	count := len(harvest.AnchorHrefs)

	finding := verdictFinding(
		fmt.Sprintf("%s %s to %s inside the message itself",
			counted(count, "One link", "links"), agree(count, "points", "point"),
			agree(count, "an anchor", "anchors")),
		model.ContentIssueSeverityLow,
		"Link to a page instead of to a place in the message, or accept that the jump does nothing: where anchors are not followed the reader stays where they were, and one webmail sends them to its own home page",
		verdict, harvest.AnchorHrefs[0])

	return &finding
}

// featureFindings groups the observations by feature and asks the dataset about
// each.
//
// One finding per feature, never one per declaration: a newsletter built on
// flexbox has forty declarations and one defect, and telling the sender forty
// times would bury everything else the report says.
func featureFindings(observed []cssObservation) []reading.Finding {
	occurrences := make(map[string]*compatOccurrence, len(observed))
	for _, observation := range observed {
		occurrence, seen := occurrences[observation.Slug]
		if !seen {
			occurrence = &compatOccurrence{Text: observation.Text}
			occurrences[observation.Slug] = occurrence
		}

		occurrence.Count++
		if !slices.Contains(occurrence.Origins, observation.Origin) {
			occurrence.Origins = append(occurrence.Origins, observation.Origin)
		}
		if occurrence.URL == "" {
			occurrence.URL = observation.URL
		}
	}

	var findings []reading.Finding
	// The table's order, not the map's: the report must read the same way twice.
	for _, feature := range compatFeatures {
		occurrence, used := occurrences[feature.Slug]
		if !used {
			continue
		}

		verdict, reported := reportableVerdict(feature.Slug)
		if !reported {
			continue
		}

		findings = append(findings, compatFinding(feature, verdict, occurrence))
	}

	return findings
}

// compatFinding writes up one feature of the CSS table.
func compatFinding(feature compatFeature, verdict caniemail.Verdict, occurrence *compatOccurrence) reading.Finding {
	title := verdict.Title
	if title == "" {
		title = strings.Join(feature.Properties, ", ")
	}

	subject := fmt.Sprintf("The styles use %s in %s", title, counted(occurrence.Count, "one place", "places"))

	location := describeOrigins(occurrence.Origins)
	if occurrence.Text != "" {
		location += " (" + occurrence.Text + ")"
	}

	finding := verdictFinding(subject, feature.Impact, feature.Advice, verdict, location)

	// A feature fetched from an address is scoped to that address, so it can be
	// recognised as one finding whoever else raises it. The feature names the
	// key: a font and an @import can name the same stylesheet, and keying both
	// on the fetching alone would leave one of the two to be swallowed by the
	// other. It is deliberately not keyed as "external_css" either:
	// htmlRemarkCheck already owns that key for the stylesheet itself.
	if occurrence.URL != "" {
		finding.Concern = concernForURL(feature.Slug, occurrence.URL)
	}

	return finding
}

// reportableVerdict is what the dataset says about a feature, when it has
// something to say: the caller reports nothing otherwise.
//
// A feature the data no longer holds is silence rather than an error here,
// because nobody at this point could say who fails it;
// TestCompatFeatureSlugsAreKnown is what makes a slug falling out of the
// dataset a failing test. A feature every client renders is not a defect
// either, which is how a row can stay in a table and stop speaking the day the
// clients catch up.
func reportableVerdict(slug string) (caniemail.Verdict, bool) {
	verdict, known := caniemail.Verdicts()[slug]
	if !known || (len(verdict.Unsupported) == 0 && len(verdict.Partial) == 0) {
		return caniemail.Verdict{}, false
	}

	return verdict, true
}

// verdictFinding writes a finding whose gravity the dataset decides.
//
// The subject is the clause naming what the message does, without its full
// stop ("The styles use display:flex in 3 places", "Two images are served as
// AVIF"): what follows it is the same sentence every time, because what follows
// is the dataset's answer and not ours.
func verdictFinding(subject string, impact model.ContentIssueSeverity, advice string, verdict caniemail.Verdict, location string) reading.Finding {
	var message string
	switch {
	case len(verdict.Unsupported) > 0:
		message = fmt.Sprintf("%s, which %s %s not support.",
			subject, listClients(verdict.Unsupported), agree(len(verdict.Unsupported), "does", "do"))
	default:
		message = fmt.Sprintf("%s, which %s support only in part.",
			subject, listClients(verdict.Partial))
	}

	if verdict.URL != "" {
		advice += "; the client-by-client detail is at " + verdict.URL
	}

	return reading.NewFinding(
		defectClientCompat,
		model.ContentIssueTypeClientCompat,
		compatSeverity(impact, verdict),
		location,
		message,
		advice,
	)
}

// majorClients are the clients whose refusal decides a severity, being the ones
// a general-audience list is mostly made of.
//
// Breadth alone would not do: the dataset tracks nineteen families, and
// counting them as nineteen equal votes would rank a feature three German
// webmail providers drop above one Gmail drops.
var majorClients = []string{"Gmail", "Outlook", "Apple Mail", "Yahoo! Mail", "Samsung Email"}

// compatSeverity weighs a finding by what the reader loses and by who makes
// them lose it, in that order.
//
// Breadth is the second term, not the first, and deliberately so: every feature
// of the table is dropped by Gmail or by Outlook, so breadth alone would answer
// the same thing about all of them. What the row declares its loss to be is the
// ceiling; how many clients, and which, is what brings a finding below it.
//
// A property Gmail drops is therefore reported at the row's full weight, one
// only LaPoste.net drops well under it, however often either is written: how
// many places a feature appears says how much work the fix is, not how much of
// the message is lost.
func compatSeverity(impact model.ContentIssueSeverity, verdict caniemail.Verdict) model.ContentIssueSeverity {
	if impact == "" {
		// A row that declares nothing is read at its most modest, rather than
		// at the gravest thing the scale can say.
		impact = model.ContentIssueSeverityLow
	}

	switch {
	case namesAMajorClient(verdict.Unsupported):
		return impact
	case len(verdict.Unsupported) >= 5:
		return lesserSeverity(impact, model.ContentIssueSeverityMedium)
	case len(verdict.Unsupported) > 0:
		return lesserSeverity(impact, model.ContentIssueSeverityLow)
	case namesAMajorClient(verdict.Partial):
		return lesserSeverity(impact, model.ContentIssueSeverityLow)
	default:
		return model.ContentIssueSeverityInfo
	}
}

// namesAMajorClient says whether a list of clients holds one of the major ones.
// The names carry a platform in parentheses when a family's platforms disagree,
// so the comparison is on the prefix.
func namesAMajorClient(clients []string) bool {
	for _, client := range clients {
		family, _, _ := strings.Cut(client, " (")
		if slices.Contains(majorClients, family) {
			return true
		}
	}

	return false
}

// listClients names the clients a finding is about: up to three of them, then
// how many others there are. The whole list belongs on the feature's page, not
// in one sentence of a report.
func listClients(clients []string) string {
	if len(clients) <= 3 {
		return joinWithAnd(clients)
	}

	rest := len(clients) - 3
	others := "other clients"
	if rest == 1 {
		others = "other client"
	}

	// Commas up to the count, and one "and" before it: the named clients are not
	// the end of the list, so they must not read as if they were.
	return strings.Join(clients[:3], ", ") + fmt.Sprintf(" and %d %s", rest, others)
}

// joinWithAnd writes a list the way a sentence does.
func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// counted writes a count and the thing it counts. Both forms are given at the
// call site rather than one derived from the other: a singular is not always
// the plural with a digit in front of it, and a sentence opening on a count
// wants the word where a log line wants the digit.
func counted(count int, one, many string) string {
	if count == 1 {
		return one
	}

	return fmt.Sprintf("%d %s", count, many)
}

// agree picks the form, of a verb or of the noun it governs, that goes with a
// count. Unlike counted it writes no number: the count is already in the
// sentence, where counted put it.
func agree(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

// describeOrigins says where the declarations were written.
func describeOrigins(origins []cssOrigin) string {
	written := make([]string, 0, len(origins))
	for _, origin := range origins {
		written = append(written, origin.String())
	}

	return joinWithAnd(written)
}

// viewportFinding reports what the viewport meta says, or that there is none.
//
// Can I email tracks no viewport feature, and rightly: the question is not
// whether a client supports the tag but whether the sender set it. So this rule
// is ours, and it is kept to the three things that are not a matter of taste.
func viewportFinding(harvest markupHarvest) *reading.Finding {
	// A fragment with no document structure is not a message missing its
	// viewport: it is a message whose HTML we were handed in pieces.
	if !harvest.HasBody {
		return nil
	}

	finding := func(category reading.Category, severity model.ContentIssueSeverity, message, advice string) *reading.Finding {
		found := reading.NewFinding(
			defectClientCompat,
			model.ContentIssueTypeClientCompat,
			severity,
			"<head>",
			message,
			advice,
		)
		found.Category = category

		return &found
	}

	directives := viewportDirectives(harvest.Viewport)

	switch {
	case !harvest.HasViewport || len(directives) == 0:
		return finding("", model.ContentIssueSeverityLow,
			"The HTML declares no viewport, so a phone renders it at desktop width and scales the result down.",
			`Add <meta name="viewport" content="width=device-width, initial-scale=1"> to the head; without it a mobile client renders at desktop width and scales the result down`)

	// A viewport that forbids zooming is not a rendering remark like the two
	// around it: the message renders, and the recipients it shuts out are the
	// ones who cannot read it at the size it was written. It answers to the
	// same reading as the missing alt text and the pale palette.
	case forbidsZooming(directives):
		return finding(reading.CategoryAccessibility, model.ContentIssueSeverityMedium,
			"The viewport forbids zooming, which a recipient who needs to enlarge the text cannot override.",
			"Drop user-scalable=no and maximum-scale from the viewport so the recipient can enlarge the text")

	case directives["width"] != "device-width":
		return finding("", model.ContentIssueSeverityLow,
			fmt.Sprintf("The viewport is set to %q, which does not adapt the message to the width of the screen it is read on.", harvest.Viewport),
			"Set the viewport to width=device-width so the layout follows the screen rather than a width fixed when the message was written")
	}

	return nil
}

// viewportDirectives reads the meta's content as what it is, a list of
// name=value pairs, rather than as a string to look for words in: a
// maximum-scale of 10 contains the maximum-scale of 1 that forbids zooming, and
// says the opposite of it.
//
// The pairs are separated by a comma or a semicolon, and messages are written
// both ways: read only the comma and "width=device-width; user-scalable=no"
// becomes one directive named width, with a value no client would honour and
// the refusal of zooming buried inside it.
func viewportDirectives(content string) map[string]string {
	directives := make(map[string]string)

	separated := strings.FieldsFunc(strings.ToLower(strings.Join(strings.Fields(content), "")), func(r rune) bool {
		return r == ',' || r == ';'
	})

	for _, directive := range separated {
		if directive == "" {
			continue
		}

		name, value, _ := strings.Cut(directive, "=")
		directives[name] = value
	}

	return directives
}

// forbidsZooming says whether the viewport denies a recipient the enlargement
// they may need, either by refusing it outright or by capping it below the
// doubling that reading at a comfortable size asks for.
func forbidsZooming(directives map[string]string) bool {
	switch directives["user-scalable"] {
	case "no", "0":
		return true
	}

	// A cap is only a cap if it parses as one: a value the client cannot read
	// is a value it ignores.
	if maximum, set := directives["maximum-scale"]; set {
		if scale, err := strconv.ParseFloat(maximum, 64); err == nil && scale < 2 {
			return true
		}
	}

	return false
}

// eventHandlerFinding reports the on* attributes.
//
// No email client runs JavaScript, so a handler is dead markup at best. It is
// reported here rather than beside the <script> tag because a sanitiser strips
// it quietly: the message arrives whole and does nothing, which is harder for a
// sender to notice than a blocked script.
func eventHandlerFinding(harvest markupHarvest) *reading.Finding {
	if len(harvest.Handlers) == 0 {
		return nil
	}

	attributes := harvest.Handlers
	if len(attributes) > 3 {
		attributes = attributes[:3]
	}

	message := fmt.Sprintf("The HTML carries %s (%s), which no email client runs.",
		counted(len(harvest.Handlers), "1 event-handler attribute", "event-handler attributes"),
		strings.Join(attributes, ", "))

	// Medium, for the same reason the defect is uncharged: nothing that ever
	// worked is lost. What is reported is that a behaviour was written into a
	// medium that has none, which is a mistake worth hearing about and not a
	// message that fails to arrive.
	found := reading.NewFinding(
		defectEventHandler,
		model.ContentIssueTypeClientCompat,
		model.ContentIssueSeverityMedium,
		harvest.Handlers[0],
		message,
		"Remove the handlers and move what they did to a page the message links to; email clients strip them, and those that keep them do not run them",
	)

	return &found
}
