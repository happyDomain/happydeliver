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
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/emaildata/caniemail"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// TestHarvestMarkup exercises the one walk the check makes over the tree.
func TestHarvestMarkup(t *testing.T) {
	document, err := parseHTML(`<html><head>
		<meta name="VIEWPORT" content="width=device-width, initial-scale=1">
		<style>.a{display:flex}</style>
		<style>   </style>
		<link rel="Stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
		<link rel="preload" href="https://example.com/not-a-sheet.css">
	</head><body>
		<div style="display:flex">one</div>
		<div style="display:flex">the same, counted again</div>
		<a href="https://example.com" onclick="go()" ONMOUSEOVER="hover()">go</a>
		<img src="https://example.com/a.png" style="  ">
	</body></html>`)
	if err != nil {
		t.Fatalf("the fixture does not parse: %v", err)
	}

	harvest := harvestMarkup(document)

	if len(harvest.Sheets) != 1 {
		t.Errorf("%d stylesheets harvested, want 1: an empty <style> carries nothing to read", len(harvest.Sheets))
	}

	// Two cells share one style, and both are kept: the count is what a finding
	// reports, and a reader looking for the problem finds it in two places.
	if len(harvest.Inline) != 2 {
		t.Errorf("%d style attributes harvested, want 2: %q", len(harvest.Inline), harvest.Inline)
	}

	if len(harvest.StylesheetHrefs) != 1 {
		t.Errorf("%d stylesheet links harvested, want 1 (rel=preload is not one): %q", len(harvest.StylesheetHrefs), harvest.StylesheetHrefs)
	}

	if !harvest.HasViewport || harvest.Viewport != "width=device-width, initial-scale=1" {
		t.Errorf("viewport harvested as %q (present: %v): the name is matched case-insensitively", harvest.Viewport, harvest.HasViewport)
	}

	if !harvest.HasBody {
		t.Error("the walk did not see the <body>, so the viewport rule would stay silent")
	}

	wantHandlers := []string{"onclick on <a>", "onmouseover on <a>"}
	slices.Sort(harvest.Handlers)
	if !slices.Equal(harvest.Handlers, wantHandlers) {
		t.Errorf("handlers harvested as %q, want %q: the attribute name is lowercased", harvest.Handlers, wantHandlers)
	}
}

// TestHarvestMarkupIgnoresWhatIsNotStyle keeps the walk from mistaking an
// ordinary attribute for a handler, "on" being a word as well as a prefix.
func TestHarvestMarkupIgnoresWhatIsNotStyle(t *testing.T) {
	document, err := parseHTML(`<html><body><div on="x" only="y" once="z" data-onclick="w">text</div></body></html>`)
	if err != nil {
		t.Fatalf("the fixture does not parse: %v", err)
	}

	harvest := harvestMarkup(document)

	// "only" and "once" begin with "on" and are not handlers. They are matched
	// all the same: nothing here can tell an invented event from an invented
	// attribute, and a list of known events was refused on purpose. What the
	// test holds is that the two that cannot be handlers are not counted.
	for _, handler := range harvest.Handlers {
		if strings.HasPrefix(handler, "on ") || strings.HasPrefix(handler, "data-") {
			t.Errorf("%q was taken for an event handler", handler)
		}
	}
}

// TestObserveCSS exercises the reading of the styles themselves.
func TestObserveCSS(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		inline  bool
		want    []string // the slugs, in order
		wantURL string
	}{
		{
			name:   "an inline declaration",
			source: "display:flex",
			inline: true,
			want:   []string{"css-display-flex"},
		},
		{
			name:   "the value decides",
			source: "display:block;position:static;position:absolute",
			inline: true,
			want:   []string{"css-position"},
		},
		{
			name:   "case is not part of the property",
			source: "DISPLAY: FLEX",
			inline: true,
			want:   []string{"css-display-flex"},
		},
		{
			name:   "a vendor prefix is a dialect of the property",
			source: "-webkit-flex-direction: column",
			inline: true,
			want:   []string{"css-flex-direction"},
		},
		{
			name:   "an important value is still the value",
			source: "position: absolute !important",
			inline: true,
			want:   []string{"css-position"},
		},
		{
			name:    "a font face names its font",
			source:  `@font-face{font-family:"Inter";src:url(https://fonts.example/inter.woff2) format("woff2")}`,
			want:    []string{"css-at-font-face"},
			wantURL: "https://fonts.example/inter.woff2",
		},
		{
			name:    "an import names its stylesheet",
			source:  `@import url("https://fonts.example/sheet.css");`,
			want:    []string{"css-at-import"},
			wantURL: "https://fonts.example/sheet.css",
		},
		{
			name:   "a declaration under a media query is still a declaration",
			source: "@media screen and (max-width:600px){.a{display:grid}}",
			want:   []string{"css-display-grid"},
		},
		{
			name:   "minified",
			source: ".a{display:flex}.b{position:fixed}",
			want:   []string{"css-display-flex", "css-position"},
		},
		{
			name:   "a comment is not a declaration",
			source: "/* display:flex */ .a{color:red}",
			want:   nil,
		},
		{
			name:   "unterminated css yields what could be read",
			source: ".a{display:flex;position:absolute",
			want:   []string{"css-display-flex", "css-position"},
		},
		{
			name:   "nothing at all",
			source: "",
			want:   nil,
		},
		{
			name:   "nothing the table names",
			source: ".a{color:red;border-radius:4px;margin:0 auto}",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := originStyleElement
			if tt.inline {
				origin = originStyleAttribute
			}

			observed := observeCSS(tt.source, origin, tt.inline)

			slugs := make([]string, 0, len(observed))
			for _, observation := range observed {
				slugs = append(slugs, observation.Slug)
			}

			if !slices.Equal(slugs, tt.want) {
				t.Fatalf("observed %q, want %q", slugs, tt.want)
			}

			if tt.wantURL != "" {
				if len(observed) == 0 || observed[0].URL != tt.wantURL {
					t.Errorf("the observation names no URL, want %q", tt.wantURL)
				}
			}
		})
	}
}

// TestObserveCSSAttributesTheFontSource holds the one piece of state the reading
// keeps: a "src" inside an @font-face belongs to the font, and a "src" outside
// one is a property the table does not name.
func TestObserveCSSAttributesTheFontSource(t *testing.T) {
	observed := observeCSS(`@font-face{src:url(https://fonts.example/a.woff2)}.a{src:url(https://example.com/b)}`,
		originStyleElement, false)

	if len(observed) != 1 {
		t.Fatalf("observed %d features, want 1: only the @font-face is named", len(observed))
	}
	if observed[0].URL != "https://fonts.example/a.woff2" {
		t.Errorf("the font is reported at %q, want the address its src named", observed[0].URL)
	}
}

// TestIsWebFontStylesheet keeps the stylesheet link rule to the fonts: an
// ordinary external stylesheet is htmlRemarkCheck's finding, and reporting it
// here would say the same thing to the sender twice.
func TestIsWebFontStylesheet(t *testing.T) {
	tests := map[string]bool{
		"https://fonts.googleapis.com/css2?family=Inter": true,
		"https://FONTS.GOOGLEAPIS.COM/css2":              true,
		"https://use.typekit.net/abc.css":                true,
		"https://example.com/newsletter.css":             false,
		"":                                               false,
		"not a url at all":                               false,
	}

	for href, want := range tests {
		if got := isWebFontStylesheet(href); got != want {
			t.Errorf("isWebFontStylesheet(%q) = %v, want %v", href, got, want)
		}
	}
}

// TestClientCompatFindingsAggregate holds the one finding per feature rule, and
// the counting that goes with it.
func TestClientCompatFindingsAggregate(t *testing.T) {
	harvest := markupHarvest{
		HasBody:     true,
		HasViewport: true,
		Viewport:    "width=device-width, initial-scale=1",
		Sheets:      []string{".a{display:flex}.b{display:flex}"},
	}
	// Ten more cells writing the same thing.
	for range 10 {
		harvest.Inline = append(harvest.Inline, "display:flex")
	}

	findings := clientCompatFindings(harvest, nil)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1: twelve declarations of one feature are one defect", len(findings))
	}

	finding := findings[0]
	if !strings.Contains(finding.Message, "12 places") {
		t.Errorf("the message reads %q, which does not count the twelve places the feature was written", finding.Message)
	}
	if finding.Defect != defectClientCompat {
		t.Errorf("the finding is priced as %v, want the client compatibility defect", finding.Defect)
	}
	if finding.Type != model.ContentIssueTypeClientCompat {
		t.Errorf("the finding is typed %q, want client_compat", finding.Type)
	}

	// Both origins are named, since the reader has to look in both.
	location := ""
	if finding.Location != nil {
		location = *finding.Location
	}
	for _, want := range []string{"<style> element", "style attribute", "display: flex"} {
		if !strings.Contains(location, want) {
			t.Errorf("the location reads %q, which does not mention %q", location, want)
		}
	}
}

// TestClientCompatFindingsFollowTheTable holds the order of the report: it is
// the table's, not a map's, so that one message produces one report twice
// running. The golden files depend on it.
func TestClientCompatFindingsFollowTheTable(t *testing.T) {
	harvest := markupHarvest{
		HasBody:     true,
		HasViewport: true,
		Viewport:    "width=device-width",
		// Written in the reverse of the table's order.
		Sheets: []string{`@font-face{src:url(https://fonts.example/a.woff2)}.a{display:grid}.b{position:absolute}`},
	}

	var previous []string
	for range 5 {
		findings := clientCompatFindings(harvest, nil)

		messages := make([]string, 0, len(findings))
		for _, finding := range findings {
			messages = append(messages, finding.Message)
		}

		if previous != nil && !slices.Equal(messages, previous) {
			t.Fatalf("the report changed between two runs on one message:\n%q\n%q", previous, messages)
		}
		previous = messages
	}

	if len(previous) < 3 {
		t.Fatalf("%d findings reported, want the three features the styles use", len(previous))
	}

	// position comes before display:grid, which comes before the font: the table
	// puts what breaks a layout before what changes a typeface. The rules that
	// are not read off the styles follow them all, so the three are the first
	// three findings whatever else the message draws.
	if !strings.Contains(previous[0], "position") {
		t.Errorf("the first finding reads %q, want the one about position", previous[0])
	}
	if !strings.Contains(previous[1], "display:grid") {
		t.Errorf("the second finding reads %q, want the one about the grid", previous[1])
	}
	if !strings.Contains(previous[2], "@font-face") {
		t.Errorf("the third finding reads %q, want the one about the font", previous[2])
	}
}

// TestClientCompatWebFontLinkIsScopedToItsURL keeps the font finding keyed on
// the address it downloads from and on the feature it reports, so it stays
// apart both from the external stylesheet htmlRemarkCheck reports on the same
// URL and from another compatibility finding about the same address.
func TestClientCompatWebFontLinkIsScopedToItsURL(t *testing.T) {
	const href = "https://fonts.googleapis.com/css2?family=Inter"

	findings := clientCompatFindings(markupHarvest{
		HasBody:         true,
		HasViewport:     true,
		Viewport:        "width=device-width",
		StylesheetHrefs: []string{href, "https://example.com/newsletter.css"},
	}, nil)

	if len(findings) != 1 {
		t.Fatalf("%d findings reported, want 1: only the font service is ours to report", len(findings))
	}

	want := concernForURL("css-at-font-face", href)
	if findings[0].Concern != want {
		t.Errorf("the finding is keyed %q, want %q", findings[0].Concern, want)
	}
	if findings[0].Concern == concernForURL("external_css", href) {
		t.Error("the finding shares htmlRemarkCheck's key, so one of the two would be swallowed by the other")
	}
}

// TestCompatSeverity holds the two terms of the weighing apart: what the row
// says is lost, and who makes the reader lose it.
func TestCompatSeverity(t *testing.T) {
	layout := compatFeature{Impact: model.ContentIssueSeverityMedium}
	cosmetic := compatFeature{Impact: model.ContentIssueSeverityLow}

	tests := []struct {
		name    string
		feature compatFeature
		verdict caniemail.Verdict
		want    model.ContentIssueSeverity
	}{
		{
			name:    "a major client drops it: the row's full weight",
			feature: layout,
			verdict: caniemail.Verdict{Unsupported: []string{"Gmail"}},
			want:    model.ContentIssueSeverityMedium,
		},
		{
			name:    "a major client on one platform still names it",
			feature: layout,
			verdict: caniemail.Verdict{Unsupported: []string{"Outlook (Windows)"}},
			want:    model.ContentIssueSeverityMedium,
		},
		{
			name:    "the row's weight is a ceiling, not a floor",
			feature: cosmetic,
			verdict: caniemail.Verdict{Unsupported: []string{"Gmail", "Outlook", "Yahoo! Mail"}},
			want:    model.ContentIssueSeverityLow,
		},
		{
			name:    "five minor clients: below the ceiling",
			feature: layout,
			verdict: caniemail.Verdict{Unsupported: []string{"GMX", "WEB.DE", "Orange", "SFR", "LaPoste.net"}},
			want:    model.ContentIssueSeverityMedium,
		},
		{
			name:    "one minor client alone",
			feature: layout,
			verdict: caniemail.Verdict{Unsupported: []string{"LaPoste.net"}},
			want:    model.ContentIssueSeverityLow,
		},
		{
			name:    "a major client supports it in part",
			feature: layout,
			verdict: caniemail.Verdict{Partial: []string{"Gmail (Android)"}},
			want:    model.ContentIssueSeverityLow,
		},
		{
			name:    "nobody fails it",
			feature: layout,
			verdict: caniemail.Verdict{},
			want:    model.ContentIssueSeverityInfo,
		},
		{
			name:    "a row declaring no impact is read at its most modest",
			feature: compatFeature{},
			verdict: caniemail.Verdict{Unsupported: []string{"Gmail"}},
			want:    model.ContentIssueSeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compatSeverity(tt.feature.Impact, tt.verdict); got != tt.want {
				t.Errorf("severity is %q, want %q", got, tt.want)
			}
		})
	}
}

// TestMajorClientsAreStillNamedThatWay keeps compatSeverity's calibration tied
// to the data it reads.
//
// majorClients holds display names, so a client family upstream renames stops
// being recognised as major without anything failing: the severities would
// quietly drop a rank. This is what says so out loud.
func TestMajorClientsAreStillNamedThatWay(t *testing.T) {
	known := caniemail.ClientNames()

	for _, major := range majorClients {
		if !slices.Contains(known, major) {
			t.Errorf("majorClients names %q, which the data no longer knows: compatSeverity would stop seeing it", major)
		}
	}
}

// TestListClients holds the naming of the clients to a sentence: the whole list
// belongs on the feature's page.
func TestListClients(t *testing.T) {
	tests := map[string]string{
		"Gmail":                     "Gmail",
		"Gmail|Outlook":             "Gmail and Outlook",
		"Gmail|Outlook|Yahoo! Mail": "Gmail, Outlook and Yahoo! Mail",
		// Once the list is cut short, the named clients take commas and the one
		// "and" goes before the count: they are not the end of the list.
		"Gmail|Outlook|Yahoo! Mail|AOL":             "Gmail, Outlook, Yahoo! Mail and 1 other client",
		"Gmail|Outlook|Yahoo! Mail|AOL|GMX|LaPoste": "Gmail, Outlook, Yahoo! Mail and 3 other clients",
	}

	for joined, want := range tests {
		if got := listClients(strings.Split(joined, "|")); got != want {
			t.Errorf("listClients(%q) = %q, want %q", joined, got, want)
		}
	}
}

// TestClientCompatViewportRules exercises the rule the dataset does not cover.
func TestClientCompatViewportRules(t *testing.T) {
	tests := []struct {
		name     string
		harvest  markupHarvest
		want     string // a phrase the message must carry, empty for no finding
		severity model.ContentIssueSeverity
	}{
		{
			name:     "no viewport at all",
			harvest:  markupHarvest{HasBody: true},
			want:     "declares no viewport",
			severity: model.ContentIssueSeverityLow,
		},
		{
			name:     "a viewport with nothing in it",
			harvest:  markupHarvest{HasBody: true, HasViewport: true, Viewport: "  "},
			want:     "declares no viewport",
			severity: model.ContentIssueSeverityLow,
		},
		{
			name:     "zooming forbidden",
			harvest:  markupHarvest{HasBody: true, HasViewport: true, Viewport: "width=device-width, user-scalable=no"},
			want:     "forbids zooming",
			severity: model.ContentIssueSeverityMedium,
		},
		{
			name:     "zooming pinned to its initial scale",
			harvest:  markupHarvest{HasBody: true, HasViewport: true, Viewport: "width=device-width, maximum-scale=1.0"},
			want:     "forbids zooming",
			severity: model.ContentIssueSeverityMedium,
		},
		{
			name:     "a maximum scale of ten is not a maximum scale of one",
			harvest:  markupHarvest{HasBody: true, HasViewport: true, Viewport: "width=device-width, maximum-scale=10"},
			want:     "",
			severity: "",
		},
		{
			name:     "a width fixed when the message was written",
			harvest:  markupHarvest{HasBody: true, HasViewport: true, Viewport: "width=600"},
			want:     "does not adapt the message to the width",
			severity: model.ContentIssueSeverityLow,
		},
		{
			name:    "a viewport that says what it should",
			harvest: markupHarvest{HasBody: true, HasViewport: true, Viewport: "width=device-width, initial-scale=1"},
			want:    "",
		},
		{
			name:    "a fragment is not a document missing its head",
			harvest: markupHarvest{},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := viewportFinding(tt.harvest)

			if tt.want == "" {
				if finding != nil {
					t.Fatalf("reported %q, want nothing", finding.Message)
				}
				return
			}

			if finding == nil {
				t.Fatalf("reported nothing, want a message about %q", tt.want)
			}
			if !strings.Contains(finding.Message, tt.want) {
				t.Errorf("the message reads %q, want it to mention %q", finding.Message, tt.want)
			}
			if finding.Severity != tt.severity {
				t.Errorf("severity is %q, want %q", finding.Severity, tt.severity)
			}
			if finding.Defect != defectClientCompat {
				t.Errorf("the finding is priced as %v, want the client compatibility defect", finding.Defect)
			}
		})
	}
}

// TestClientCompatEventHandlers exercises the other rule of our own.
func TestClientCompatEventHandlers(t *testing.T) {
	if finding := eventHandlerFinding(markupHarvest{}); finding != nil {
		t.Errorf("reported %q on a message carrying no handler", finding.Message)
	}

	one := eventHandlerFinding(markupHarvest{Handlers: []string{"onclick on <a>"}})
	if one == nil {
		t.Fatal("reported nothing on a message carrying a handler")
	}
	if !strings.Contains(one.Message, "1 event-handler attribute (onclick on <a>)") {
		t.Errorf("the message reads %q, want it to name the one handler in the singular", one.Message)
	}
	if one.Defect != defectEventHandler {
		t.Errorf("the finding is priced as %v, want the event handler defect", one.Defect)
	}

	many := eventHandlerFinding(markupHarvest{Handlers: []string{
		"onclick on <a>", "onload on <img>", "onerror on <img>", "onmouseover on <div>",
	}})
	if many == nil {
		t.Fatal("reported nothing on a message carrying four handlers")
	}
	if !strings.Contains(many.Message, "4 event-handler attributes") {
		t.Errorf("the message reads %q, want it to count the four handlers", many.Message)
	}
	if strings.Contains(many.Message, "onmouseover") {
		t.Errorf("the message reads %q, want at most three of them named", many.Message)
	}
}

// TestClientCompatSaysNothingWithoutMarkup keeps the check quiet on a message
// it has nothing to read: the analysis of a plain text message must not acquire
// a rendering finding.
func TestClientCompatSaysNothingWithoutMarkup(t *testing.T) {
	findings, err := clientCompatCheck.Run(t.Context(), &contentInput{Results: &Results{}})
	if err != nil {
		t.Fatalf("the check could not answer: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("reported %d findings on a message carrying no HTML at all", len(findings))
	}

	document, err := parseHTML("<html><body><p>Just words, and a <a href=\"https://example.com\">link</a>.</p></body></html>")
	if err != nil {
		t.Fatalf("the fixture does not parse: %v", err)
	}

	findings = clientCompatFindings(harvestMarkup(document), nil)

	// The viewport is genuinely missing here, so that one finding is expected,
	// and nothing else: a message with no styles has no unsupported CSS.
	for _, finding := range findings {
		if strings.Contains(finding.Message, "The styles use") {
			t.Errorf("reported %q on a message carrying no styles", finding.Message)
		}
	}
}

// TestCompatFeatureSlugsAreKnown holds the detection table to the data it is
// read against.
//
// Nothing else would catch a typo: a slug the dataset does not hold yields no
// verdict, and a feature with no verdict is not reported, so the check would
// quietly stop speaking about it. That is also what a refresh renaming a
// feature upstream looks like from here.
func TestCompatFeatureSlugsAreKnown(t *testing.T) {
	verdicts := caniemail.Verdicts()
	if len(verdicts) == 0 {
		t.Fatal("the embedded data yielded no verdict at all")
	}

	// Every slug the check consults, from whichever table or rule, held to the
	// same standard. The tables that match on a tag or an image source are as
	// able to carry a typo as the CSS one, and as silent about it.
	for name, slug := range map[string]string{
		"<video>":                   "html-video",
		"<audio>":                   "html-audio",
		"<picture>":                 "html-picture",
		"<svg>":                     "html-svg",
		"<marquee>":                 "html-marquee",
		"the data: URI images":      "image-base64",
		"the AVIF images":           "image-avif",
		"the WebP images":           "image-webp",
		"the SVG images":            "image-svg",
		"the HEIF images":           "image-heif",
		"the TIFF images":           "image-tiff",
		"the MP4 images":            "image-mp4",
		"the BMP images":            "image-bmp",
		"the icon images":           "image-ico",
		"the APNG images":           "image-apng",
		"the <style> element rules": "html-style",
		"the anchor link rule":      "html-anchor-links",
	} {
		if _, known := verdicts[slug]; !known {
			t.Errorf("%s is looked for as %q, which the data does not hold: the check would never report it", name, slug)
		}
	}

	// The two tables must say what they look for and what it is worth, or a row
	// reports nothing, or reports it at the wrong weight.
	for _, feature := range markupFeatures {
		if feature.Tag == "" || feature.Advice == "" || feature.Impact == "" {
			t.Errorf("the markup row for %q is incomplete: tag %q, impact %q", feature.Slug, feature.Tag, feature.Impact)
		}
	}
	for _, feature := range imageFormatFeatures {
		if (len(feature.Suffixes) == 0) == (feature.Scheme == "") {
			t.Errorf("the image row for %q must match on suffixes or on a scheme, and names %v and %q",
				feature.Slug, feature.Suffixes, feature.Scheme)
		}
		if feature.Name == "" || feature.Advice == "" || feature.Impact == "" {
			t.Errorf("the image row for %q is incomplete: name %q, impact %q", feature.Slug, feature.Name, feature.Impact)
		}
	}

	// No two rows may name one feature: a row is what a finding is written from,
	// so a shared slug is two pieces of advice for one finding, only one of which
	// would ever be read.
	claimed := make(map[string]string, len(compatFeatures))

	for _, feature := range compatFeatures {
		name := strings.Join(feature.Properties, ", ")
		if feature.AtRule != "" {
			name = "@" + feature.AtRule
		}

		if other, taken := claimed[feature.Slug]; taken {
			t.Errorf("%s and %s are both written from %q, so one of their advices is unreachable", other, name, feature.Slug)
		}
		claimed[feature.Slug] = name

		verdict, known := verdicts[feature.Slug]
		if !known {
			t.Errorf("%s is looked for as %q, which the data does not hold: the check would never report it", name, feature.Slug)
			continue
		}

		if verdict.Title == "" {
			t.Errorf("%q has no title, so a finding about it could not name the feature", feature.Slug)
		}
		if verdict.URL == "" {
			t.Errorf("%q has no page, so its advice could not point the reader at the matrix", feature.Slug)
		}

		// A row nobody fails is a row that reports nothing. That is a legitimate
		// state, so it is logged rather than failed: it says the clients caught
		// up, and the row can go.
		if len(verdict.Unsupported) == 0 && len(verdict.Partial) == 0 {
			t.Logf("%s (%s) is now rendered by every client the data knows: the row reports nothing", name, feature.Slug)
			continue
		}

		t.Logf("%s (%s): unsupported by %v, partial in %v, severity %s",
			name, feature.Slug, verdict.Unsupported, verdict.Partial, compatSeverity(feature.Impact, verdict))
	}
}

// TestStyleElementFindings exercises the gravest and least visible rule here:
// six clients drop the <style> element, Gmail among them for a reader whose
// account is not a Google one.
func TestStyleElementFindings(t *testing.T) {
	// A design held up by a <style> element alone.
	only := styleElementFindings(markupHarvest{Sheets: []string{".a{color:red}"}})
	if len(only) != 1 {
		t.Fatalf("%d findings on a design that is all in a <style> element, want 1: %v", len(only), messagesOf(only))
	}
	if !strings.Contains(only[0].Message, "nothing is inlined") {
		t.Errorf("the message reads %q, want it to say nothing is inlined", only[0].Message)
	}
	if only[0].Defect != defectClientCompat {
		t.Errorf("the finding is priced as %v, want the client compatibility defect", only[0].Defect)
	}

	// A message that also inlines keeps its design where the element is dropped,
	// so it is not told it loses everything.
	both := styleElementFindings(markupHarvest{
		Sheets: []string{"@media screen{.a{color:red}}"},
		Inline: []string{"color:red"},
	})
	for _, finding := range both {
		if strings.Contains(finding.Message, "nothing is inlined") {
			t.Errorf("reported %q on a message that does inline its styles", finding.Message)
		}
	}

	// Where the element sits is a finding of its own.
	inBody := styleElementFindings(markupHarvest{
		Sheets:      []string{".a{color:red}"},
		Inline:      []string{"color:red"},
		StyleInBody: true,
	})
	if len(inBody) != 1 || !strings.Contains(inBody[0].Message, "inside the body") {
		t.Errorf("reported %v, want one finding about the element sitting in the body", messagesOf(inBody))
	}

	// Nothing to say about a message carrying no <style> at all.
	if findings := styleElementFindings(markupHarvest{Inline: []string{"color:red"}}); len(findings) != 0 {
		t.Errorf("reported %v on a message with no <style> element", messagesOf(findings))
	}
}

// TestMarkupTagFindings exercises the elements read straight off the walk.
func TestMarkupTagFindings(t *testing.T) {
	findings := markupTagFindings(markupHarvest{Tags: map[string]int{"video": 2, "marquee": 1}})

	if len(findings) != 2 {
		t.Fatalf("%d findings, want one per element: %v", len(findings), messagesOf(findings))
	}

	// The table's order, video before marquee, whatever the map says.
	if !strings.Contains(findings[0].Message, "<video>") {
		t.Errorf("the first finding reads %q, want the one about <video>", findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "2 places") {
		t.Errorf("the first finding reads %q, want it to count the two places", findings[0].Message)
	}
	if !strings.Contains(findings[1].Message, "<marquee>") {
		t.Errorf("the second finding reads %q, want the one about <marquee>", findings[1].Message)
	}

	// An element every client renders draws nothing, which is why <div> is not
	// in the table and would say nothing if it were.
	if findings := markupTagFindings(markupHarvest{Tags: map[string]int{"div": 40}}); len(findings) != 0 {
		t.Errorf("reported %v about elements no client refuses", messagesOf(findings))
	}
}

// TestImageFormatFindings exercises what the message claims to serve.
func TestImageFormatFindings(t *testing.T) {
	findings := imageFormatFindings([]ImageCheck{
		{Src: "https://example.com/hero.avif"},
		{Src: "https://example.com/logo.png"},
		{Src: "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"},
		{Src: "https://example.com/icon.svg?v=2"},
		{Src: "https://example.com/second.avif"},
	})

	messages := messagesOf(findings)
	if len(findings) != 3 {
		t.Fatalf("%d findings, want one per format the message serves: %v", len(findings), messages)
	}

	// The table's order: the data: URI, then AVIF, then SVG.
	if !strings.Contains(messages[0], "an inline data: URI") {
		t.Errorf("the first finding reads %q, want the one about the data: URI", messages[0])
	}
	if !strings.Contains(messages[1], "2 images are served as AVIF") {
		t.Errorf("the second finding reads %q, want it to count both AVIF images", messages[1])
	}
	if !strings.Contains(messages[2], "One image is served as SVG") {
		t.Errorf("the third finding reads %q: a query string is not part of the extension", messages[2])
	}

	// A location must not reproduce a data: URI, which is as long as the image.
	if location := findings[0].Location; location == nil || len(*location) > 40 {
		t.Errorf("the location of the data: URI finding reads %v, want it named rather than reproduced", location)
	}

	// PNG is refused by nobody, so it draws nothing even though it was there.
	for _, message := range messages {
		if strings.Contains(message, "PNG") {
			t.Errorf("reported %q about a format no client refuses", message)
		}
	}

	if findings := imageFormatFindings(nil); len(findings) != 0 {
		t.Error("reported something about a message carrying no image")
	}
}

// TestImageFormatMatchesSource holds the reading of a source to what it says.
func TestImageFormatMatchesSource(t *testing.T) {
	avif := imageFormatFeature{Suffixes: []string{".avif"}}
	base64 := imageFormatFeature{Scheme: "data"}

	tests := []struct {
		src     string
		feature imageFormatFeature
		want    bool
	}{
		{"https://example.com/a.avif", avif, true},
		{"https://example.com/a.AVIF", avif, true},
		{"https://example.com/a.avif?w=600", avif, true},
		{"https://example.com/a.avif#top", avif, true},
		{"https://example.com/a.png?fallback=a.avif", avif, false},
		{"https://example.com/a.png", avif, false},
		{"", avif, false},
		{"data:image/png;base64,AAA", base64, true},
		{"DATA:image/png;base64,AAA", base64, true},
		{"https://example.com/data.png", base64, false},
	}

	for _, tt := range tests {
		if got := tt.feature.matchesSource(tt.src); got != tt.want {
			t.Errorf("matchesSource(%q) = %v, want %v", tt.src, got, tt.want)
		}
	}
}

// TestAnchorLinkFinding exercises the table of contents nobody expects to fail.
func TestAnchorLinkFinding(t *testing.T) {
	if finding := anchorLinkFinding(markupHarvest{}); finding != nil {
		t.Errorf("reported %q on a message carrying no anchor", finding.Message)
	}

	one := anchorLinkFinding(markupHarvest{AnchorHrefs: []string{"#summary"}})
	if one == nil {
		t.Fatal("reported nothing on a message linking to an anchor")
	}
	if !strings.Contains(one.Message, "One link points to an anchor") {
		t.Errorf("the message reads %q, want the singular", one.Message)
	}
	if one.Location == nil || *one.Location != "#summary" {
		t.Errorf("the location reads %v, want the anchor itself", one.Location)
	}

	many := anchorLinkFinding(markupHarvest{AnchorHrefs: []string{"#a", "#b", "#c"}})
	if many == nil || !strings.Contains(many.Message, "3 links point to anchors") {
		t.Errorf("reported %v, want the plural counted", many)
	}
}

// TestHarvestMarkupReadsTagsAndAnchors covers what the walk gained: the elements
// a table names, the anchors, and where a <style> element sits.
func TestHarvestMarkupReadsTagsAndAnchors(t *testing.T) {
	document, err := parseHTML(`<html><head><style>.a{color:red}</style></head><body>
		<a href="#summary">Jump to the summary</a>
		<a href="#">A placeholder that designates nothing</a>
		<a href="https://example.com/page#section">An anchor on another page</a>
		<video src="https://example.com/a.mp4"></video>
		<video src="https://example.com/b.mp4"></video>
		<div>Not an element any table names</div>
		<style>.b{color:blue}</style>
	</body></html>`)
	if err != nil {
		t.Fatalf("the fixture does not parse: %v", err)
	}

	harvest := harvestMarkup(document)

	if !slices.Equal(harvest.AnchorHrefs, []string{"#summary"}) {
		t.Errorf("anchors harvested as %q, want only %q: a bare # designates nothing, and a fragment on another page is another page",
			harvest.AnchorHrefs, "#summary")
	}

	if harvest.Tags["video"] != 2 {
		t.Errorf("%d <video> counted, want 2", harvest.Tags["video"])
	}
	if _, counted := harvest.Tags["div"]; counted {
		t.Error("<div> was counted, though no table names it: the harvest keeps only what is looked for")
	}

	if !harvest.StyleInBody {
		t.Error("the <style> element written in the body went unnoticed")
	}
}

// messagesOf is the messages of a list of findings, for a test's own reporting.
func messagesOf(findings []reading.Finding) []string {
	messages := make([]string, 0, len(findings))
	for _, finding := range findings {
		messages = append(messages, finding.Message)
	}

	return messages
}

// TestTruncateKeepsCharactersWhole holds the cut to character boundaries: a
// location is written out as JSON, and half a character is not text.
func TestTruncateKeepsCharactersWhole(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		limit int
		want  string
	}{
		{
			name:  "a text within the limit is left alone",
			text:  "font-family: Hélvetica",
			limit: 80,
			want:  "font-family: Hélvetica",
		},
		{
			name:  "the cut falls back to the start of the character",
			text:  "aaaaaaaébbbb",
			limit: 10,
			want:  "aaaaaaa...",
		},
		{
			name:  "an ASCII text is cut where the limit says",
			text:  "aaaaaaaaaabbbb",
			limit: 10,
			want:  "aaaaaaa...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.text, tt.limit)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.text, tt.limit, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("truncate(%q, %d) returned invalid UTF-8: %q", tt.text, tt.limit, got)
			}
		})
	}
}
