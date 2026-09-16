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
	"net/http"
	"net/mail"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading/readingtest"
)

// TestContentRegistry holds the content analysis to the rules every reading is
// made of, which live in readingtest.
func TestContentRegistry(t *testing.T) {
	readingtest.Registry[*contentInput]{
		Checks:   contentChecks,
		Defects:  contentDefects,
		Criteria: contentCriteria,
		// Built from the results themselves: checkInput reads email and
		// htmlDocument off the results at construction.
		Speaking: map[string]*contentInput{"a message carrying one of everything": speakingResults().checkInput()},
		Empty:    &contentInput{Results: &Results{}},
	}.Test(t)
}

// speakingResults is a message built to make every registered check speak: it
// carries one instance of everything the registry looks for. The checks are
// then run over it one at a time, so that what each of them reports can be
// held to what it declares.
//
// It is written out here rather than read from a fixture on purpose. What this
// test needs is not a realistic message but a message that triggers
// everything, and a fixture drifts out of that the moment a check is added
// without one.
func speakingResults() *Results {
	notFound, _ := httpStatusFinding("Link", http.StatusNotFound)
	detour, _ := redirectChainFinding("Link", []string{"a", "b", "c"}, "https://example.com/end")

	// The markup a check reading the tree looks at: a downloaded font, a
	// stylesheet fetched from elsewhere, a tag no client runs, a property
	// clients drop, an event handler, no viewport, and a colour pair too pale
	// to read.
	markup := `<html><head><style>@font-face{font-family:X;src:url(https://fonts.example/x.woff2)}</style>` +
		`<link rel="stylesheet" href="https://example.com/style.css"></head>` +
		`<body><script>go()</script><div style="display:flex"><a href="https://example.com" onclick="go()">Go</a></div>` +
		`<p style="color:#999999;background-color:#ffffff">Barely there</p></body></html>`
	document, err := parseHTML(markup)
	if err != nil {
		panic("speakingResults: the markup it carries does not parse: " + err.Error())
	}

	shortened := URLSuspicion{
		Kind:     URLSuspicionShortener,
		Severity: model.IssueSeverityMedium,
		Message:  "The destination is hidden behind a public shortener",
		Advice:   "Write the destination out",
	}
	insecure := URLSuspicion{
		Kind:     URLSuspicionInsecureScheme,
		Severity: model.IssueSeverityLow,
		Message:  "The source is fetched over http:",
		Advice:   "Serve it over https:",
	}

	return &Results{
		// A message sent from a domain none of its links leads back to, which
		// is what the off-domain check looks for. Every destination below is
		// under example.com, so the sender's own domain is another one.
		email:           &mailmsg.Message{From: &mail.Address{Address: "campaign@example.net"}},
		BodyTruncated:   true,
		HTMLValid:       false,
		htmlDocument:    document,
		HTMLContent:     markup,
		HTMLErrors:      []string{"unexpected closing tag"},
		ImageTextRatio:  20,
		UnprobedURLs:    3,
		TextAlternative: textAltStale,
		Links: []LinkCheck{
			{URL: "https://example.com/{{UNSUB}}", IsTemplate: true},
			// A destination the text part offers alone, which is what the
			// parity check looks for.
			{URL: "https://example.com/text-only", Valid: true, InText: true},
			{
				URL: "https://short.example/x", Valid: true,
				Suspicions: []URLSuspicion{shortened},
				probedURL:  probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
			},
			{
				URL: "https://example.com/detour", Valid: true,
				probedURL: probedURL{Status: 200, HTTPFindings: []LinkHTTPFinding{detour}},
			},
		},
		Images: []ImageCheck{{
			Src:        "http://example.com/banner.png",
			Suspicions: []URLSuspicion{insecure},
			probedURL:  probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
		}},
		UnsubscribeChecks: []LinkCheck{{
			URL:       "https://example.com/unsubscribe",
			probedURL: probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
		}},
		Rspamd: &model.RspamdResult{Symbols: map[string]model.SpamTestDetail{
			// One symbol of each kind the catalogue prices: one nothing of
			// ours measures, one a criterion already grades.
			"R_WHITE_ON_WHITE":    {Name: "R_WHITE_ON_WHITE"},
			"R_SUSPICIOUS_IMAGES": {Name: "R_SUSPICIOUS_IMAGES"},
		}},
	}
}
