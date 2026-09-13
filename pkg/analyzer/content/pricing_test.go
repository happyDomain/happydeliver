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
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// TestEveryDefectIsPricedOnce is the rule the whole content score rests on: a
// defect is charged for by exactly one party.
//
// The score is the sum of two answers: what the criteria withhold from a
// flawless message, and what the checks deduct on top, and nothing but this
// keeps them from answering for the same thing. A defect charged twice costs
// the sender a grade for one mistake; a defect charged by nobody is reported
// and free. Both are silent, and both are what this test refuses.
//
// It reads the two registries and runs nothing: the rule is a property of how
// the defects are declared, not of what a given message happens to trigger.
func TestEveryDefectIsPricedOnce(t *testing.T) {
	answeredBy := make(map[*reading.Defect][]string, len(contentDefects))
	for _, criterion := range contentCriteria {
		for _, defect := range criterion.Answers {
			answeredBy[defect] = append(answeredBy[defect], criterion.Name)
		}
	}

	for _, defect := range contentDefects {
		t.Run(defect.Name, func(t *testing.T) {
			criteria := answeredBy[defect]

			switch {
			case len(criteria) > 1:
				t.Errorf("criteria %s all charge for it: one defect, one payer", strings.Join(criteria, ", "))

			case len(criteria) == 1 && defect.Family != nil:
				t.Errorf("the %s criterion already charges for it, and family %q charges for it again: the sender pays twice for one defect",
					criteria[0], defect.Family.Name)

			case len(criteria) == 1 && defect.Uncharged != "":
				t.Errorf("the %s criterion charges for it, yet it claims to cost nothing (%q): one of the two is wrong",
					criteria[0], defect.Uncharged)

			case defect.Family != nil && defect.Uncharged != "":
				t.Errorf("family %q charges for it, yet it claims to cost nothing (%q): one of the two is wrong",
					defect.Family.Name, defect.Uncharged)

			case len(criteria) == 0 && defect.Family == nil && defect.Uncharged == "":
				t.Error("nobody charges for it: give it a penalty family, name it in the Answers of the criterion that already grades it, or say in Uncharged why it costs nothing on purpose")
			}
		})
	}
}

// TestCriteriaAnswerKnownDefects keeps the two registries from drifting apart:
// a criterion answering for a defect the vocabulary does not hold prices
// nothing at all, and the rule above would never notice.
func TestCriteriaAnswerKnownDefects(t *testing.T) {
	for _, criterion := range contentCriteria {
		for _, defect := range criterion.Answers {
			if !slices.Contains(contentDefects, defect) {
				t.Errorf("the %s criterion answers for %q, which the defect vocabulary does not hold", criterion.Name, defect.Name)
			}
		}
	}
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

	// The markup a check reading the tree looks at: a stylesheet fetched from
	// elsewhere and a tag no client runs.
	markup := `<html><head><link rel="stylesheet" href="https://example.com/style.css"></head>` +
		`<body><script>go()</script><p>Hello</p></body></html>`
	document, err := parseHTML(markup)
	if err != nil {
		panic("the fixture's markup does not parse: " + err.Error())
	}

	shortened := URLSuspicion{
		Kind:     URLSuspicionShortener,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "The destination is hidden behind a public shortener",
		Advice:   "Write the destination out",
	}
	insecure := URLSuspicion{
		Kind:     URLSuspicionInsecureScheme,
		Severity: model.ContentIssueSeverityLow,
		Message:  "The source is fetched over http:",
		Advice:   "Serve it over https:",
	}

	return &Results{
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

// TestACheckOnlyReportsWhatItDeclares keeps a check's Reports honest, since
// that declaration is what the rule above is read off: a check quietly
// reporting a defect it never declared is a defect priced by nobody.
//
// A finding carrying no defect at all fails here too: it would cost nothing,
// whatever the check meant.
func TestACheckOnlyReportsWhatItDeclares(t *testing.T) {
	// Built from the results themselves, not copied into an input made from an
	// empty set: checkInput reads email and htmlDocument off the results at
	// construction, so overwriting them afterwards left every check that reads
	// the message or its markup with nothing to read.
	in := speakingResults().checkInput()

	for _, check := range contentChecks {
		t.Run(check.Name, func(t *testing.T) {
			findings, err := check.Run(context.Background(), in)
			if err != nil {
				t.Fatalf("the check could not answer: %v", err)
			}

			// A check that says nothing about a message carrying one of
			// everything leaves its declaration unverified, which is how a
			// wrong one survives. speakingResults is what has to grow.
			if len(findings) == 0 {
				t.Fatal("the check reported nothing on a message built to make every check speak: add what it looks for to speakingResults")
			}

			for _, finding := range findings {
				if finding.Defect == nil {
					t.Errorf("%q is reported with no defect, so nothing says what it costs", finding.Message)
					continue
				}
				if !slices.Contains(check.Reports, finding.Defect) {
					t.Errorf("%q is reported as %q, which the check does not declare in Reports", finding.Message, finding.Defect.Name)
				}
			}
		})
	}
}
