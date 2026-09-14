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
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// rspamdWith builds a result carrying the given symbols, as the header parsing
// or a scan would hand it over. A value of "" means the symbol was raised
// without options.
func rspamdWith(symbols map[string]string) *model.RspamdResult {
	result := &model.RspamdResult{Symbols: map[string]model.SpamTestDetail{}}

	for name, params := range symbols {
		detail := model.SpamTestDetail{Name: name}
		if params != "" {
			detail.Params = utils.PtrTo(params)
		}
		result.Symbols[name] = detail
	}

	return result
}

func runRspamdCheck(t *testing.T, rspamd *model.RspamdResult) []model.ContentIssue {
	t.Helper()

	found, err := rspamdFindingsCheck.Run(context.Background(), &contentInput{Results: &Results{Rspamd: rspamd}})
	if err != nil {
		t.Fatalf("the rspamd check could not answer: %v", err)
	}

	issues := make([]model.ContentIssue, 0, len(found))
	for _, finding := range found {
		issues = append(issues, finding.ContentIssue)
	}

	return issues
}

func TestRspamdFindings(t *testing.T) {
	tests := []struct {
		name    string
		rspamd  *model.RspamdResult
		want    []string // the symbol of each expected finding, in order
		wantNot []string
	}{
		{
			name:   "no filter result at all",
			rspamd: nil,
			want:   nil,
		},
		{
			name:   "a filter that raised nothing",
			rspamd: rspamdWith(nil),
			want:   nil,
		},
		{
			name:   "a symbol of the catalogue is reported",
			rspamd: rspamdWith(map[string]string{"ZERO_FONT": ""}),
			want:   []string{"ZERO_FONT"},
		},
		{
			name: "a symbol outside the catalogue is ignored",
			rspamd: rspamdWith(map[string]string{
				// Authentication and trace symbols are the bulk of what a
				// filter raises, and happyDeliver reports on those itself.
				"R_SPF_ALLOW": "",
				"DKIM_TRACE":  "example.com:+",
				"MIME_TRACE":  "0:+",
				"ZERO_FONT":   "",
			}),
			want:    []string{"ZERO_FONT"},
			wantNot: []string{"R_SPF_ALLOW", "DKIM_TRACE", "MIME_TRACE"},
		},
		{
			name: "findings come out gravest first, then by name",
			rspamd: rspamdWith(map[string]string{
				"HTML_SHORT_LINK_IMG_3": "",                  // info
				"DBL_PHISH":             "bad.example.com",   // critical
				"ZERO_FONT":             "",                  // high
				"HTTP_TO_IP":            "http://192.0.2.1/", // medium
				"R_PARTS_DIFFER":        "40%",               // low
			}),
			want: []string{"DBL_PHISH", "ZERO_FONT", "HTTP_TO_IP", "R_PARTS_DIFFER", "HTML_SHORT_LINK_IMG_3"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := runRspamdCheck(t, test.rspamd)

			if len(issues) != len(test.want) {
				t.Fatalf("reported %d finding(s), want %d: %+v", len(issues), len(test.want), issues)
			}

			for i, symbol := range test.want {
				if issues[i].Symbol == nil {
					t.Errorf("finding %d names no symbol, want %q", i, symbol)
					continue
				}
				if *issues[i].Symbol != symbol {
					t.Errorf("finding %d comes from %q, want %q", i, *issues[i].Symbol, symbol)
				}
			}

			for _, symbol := range test.wantNot {
				for _, issue := range issues {
					if issue.Symbol != nil && *issue.Symbol == symbol {
						t.Errorf("%q should not have been reported", symbol)
					}
				}
			}
		})
	}
}

// TestRspamdFindingCarriesItsProvenance covers what tells a reader this came
// from the filter rather than from happyDeliver's own reading of the message.
func TestRspamdFindingCarriesItsProvenance(t *testing.T) {
	issues := runRspamdCheck(t, rspamdWith(map[string]string{"ZERO_FONT": ""}))
	if len(issues) != 1 {
		t.Fatalf("reported %d finding(s), want 1", len(issues))
	}

	issue := issues[0]

	if issue.Source == nil || *issue.Source != model.ContentIssueSourceRspamd {
		t.Errorf("finding does not say it comes from rspamd: %+v", issue.Source)
	}
	if issue.Symbol == nil || *issue.Symbol != "ZERO_FONT" {
		t.Errorf("finding does not name its symbol: %+v", issue.Symbol)
	}
	if issue.Advice == nil || *issue.Advice == "" {
		t.Error("finding carries no advice, which is the whole point of the catalogue")
	}
	if issue.Type != model.ContentIssueTypeHiddenText {
		t.Errorf("finding is filed under %q, want %q", issue.Type, model.ContentIssueTypeHiddenText)
	}
}

func TestRspamdFindingInterpolatesOptions(t *testing.T) {
	tests := []struct {
		name     string
		symbol   string
		params   string
		contains string
		location string
	}{
		{
			name:     "the options are written into the message",
			symbol:   "DBL_PHISH",
			params:   "phish.example.com",
			contains: "phish.example.com",
			location: "phish.example.com",
		},
		{
			name:   "a message needing options survives their absence",
			symbol: "DBL_PHISH",
			params: "",
			// The sentence must still read as one, and must not show a raw
			// format verb to the user.
			contains: "the message does not say which",
		},
		{
			name:     "a message needing no options is left alone",
			symbol:   "PDF_JAVASCRIPT",
			params:   "invoice.pdf",
			contains: "contains JavaScript",
			location: "invoice.pdf",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := runRspamdCheck(t, rspamdWith(map[string]string{test.symbol: test.params}))
			if len(issues) != 1 {
				t.Fatalf("reported %d finding(s), want 1", len(issues))
			}

			issue := issues[0]

			if !strings.Contains(issue.Message, test.contains) {
				t.Errorf("message %q does not mention %q", issue.Message, test.contains)
			}
			if strings.Contains(issue.Message, "%s") {
				t.Errorf("message %q still carries a format verb", issue.Message)
			}

			switch {
			case test.location == "" && issue.Location != nil:
				t.Errorf("finding points at %q, want no location", *issue.Location)
			case test.location != "" && (issue.Location == nil || *issue.Location != test.location):
				t.Errorf("finding points at %v, want %q", issue.Location, test.location)
			}
		})
	}
}

// TestRspamdFindingsAreCapped checks that a filter with a great deal to say
// informs the reader without deciding the content grade by itself.
func TestRspamdFindingsAreCapped(t *testing.T) {
	// Six critical findings would be worth eighteen points uncapped.
	symbols := map[string]string{
		"DBL_PHISH":                 "a.example.com",
		"DBL_SPAM":                  "b.example.com",
		"DBL_BOTNET":                "c.example.com",
		"URIBL_BLACK":               "d.example.com",
		"URL_ZERO_WIDTH_SPACES":     "https://e.example.com",
		"MIME_DOUBLE_BAD_EXTENSION": "invoice.pdf.exe",
	}

	issues, penalty := reading.Run(context.Background(), contentChecks, &contentInput{
		Results: &Results{Rspamd: rspamdWith(symbols)},
	})

	if len(issues) != len(symbols) {
		t.Errorf("reported %d finding(s), want %d", len(issues), len(symbols))
	}
	if penalty != familyRspamd.Cap {
		t.Errorf("charged %d point(s), want the family cap of %d", penalty, familyRspamd.Cap)
	}
}

// TestRspamdCatalogIsWellFormed guards the catalogue itself. It is a table of
// prose, so nothing but a test keeps an entry from shipping without advice, or
// with a severity that does not exist.
func TestRspamdCatalogIsWellFormed(t *testing.T) {
	for symbol, finding := range rspamdFindingCatalog {
		if symbol != strings.ToUpper(symbol) {
			t.Errorf("%q is not written as rspamd names its symbols", symbol)
		}
		if !finding.Issue.Valid() {
			t.Errorf("%q is filed under %q, which is not a content issue type", symbol, finding.Issue)
		}
		if !finding.Severity.Valid() {
			t.Errorf("%q carries the severity %q, which does not exist", symbol, finding.Severity)
		}
		// Empty is the ordinary answer: the symbol observes what the filter is
		// there to observe, and answers the check's own reading. What is
		// refused is a reading the schema does not offer, which would reach
		// the report as a group no reader is shown.
		if finding.Category != "" && !finding.Category.Valid() {
			t.Errorf("%q answers %q, which is not a reading the report groups by", symbol, finding.Category)
		}
		if finding.Message == "" {
			t.Errorf("%q states nothing", symbol)
		}
		if finding.Advice == "" {
			t.Errorf("%q gives no advice, so it says no more than rspamd's own description", symbol)
		}
		if strings.Count(finding.Message, "%") != strings.Count(finding.Message, "%s") {
			t.Errorf("%q has a stray %% in its message: %q", symbol, finding.Message)
		}
		if strings.Contains(finding.Advice, "%s") {
			t.Errorf("%q interpolates into its advice, which is never filled in: %q", symbol, finding.Advice)
		}
	}
}

// TestRspamdFindingsReachTheReport covers the path from what the filter
// observed to the findings of the report.
//
// It starts from the result rather than from the headers a milter wrote:
// reading those is the analyzer's business, and this package is handed what
// they said.
func TestRspamdFindingsReachTheReport(t *testing.T) {
	analyzer := NewAnalyzer(0)
	analyzer.SkipProbes = true

	email, err := mailmsg.Parse([]byte(
		"From: sender@example.com\r\n" +
			"Subject: A newsletter\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<html><body><p>Hello</p></body></html>"))
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	// ZERO_FONT is content, R_SPF_ALLOW is authentication: only the first
	// belongs in a content report.
	rspamd := rspamdWith(map[string]string{"ZERO_FONT": "", "R_SPF_ALLOW": "+ip4:192.0.2.0/24"})

	results := analyzer.Analyze(email)
	results.Rspamd = rspamd

	analysis := analyzer.analysisOf(results)
	if analysis == nil || analysis.HtmlIssues == nil {
		t.Fatal("the report holds no content issue")
	}

	var found *model.ContentIssue
	for i, issue := range *analysis.HtmlIssues {
		if issue.Symbol != nil && *issue.Symbol == "ZERO_FONT" {
			found = &(*analysis.HtmlIssues)[i]
		}
		if issue.Symbol != nil && *issue.Symbol == "R_SPF_ALLOW" {
			t.Error("an authentication symbol reached the content report")
		}
	}

	if found == nil {
		t.Fatal("ZERO_FONT was raised on the message but is missing from the report")
	}
	if found.Type != model.ContentIssueTypeHiddenText {
		t.Errorf("the finding is filed under %q, want %q", found.Type, model.ContentIssueTypeHiddenText)
	}

	// And the score answers for it, once.
	score, _ := analyzer.scoreOf(results)
	bare, _ := analyzer.scoreOf(&Results{
		HTMLValid:       results.HTMLValid,
		HTMLContent:     results.HTMLContent,
		TextContent:     results.TextContent,
		TextAlternative: results.TextAlternative,
		IsMultipart:     results.IsMultipart,
	})
	if score >= bare {
		t.Errorf("the finding cost nothing: %d with it, %d without", score, bare)
	}
}
