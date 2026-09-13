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
	"slices"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// TestMergeKeepsTheFirstObserver covers the mechanism itself, on checks
// written for the purpose.
func TestMergeKeepsTheFirstObserver(t *testing.T) {
	family := &reading.Family{Name: "test", Cap: 10}

	tests := []struct {
		name        string
		checks      []contentCheck
		wantIssues  []string // the message of each expected finding, in order
		wantCorrob  []string // corroborated_by of the first finding
		wantPenalty int
	}{
		{
			name: "two observers of one defect make one finding",
			checks: []contentCheck{
				concernedIssuesOf("ours", family, "same_defect", model.ContentIssueSeverityHigh),
				concernedIssuesOf("theirs", family, "same_defect", model.ContentIssueSeverityHigh),
			},
			wantIssues: []string{"ours"},
			wantCorrob: []string{"theirs"},
			// Charged once, not twice: one defect, one penalty.
			wantPenalty: 3,
		},
		{
			name: "three observers all land on the one finding",
			checks: []contentCheck{
				concernedIssuesOf("ours", family, "same_defect", model.ContentIssueSeverityHigh),
				concernedIssuesOf("theirs", family, "same_defect", model.ContentIssueSeverityHigh),
				concernedIssuesOf("third", family, "same_defect", model.ContentIssueSeverityHigh),
			},
			wantIssues:  []string{"ours"},
			wantCorrob:  []string{"theirs", "third"},
			wantPenalty: 3,
		},
		{
			name: "different concerns are left apart",
			checks: []contentCheck{
				concernedIssuesOf("ours", family, "one_defect", model.ContentIssueSeverityHigh),
				concernedIssuesOf("theirs", family, "another_defect", model.ContentIssueSeverityHigh),
			},
			wantIssues:  []string{"ours", "theirs"},
			wantCorrob:  nil,
			wantPenalty: 6,
		},
		{
			name: "findings with no concern are never merged, even from one check",
			checks: []contentCheck{
				issuesOf("unkeyed", family,
					model.ContentIssueSeverityHigh,
					model.ContentIssueSeverityHigh,
				),
			},
			wantIssues:  []string{"unkeyed", "unkeyed"},
			wantCorrob:  nil,
			wantPenalty: 6,
		},
		{
			name: "a check agreeing with itself drops the duplicate silently",
			checks: []contentCheck{
				concernedIssuesOf("ours", family, "same_defect",
					model.ContentIssueSeverityHigh,
					model.ContentIssueSeverityHigh,
				),
			},
			wantIssues: []string{"ours"},
			// Not corroborated: "also reported by ourselves" says nothing.
			wantCorrob:  nil,
			wantPenalty: 3,
		},
		{
			name: "the kept finding's own penalty is the one charged",
			checks: []contentCheck{
				// Ours answers for itself elsewhere, so it charges nothing;
				// the filter's agreement must not smuggle a penalty back in.
				concernedIssuesOf("ours", nil, "same_defect", model.ContentIssueSeverityCritical),
				concernedIssuesOf("theirs", family, "same_defect", model.ContentIssueSeverityCritical),
			},
			wantIssues:  []string{"ours"},
			wantCorrob:  []string{"theirs"},
			wantPenalty: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues, penalty := reading.Run(context.Background(), test.checks, &contentInput{Results: &Results{}})

			messages := make([]string, 0, len(issues))
			for _, issue := range issues {
				messages = append(messages, issue.Message)
			}
			if !slices.Equal(messages, test.wantIssues) {
				t.Errorf("reported %v, want %v", messages, test.wantIssues)
			}

			if penalty != test.wantPenalty {
				t.Errorf("charged %d point(s), want %d", penalty, test.wantPenalty)
			}

			if len(issues) == 0 {
				return
			}

			var corroborated []string
			if issues[0].CorroboratedBy != nil {
				corroborated = *issues[0].CorroboratedBy
			}
			if !slices.Equal(corroborated, test.wantCorrob) {
				t.Errorf("the finding is corroborated by %v, want %v", corroborated, test.wantCorrob)
			}
		})
	}
}

func TestConcernForURL(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		same bool
	}{
		{
			name: "the same URL keys the same",
			a:    "https://example.com/page",
			b:    "https://example.com/page",
			same: true,
		},
		{
			name: "case in the scheme and host does not matter",
			a:    "HTTPS://Example.COM/page",
			b:    "https://example.com/page",
			same: true,
		},
		{
			name: "surrounding space does not matter",
			a:    "  https://example.com/page\t",
			b:    "https://example.com/page",
			same: true,
		},
		{
			name: "case in the path does matter, because it does to a server",
			a:    "https://example.com/Page",
			b:    "https://example.com/page",
			same: false,
		},
		{
			name: "a trailing slash is not assumed away",
			a:    "https://example.com/page/",
			b:    "https://example.com/page",
			same: false,
		},
		{
			name: "different hosts never key the same",
			a:    "https://example.com/page",
			b:    "https://example.org/page",
			same: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := concernForURL("defect", test.a)
			b := concernForURL("defect", test.b)

			if a == "" || b == "" {
				t.Fatalf("one of the URLs got no key: %q, %q", a, b)
			}
			if (a == b) != test.same {
				t.Errorf("%q keys as %q and %q as %q; want same=%v", test.a, a, test.b, b, test.same)
			}
		})
	}

	t.Run("a defect keeps its own key space", func(t *testing.T) {
		if concernForURL("one", "https://example.com/") == concernForURL("other", "https://example.com/") {
			t.Error("two different defects about one URL key the same, so they would be merged")
		}
	})

	t.Run("what cannot be parsed is never merged", func(t *testing.T) {
		for _, raw := range []string{"", "not a url", "mailto:someone@example.com", "/relative/path", "{{UNSUB}}"} {
			if key := concernForURL("defect", raw); key != "" {
				t.Errorf("%q was keyed as %q, so it could be merged on a guess", raw, key)
			}
		}
	})
}

func TestRspamdConcern(t *testing.T) {
	tests := []struct {
		name   string
		recipe string
		params string
		want   string
	}{
		{
			name:   "no recipe, no key",
			recipe: "",
			params: "https://example.com/",
			want:   "",
		},
		{
			name:   "a whole-message concern is used as written",
			recipe: "excessive_images",
			params: "",
			want:   "excessive_images",
		},
		{
			name:   "a URL recipe keys on the URL of the options",
			recipe: "ip_host" + concernURLRecipe,
			params: "http://192.0.2.1/page",
			want:   concernForURL("ip_host", "http://192.0.2.1/page"),
		},
		{
			name:   "the URL is found among other options",
			recipe: "shortener" + concernURLRecipe,
			params: "redirector, https://example.com/r/abc, 302",
			want:   concernForURL("shortener", "https://example.com/r/abc"),
		},
		{
			name:   "a URL recipe with no URL to key on yields nothing",
			recipe: "shortener" + concernURLRecipe,
			params: "",
			want:   "",
		},
		{
			name:   "options that are not a URL yield nothing either",
			recipe: "shortener" + concernURLRecipe,
			params: "example.com",
			want:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rspamdConcern(test.recipe, test.params); got != test.want {
				t.Errorf("rspamdConcern(%q, %q) = %q, want %q", test.recipe, test.params, got, test.want)
			}
		})
	}
}

// TestRspamdCorroboratesOurOwnFinding walks the real registry: a message whose
// link is a public shortener draws our own suspicion, and rspamd's
// REDIRECTOR_URL on the same URL must join it rather than be listed beside it.
func TestRspamdCorroboratesOurOwnFinding(t *testing.T) {
	const shortened = "https://bit.ly/3xYzAbC"

	results := &Results{
		Links: []LinkCheck{{
			URL:   shortened,
			Valid: true,
			Suspicions: []URLSuspicion{{
				Kind:     URLSuspicionShortener,
				Severity: model.ContentIssueSeverityMedium,
				Message:  "the link goes through a public URL shortener",
				Advice:   "link to your own domain instead",
			}},
		}},
		Rspamd: rspamdWith(map[string]string{"REDIRECTOR_URL": shortened}),
	}

	issues, _ := reading.Run(context.Background(), contentChecks, results.checkInput())

	if len(issues) != 1 {
		t.Fatalf("reported %d finding(s), want 1: %+v", len(issues), issues)
	}

	issue := issues[0]

	// Ours is the one kept: the registry lists our checks first, and ours
	// carries a location and an advice written for this report.
	if issue.Source != nil {
		t.Errorf("the finding reports source %q, want our own (absent)", *issue.Source)
	}
	if issue.CorroboratedBy == nil || !slices.Contains(*issue.CorroboratedBy, "REDIRECTOR_URL") {
		t.Errorf("the finding is corroborated by %v, want REDIRECTOR_URL among them", issue.CorroboratedBy)
	}
}

// TestRspamdStandsAloneWhenWeMissedIt is the case the merge exists to allow:
// the filter saw something no check of ours did, so it is reported on its own
// rather than dropped for overlapping in principle.
func TestRspamdStandsAloneWhenWeMissedIt(t *testing.T) {
	results := &Results{
		// No link of ours, so no suspicion of ours.
		Rspamd: rspamdWith(map[string]string{"REDIRECTOR_URL": "https://bit.ly/3xYzAbC"}),
	}

	issues, penalty := reading.Run(context.Background(), contentChecks, results.checkInput())

	if len(issues) != 1 {
		t.Fatalf("reported %d finding(s), want 1: %+v", len(issues), issues)
	}
	if issues[0].Source == nil || *issues[0].Source != model.ContentIssueSourceRspamd {
		t.Error("the finding does not say it comes from the filter")
	}
	if penalty == 0 {
		t.Error("a finding nothing else reported cost nothing")
	}
}

// TestTwoDistinctSuspicionsOnOneURLStayApart guards the direction that matters:
// merging two different defects would lose one of them, which is worse than
// showing one defect twice.

// stylesheetResults reads a message carrying one external stylesheet, as the
// report generator would.
func stylesheetResults(t *testing.T, href string) *Results {
	t.Helper()

	raw := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.net\r\n" +
		"Subject: Styled\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><head><link rel=\"stylesheet\" href=\"" + href + "\"></head>" +
		"<body><p>Hello</p></body></html>\r\n")

	email, err := mailmsg.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	return NewAnalyzer(time.Second).Analyze(email)
}

// TestRspamdCorroboratesTheStylesheetWeSaw is the case the URL key was written
// for on our side: the remark the HTML pass writes and rspamd's EXT_CSS are
// the same observation about the same stylesheet, and must reach the reader as
// one finding that names both.
//
// It reads the remark from a real message on purpose. The two keys are built
// from different texts: ours from a sentence we wrote, rspamd's from the
// options it sent, so a test quoting our own format on both sides would agree
// with itself while the report listed the stylesheet twice.
func TestRspamdCorroboratesTheStylesheetWeSaw(t *testing.T) {
	const stylesheet = "https://cdn.example.com/mail.css"

	results := stylesheetResults(t, stylesheet)
	results.Rspamd = rspamdWith(map[string]string{"EXT_CSS": stylesheet})

	// The two checks the merge is between, rather than the whole registry:
	// what else a stylesheet-carrying message draws is another test's business.
	issues, _ := reading.Run(context.Background(), []contentCheck{htmlRemarkCheck, rspamdFindingsCheck}, results.checkInput())

	if len(issues) != 1 {
		t.Fatalf("reported %d finding(s), want 1: %+v", len(issues), issues)
	}

	issue := issues[0]

	// Ours is the one kept: the registry reads the markup before it reads the
	// filter, and our remark quotes the stylesheet in a sentence a sender can
	// act on.
	if issue.Source != nil {
		t.Errorf("the finding reports source %q, want our own (absent)", *issue.Source)
	}
	if issue.CorroboratedBy == nil || !slices.Contains(*issue.CorroboratedBy, "EXT_CSS") {
		t.Fatalf("the finding is corroborated by %v, want EXT_CSS among them", issue.CorroboratedBy)
	}
}

// TestRspamdStylesheetOnAnotherURLStaysApart guards the other direction: two
// stylesheets are two defects, and keying both on "external_css" alone would
// hide one of them.
func TestRspamdStylesheetOnAnotherURLStaysApart(t *testing.T) {
	results := stylesheetResults(t, "https://cdn.example.com/mail.css")
	results.Rspamd = rspamdWith(map[string]string{"EXT_CSS": "https://cdn.example.org/other.css"})

	issues, _ := reading.Run(context.Background(), []contentCheck{htmlRemarkCheck, rspamdFindingsCheck}, results.checkInput())

	if len(issues) != 2 {
		t.Fatalf("reported %d finding(s), want 2: %+v", len(issues), issues)
	}
	for _, issue := range issues {
		if issue.CorroboratedBy != nil {
			t.Errorf("a finding about one stylesheet is corroborated by %v, which was raised about another", *issue.CorroboratedBy)
		}
	}
}
