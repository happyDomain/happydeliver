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
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// issuesOf builds a check reporting one finding per severity given, so that a
// test states what a check found rather than how it found it.
func issuesOf(name string, family *reading.Family, severities ...model.ContentIssueSeverity) contentCheck {
	return concernedIssuesOf(name, family, "", severities...)
}

// concernedIssuesOf is issuesOf with every finding keyed on one concern, for
// the tests about merging.
func concernedIssuesOf(name string, family *reading.Family, concern string, severities ...model.ContentIssueSeverity) contentCheck {
	return contentCheck{
		Name:   name,
		Family: family,
		Run: func(context.Context, *contentInput) ([]reading.Finding, error) {
			issues := make([]reading.Finding, 0, len(severities))
			for _, severity := range severities {
				issues = append(issues, reading.Finding{
					ContentIssue: model.ContentIssue{
						Type:     model.ContentIssueTypeSuspiciousLink,
						Severity: severity,
						Message:  name,
					},
					Concern: concern,
				})
			}
			return issues, nil
		},
	}
}

// failingCheck stands for a check whose verdict never came: the scanner was
// down, the resolver timed out.
func failingCheck(name string) contentCheck {
	return contentCheck{
		Name:     name,
		Category: reading.CategorySecurity,
		Run: func(context.Context, *contentInput) ([]reading.Finding, error) {
			return []reading.Finding{{ContentIssue: model.ContentIssue{
				Type:     model.ContentIssueTypeSuspiciousLink,
				Severity: model.ContentIssueSeverityHigh,
				Message:  name,
			}}}, errors.New("the service did not answer")
		},
	}
}

func TestRunContentChecksPenalty(t *testing.T) {
	// A family used by these tests alone, so that tuning a real one does not
	// silently rewrite what they assert.
	family := &reading.Family{Name: "test", Cap: 10}
	other := &reading.Family{Name: "test_other", Cap: 10}
	flat := &reading.Family{Name: "test_flat", Cap: 40, PerItem: 20}

	tests := []struct {
		name    string
		checks  []contentCheck
		issues  int
		penalty int
	}{
		{
			name:    "nothing found costs nothing",
			checks:  []contentCheck{issuesOf("quiet", family)},
			issues:  0,
			penalty: 0,
		},
		{
			name: "each severity has its weight",
			checks: []contentCheck{issuesOf("weighed", family,
				model.ContentIssueSeverityCritical, // 3
				model.ContentIssueSeverityHigh,     // 3
				model.ContentIssueSeverityMedium,   // 2
				model.ContentIssueSeverityLow,      // 1
			)},
			issues:  4,
			penalty: 9,
		},
		{
			name: "info weighs the same as low",
			checks: []contentCheck{issuesOf("informed", family,
				model.ContentIssueSeverityInfo,
			)},
			issues:  1,
			penalty: 1,
		},
		{
			name: "a check without a family reports without charging",
			checks: []contentCheck{issuesOf("reporter", nil,
				model.ContentIssueSeverityCritical,
				model.ContentIssueSeverityCritical,
			)},
			issues:  2,
			penalty: 0,
		},
		{
			name: "a family is capped however much it found",
			checks: []contentCheck{issuesOf("noisy", family,
				model.ContentIssueSeverityCritical, // 3
				model.ContentIssueSeverityCritical, // 3
				model.ContentIssueSeverityCritical, // 3
				model.ContentIssueSeverityCritical, // 3, past the cap of 10
			)},
			issues:  4,
			penalty: 10,
		},
		{
			name: "two checks share one cap",
			checks: []contentCheck{
				issuesOf("first", family,
					model.ContentIssueSeverityCritical, // 3
					model.ContentIssueSeverityCritical, // 3
				),
				issuesOf("second", family,
					model.ContentIssueSeverityCritical, // 3
					model.ContentIssueSeverityCritical, // 3, past the shared cap
				),
			},
			issues:  4,
			penalty: 10,
		},
		{
			name: "two families are capped apart",
			checks: []contentCheck{
				issuesOf("one", family,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
				),
				issuesOf("other", other,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
					model.ContentIssueSeverityCritical,
				),
			},
			issues:  8,
			penalty: 20,
		},
		{
			name: "a flat family ignores severity",
			checks: []contentCheck{issuesOf("flat", flat,
				model.ContentIssueSeverityLow, // 20 all the same
				model.ContentIssueSeverityLow, // 20
			)},
			issues:  2,
			penalty: 40,
		},
		{
			name: "a flat family is capped too",
			checks: []contentCheck{issuesOf("flat", flat,
				model.ContentIssueSeverityCritical,
				model.ContentIssueSeverityCritical,
				model.ContentIssueSeverityCritical, // 60, past the cap of 40
			)},
			issues:  3,
			penalty: 40,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues, penalty := reading.Run(context.Background(), test.checks, &contentInput{Results: &Results{}})

			if len(issues) != test.issues {
				t.Errorf("reported %d issue(s), want %d", len(issues), test.issues)
			}
			if penalty != test.penalty {
				t.Errorf("charged %d point(s), want %d", penalty, test.penalty)
			}
		})
	}
}

// TestRunContentChecksOrder pins that findings come out in registry order: the
// order is what puts a truncated body before everything it qualifies, and a
// remark after everything it comments on.
func TestRunContentChecksOrder(t *testing.T) {
	checks := []contentCheck{
		issuesOf("first", nil, model.ContentIssueSeverityLow),
		issuesOf("second", nil, model.ContentIssueSeverityLow),
		issuesOf("third", nil, model.ContentIssueSeverityLow),
	}

	issues, _ := reading.Run(context.Background(), checks, &contentInput{Results: &Results{}})

	want := []string{"first", "second", "third"}
	if len(issues) != len(want) {
		t.Fatalf("reported %d issue(s), want %d", len(issues), len(want))
	}
	for i, name := range want {
		if issues[i].Message != name {
			t.Errorf("issue %d comes from %q, want %q", i, issues[i].Message, name)
		}
	}
}

// TestContentRegistryIsWellFormed guards the registry itself: a check added
// without a name, or twice, is a mistake no fixture would catch.
func TestContentRegistryIsWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(contentChecks))

	for i, check := range contentChecks {
		if check.Name == "" {
			t.Errorf("check %d has no name", i)
		}
		if check.Run == nil {
			t.Errorf("check %q has nothing to run", check.Name)
		}
		if seen[check.Name] {
			t.Errorf("check %q is registered twice", check.Name)
		}
		seen[check.Name] = true

		if check.Category == "" {
			t.Errorf("check %q says nothing about which reading it answers", check.Name)
		}

		if check.Family != nil && check.Family.Cap <= 0 {
			t.Errorf("check %q belongs to family %q, whose cap of %d would silence it", check.Name, check.Family.Name, check.Family.Cap)
		}
	}
}

// TestContentChecksTolerateAnEmptyMessage covers the case every check must
// survive: a message the parser could read nothing from. A check that assumes
// a part, a link or an image is there would panic here rather than in
// production.
func TestContentChecksTolerateAnEmptyMessage(t *testing.T) {
	issues, penalty := reading.Run(context.Background(), contentChecks, &contentInput{Results: &Results{}})

	if len(issues) != 0 {
		t.Errorf("an empty message drew %d issue(s): %+v", len(issues), issues)
	}
	if penalty != 0 {
		t.Errorf("an empty message was charged %d point(s)", penalty)
	}
}

// TestReadRunsTheChecksOnce pins what Read is for: the checks run when it is
// called, and the findings and the penalty both come from that one run.
//
// Nothing caches it. The report generator calls Read once and hands what it
// got to the report and to the score, which is the only way a check that
// fetches a URL or hands a file to a scanner is affordable.
func TestReadRunsTheChecksOnce(t *testing.T) {
	runs := 0
	counting := contentCheck{
		Name:     "counting",
		Category: reading.CategoryContent,
		Run: func(context.Context, *contentInput) ([]reading.Finding, error) {
			runs++
			return nil, nil
		},
	}

	restore := contentChecks
	contentChecks = []contentCheck{counting}
	defer func() { contentChecks = restore }()

	analyzer := NewAnalyzer(time.Second)
	observed := &Results{}

	read := analyzer.Read(observed)
	analyzer.Analysis(observed, read)
	analyzer.Score(observed, read)

	if runs != 1 {
		t.Fatalf("the checks ran %d times for one reading, want 1", runs)
	}

	// A second message is a second reading: nothing of the first is kept, on
	// the analyzer or anywhere else, the analyzer being shared between
	// concurrent analyses.
	analyzer.Read(&Results{})
	if runs != 2 {
		t.Fatalf("the checks ran %d times for two messages, want 2", runs)
	}
}

// TestCheckInputCarriesTheMessageAndItsMarkup pins what a check may read. The
// facts a single check needs are looked up in the message or walked in the
// tree, so adding one costs a check file rather than a field on Results
// and a pass filling it.
func TestCheckInputCarriesTheMessageAndItsMarkup(t *testing.T) {
	raw := []byte("From: sender@example.com\r\n" +
		"To: recipient@example.net\r\n" +
		"Subject: Hello\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body><p>Hi</p><img src=\"https://example.com/a.png\"></body></html>\r\n")

	email, err := mailmsg.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	in := newProbingTestAnalyzer(time.Second).Analyze(email).checkInput()

	if in.Message != email {
		t.Error("the checks are not handed the message they are asked about")
	}

	if in.HTML == nil {
		t.Fatal("the checks are not handed the parsed markup")
	}

	var images int
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "img" {
			images++
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(in.HTML)

	if images != 1 {
		t.Errorf("walking the tree handed to the checks found %d images, want 1", images)
	}
}

// TestACheckThatCouldNotAnswerIsNotReported states the error policy: a check
// that reached no verdict says nothing, and the rest of the report stands. A
// finding from it would state a defect nobody observed, and dropping the whole
// analysis would lose what every other check did see.
func TestACheckThatCouldNotAnswerIsNotReported(t *testing.T) {
	checks := []contentCheck{
		failingCheck("scanner"),
		issuesOf("reader", nil, model.ContentIssueSeverityLow),
	}

	issues, penalty := reading.Run(context.Background(), checks, &contentInput{Results: &Results{}})

	if len(issues) != 1 || issues[0].Message != "reader" {
		t.Fatalf("reported %+v, want the sole finding of the check that answered", issues)
	}
	if penalty != 0 {
		t.Errorf("a check that could not answer was charged %d point(s)", penalty)
	}
}

// TestChecksAreGivenTheAnalysisDeadline pins that a check may wait on
// something, and is told when the analysis will not wait any longer.
func TestChecksAreGivenTheAnalysisDeadline(t *testing.T) {
	var got context.Context
	watching := contentCheck{
		Name:     "watching",
		Category: reading.CategoryContent,
		Run: func(ctx context.Context, _ *contentInput) ([]reading.Finding, error) {
			got = ctx
			return nil, nil
		},
	}

	restore := contentChecks
	contentChecks = []contentCheck{watching}
	defer func() { contentChecks = restore }()

	NewAnalyzer(time.Second).scoreOf(&Results{})

	if got == nil {
		t.Fatal("the check was run without a context")
	}
	if _, ok := got.Deadline(); !ok {
		t.Error("the check was given a context that never expires")
	}
}

// scoreOf and analysisOf read the checks once and hand what they found to the
// grading and to the report, which is what the report generator does. A test
// caring about one of the two says so; none of them wants to thread a reading
// through by hand.
func (c *Analyzer) scoreOf(observed *Results) (int, string) {
	return c.Score(observed, c.Read(observed))
}

func (c *Analyzer) analysisOf(observed *Results) *model.ContentAnalysis {
	return c.Analysis(observed, c.Read(observed))
}

// runCheck asks one check what it makes of the facts given, so that a test
// about a check states the finding rather than the plumbing around it.
func runCheck(t *testing.T, check contentCheck, results *Results) []model.ContentIssue {
	t.Helper()

	found, err := check.Run(context.Background(), results.checkInput())
	if err != nil {
		t.Fatalf("the %q check could not answer: %v", check.Name, err)
	}

	issues := make([]model.ContentIssue, 0, len(found))
	for _, finding := range found {
		issues = append(issues, finding.ContentIssue)
	}

	return issues
}

// TestBrokenHTMLCheckReportsWhatTheReaderGaveUpOn covers the one check no
// fixture can reach: html.Parse recovers from every kind of malformed markup a
// message can carry, so HTMLErrors is only ever filled by a reader that gave
// up outright. The check is therefore asked about that state directly, which
// is also the only way to hold it to the two states it must tell apart, a
// message whose HTML would not be read and one that simply has none.
func TestBrokenHTMLCheckReportsWhatTheReaderGaveUpOn(t *testing.T) {
	tests := []struct {
		name    string
		results *Results
		want    []string // the message of each expected finding, in order
	}{
		{
			name:    "a message with no HTML at all is not a message with broken HTML",
			results: &Results{},
		},
		{
			name:    "HTML that was read draws nothing",
			results: &Results{HTMLValid: true},
		},
		{
			name: "an error left behind by a reading that succeeded is not reported",
			results: &Results{
				HTMLValid:  true,
				HTMLErrors: []string{"Failed to parse HTML: unexpected EOF"},
			},
		},
		{
			name: "each error the reader left is reported, in the order it was left",
			results: &Results{
				HTMLErrors: []string{
					"Failed to parse HTML: unexpected EOF",
					"Failed to parse HTML: invalid encoding",
				},
			},
			want: []string{
				"Failed to parse HTML: unexpected EOF",
				"Failed to parse HTML: invalid encoding",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := runCheck(t, brokenHTMLCheck, test.results)

			messages := make([]string, 0, len(issues))
			for _, issue := range issues {
				messages = append(messages, issue.Message)
			}
			if !slices.Equal(messages, test.want) {
				t.Fatalf("reported %v, want %v", messages, test.want)
			}

			for _, issue := range issues {
				if issue.Type != model.ContentIssueTypeBrokenHtml {
					t.Errorf("the finding is typed %q, want %q", issue.Type, model.ContentIssueTypeBrokenHtml)
				}
				// High, not critical: the message still reaches the reader,
				// it is what it looks like on arrival that is in doubt.
				if issue.Severity != model.ContentIssueSeverityHigh {
					t.Errorf("the finding is graded %q, want %q", issue.Severity, model.ContentIssueSeverityHigh)
				}
				if issue.Advice == nil || *issue.Advice == "" {
					t.Error("the finding names a defect without saying what to do about it")
				}
			}
		})
	}
}

// TestHTMLRemarkCheckReportsWithoutCharging pins the contract of the remarks:
// they are reported because a sender may want to know, and they cost nothing
// because none of them keeps the message from being read. A remark promoted to
// a real defect should be given its own check and its own type, not a higher
// severity here.
func TestHTMLRemarkCheckReportsWithoutCharging(t *testing.T) {
	const stylesheet = "https://cdn.example.com/mail.css"

	t.Run("a message that drew no remark is not reported on", func(t *testing.T) {
		if issues := runCheck(t, htmlRemarkCheck, htmlResults(t, `<html><body><p>Hello</p></body></html>`)); len(issues) != 0 {
			t.Errorf("reported %d remark(s) about a message that drew none: %+v", len(issues), issues)
		}
	})

	t.Run("each stylesheet the markup names is reported", func(t *testing.T) {
		markup := `<html><head><link rel="stylesheet" href="` + stylesheet + `">` +
			`<link rel="stylesheet" href="https://cdn.example.org/other.css"></head><body></body></html>`
		issues := runCheck(t, htmlRemarkCheck, htmlResults(t, markup))

		if len(issues) != 2 {
			t.Fatalf("reported %d remark(s), want 2: %+v", len(issues), issues)
		}
		if !strings.Contains(issues[0].Message, stylesheet) {
			t.Errorf("the first remark reads %q, want it to name %q", issues[0].Message, stylesheet)
		}

		for _, issue := range issues {
			// Filed under broken_html for want of a type of its own, and kept
			// at the lowest severity so it never reads as a defect.
			if issue.Type != model.ContentIssueTypeBrokenHtml {
				t.Errorf("the remark is typed %q, want %q", issue.Type, model.ContentIssueTypeBrokenHtml)
			}
			if issue.Severity != model.ContentIssueSeverityLow {
				t.Errorf("the remark is graded %q, want %q", issue.Severity, model.ContentIssueSeverityLow)
			}
			if issue.Advice == nil || *issue.Advice == "" {
				t.Error("the remark says nothing about what to do instead")
			}
		}
	})

	t.Run("a remark costs the message nothing", func(t *testing.T) {
		if htmlRemarkCheck.Family != nil {
			t.Errorf("the remarks belong to family %q, so they deduct points for a message that reads fine", htmlRemarkCheck.Family.Name)
		}

		_, penalty := reading.Run(context.Background(), []contentCheck{htmlRemarkCheck},
			htmlResults(t, `<html><head><link rel="stylesheet" href="`+stylesheet+`"></head><body></body></html>`).checkInput())

		if penalty != 0 {
			t.Errorf("a remark was charged %d point(s)", penalty)
		}
	})
}
