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

package reading

import (
	"context"
	"errors"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// message stands for whatever a reading is handed. This package never looks
// inside it, which is the whole point of it being a type parameter.
type message struct{}

// reports builds a check reporting one issue per severity given, so that a
// test states what a check found rather than how it found it.
func reports(name string, family *Family, severities ...model.ContentIssueSeverity) Check[message] {
	defect := &Defect{Name: name, Family: family}

	return Check[message]{
		Name:     name,
		Reports:  []*Defect{defect},
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			findings := make([]Finding, 0, len(severities))
			for _, severity := range severities {
				findings = append(findings, Finding{
					Defect:       defect,
					ContentIssue: model.ContentIssue{Severity: severity, Message: name},
				})
			}
			return findings, nil
		},
	}
}

// concerning builds a check whose findings all name one concern, for the tests
// about two checks seeing one defect.
func concerning(name string, concern string, severities ...model.ContentIssueSeverity) Check[message] {
	return Check[message]{
		Name:     name,
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			findings := make([]Finding, 0, len(severities))
			for _, severity := range severities {
				findings = append(findings, Finding{
					Concern:      concern,
					ContentIssue: model.ContentIssue{Severity: severity, Message: name},
				})
			}
			return findings, nil
		},
	}
}

// TestRunCharges holds what a finding costs: its severity, unless its family
// charges a flat rate, and never past what the family may deduct in all.
func TestRunCharges(t *testing.T) {
	family := &Family{Name: "test", Cap: 10}
	other := &Family{Name: "test_other", Cap: 10}
	flat := &Family{Name: "test_flat", Cap: 40, PerItem: 20}

	critical := model.ContentIssueSeverityCritical

	tests := []struct {
		name    string
		checks  []Check[message]
		issues  int
		penalty int
	}{
		{"nothing found costs nothing", []Check[message]{reports("quiet", family)}, 0, 0},
		{
			"each severity has its weight",
			[]Check[message]{reports("weighed", family, critical, model.ContentIssueSeverityHigh, model.ContentIssueSeverityMedium, model.ContentIssueSeverityLow)},
			4, 9,
		},
		{
			"a defect no family answers for reports without charging",
			[]Check[message]{reports("reporter", nil, critical, critical)},
			2, 0,
		},
		{
			"a family is capped however much it found",
			[]Check[message]{reports("noisy", family, critical, critical, critical, critical)},
			4, 10,
		},
		{
			"two checks share one cap",
			[]Check[message]{reports("first", family, critical, critical), reports("second", family, critical, critical)},
			4, 10,
		},
		{
			"two families are capped apart",
			[]Check[message]{reports("one", family, critical, critical, critical, critical), reports("other", other, critical, critical, critical, critical)},
			8, 20,
		},
		{
			"a flat family ignores severity, and is capped too",
			[]Check[message]{reports("flat", flat, model.ContentIssueSeverityLow, critical, critical)},
			3, 40,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues, penalty := Run(context.Background(), test.checks, message{})

			if len(issues) != test.issues {
				t.Errorf("reported %d issue(s), want %d", len(issues), test.issues)
			}
			if penalty != test.penalty {
				t.Errorf("charged %d point(s), want %d", penalty, test.penalty)
			}
		})
	}
}

// TestRunKeepsRegistryOrder pins that findings come out in the order the
// registry lists the checks: that order is how a reading puts what qualifies
// the rest first, and what merely remarks last.
func TestRunKeepsRegistryOrder(t *testing.T) {
	low := model.ContentIssueSeverityLow
	checks := []Check[message]{reports("first", nil, low), reports("second", nil, low), reports("third", nil, low)}

	issues, _ := Run(context.Background(), checks, message{})

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

// TestACheckThatCouldNotAnswerIsNotReported states the error policy: a check
// that reached no verdict says nothing, and the rest of the reading stands. A
// finding from it would state a defect nobody observed, and dropping the whole
// reading would lose what every other check did see.
func TestACheckThatCouldNotAnswerIsNotReported(t *testing.T) {
	failing := Check[message]{
		Name: "scanner",
		Run: func(context.Context, message) ([]Finding, error) {
			return []Finding{{ContentIssue: model.ContentIssue{Severity: model.ContentIssueSeverityHigh, Message: "scanner"}}},
				errors.New("the service did not answer")
		},
	}

	issues, penalty := Run(context.Background(), []Check[message]{failing, reports("reader", nil, model.ContentIssueSeverityLow)}, message{})

	if len(issues) != 1 || issues[0].Message != "reader" {
		t.Fatalf("reported %+v, want the sole finding of the check that answered", issues)
	}
	if penalty != 0 {
		t.Errorf("a check that could not answer was charged %d point(s)", penalty)
	}
}

// TestADefectSeenTwiceIsReportedOnce holds the merge: two checks describing
// the same thing about the same object leave one finding, naming the other as
// having seen it too.
func TestADefectSeenTwiceIsReportedOnce(t *testing.T) {
	low := model.ContentIssueSeverityLow
	checks := []Check[message]{
		concerning("ours", "dead_link:https://example.com/", low),
		concerning("filter", "dead_link:https://example.com/", low),
	}

	issues, _ := Run(context.Background(), checks, message{})

	if len(issues) != 1 {
		t.Fatalf("reported %d issue(s), want the one they both saw", len(issues))
	}
	if issues[0].Message != "ours" {
		t.Errorf("kept the finding of %q, want the first one reported", issues[0].Message)
	}
	if issues[0].CorroboratedBy == nil || len(*issues[0].CorroboratedBy) != 1 || (*issues[0].CorroboratedBy)[0] != "filter" {
		t.Errorf("corroborated_by reads %v, want the other observer named once", issues[0].CorroboratedBy)
	}
}

// TestAnObserverAgreeingWithItselfIsNotACorroboration: the same check reporting
// one concern twice has found it twice, not had it confirmed.
func TestAnObserverAgreeingWithItselfIsNotACorroboration(t *testing.T) {
	low := model.ContentIssueSeverityLow
	twice := concerning("ours", "dead_link:https://example.com/", low, low)

	issues, _ := Run(context.Background(), []Check[message]{twice}, message{})

	if len(issues) != 1 {
		t.Fatalf("reported %d issue(s), want one", len(issues))
	}
	if issues[0].CorroboratedBy != nil {
		t.Errorf("corroborated_by reads %v, want nothing at all", *issues[0].CorroboratedBy)
	}
}

// TestAFindingAnswersItsCheckReading: a finding that names no reading answers
// the one its check does, which is the answer for all but a handful.
func TestAFindingAnswersItsCheckReading(t *testing.T) {
	named := Check[message]{
		Name:     "mixed",
		Category: CategoryDeliverability,
		Run: func(context.Context, message) ([]Finding, error) {
			return []Finding{
				{ContentIssue: model.ContentIssue{Message: "silent"}},
				{ContentIssue: model.ContentIssue{Message: "spoken", Category: CategorySecurity}},
			}, nil
		},
	}

	issues, _ := Run(context.Background(), []Check[message]{named}, message{})

	if len(issues) != 2 {
		t.Fatalf("reported %d issue(s), want 2", len(issues))
	}
	if issues[0].Category != CategoryDeliverability {
		t.Errorf("a finding naming no reading answers %q, want its check's", issues[0].Category)
	}
	if issues[1].Category != CategorySecurity {
		t.Errorf("a finding naming its own reading answers %q, want the one it named", issues[1].Category)
	}
}
