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
	"slices"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// message stands for whatever a reading is handed. This package never looks
// inside it, which is the whole point of it being a type parameter.
type message struct{}

// reports builds a check reporting one issue per severity given, so that a
// test states what a check found rather than how it found it.
func reports(name string, family *Family, severities ...model.IssueSeverity) Check[message] {
	defect := &Defect{Name: name, Family: family}

	return Check[message]{
		Name:     name,
		Reports:  []*Defect{defect},
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			findings := make([]Finding, 0, len(severities))
			for _, severity := range severities {
				findings = append(findings, Finding{
					Defect: defect,
					Issue:  model.Issue{Severity: severity, Message: name},
				})
			}
			return findings, nil
		},
	}
}

// concerning builds a check whose findings all name one concern, for the tests
// about two checks seeing one defect.
func concerning(name string, concern string, severities ...model.IssueSeverity) Check[message] {
	return Check[message]{
		Name:     name,
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			findings := make([]Finding, 0, len(severities))
			for _, severity := range severities {
				findings = append(findings, Finding{
					Concern: concern,
					Issue:   model.Issue{Severity: severity, Message: name},
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
	graded := &Family{Name: "test_graded", Cap: 60, PerSeverity: map[model.IssueSeverity]int{
		model.IssueSeverityCritical: 40,
		model.IssueSeverityMedium:   15,
	}}

	critical := model.IssueSeverityCritical

	tests := []struct {
		name    string
		checks  []Check[message]
		issues  int
		penalty int
	}{
		{"nothing found costs nothing", []Check[message]{reports("quiet", family)}, 0, 0},
		{
			"each severity has its weight",
			[]Check[message]{reports("weighed", family, critical, model.IssueSeverityHigh, model.IssueSeverityMedium, model.IssueSeverityLow)},
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
			[]Check[message]{reports("flat", flat, model.IssueSeverityLow, critical, critical)},
			3, 40,
		},
		{
			"a graded family reads what a finding costs off its gravity",
			[]Check[message]{reports("graded", graded, critical, model.IssueSeverityMedium)},
			2, 55,
		},
		{
			"a gravity a graded family does not name costs nothing",
			[]Check[message]{reports("graded", graded, model.IssueSeverityLow, model.IssueSeverityInfo)},
			2, 0,
		},
		{
			"a graded family is capped like any other",
			[]Check[message]{reports("graded", graded, critical, critical)},
			2, 60,
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
	low := model.IssueSeverityLow
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
			return []Finding{{Issue: model.Issue{Severity: model.IssueSeverityHigh, Message: "scanner"}}},
				errors.New("the service did not answer")
		},
	}

	issues, penalty := Run(context.Background(), []Check[message]{failing, reports("reader", nil, model.IssueSeverityLow)}, message{})

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
	low := model.IssueSeverityLow
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
	low := model.IssueSeverityLow
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
				{Issue: model.Issue{Message: "silent"}},
				{Issue: model.Issue{Message: "spoken", Category: CategorySecurity}},
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

// TestSaysTheSame pins when two findings of one concern are one observation:
// when a reader would see the same thing in the same place.
func TestSaysTheSame(t *testing.T) {
	at := func(message, location string) Finding {
		finding := Finding{Issue: model.Issue{Message: message}}
		if location != "" {
			finding.Location = &location
		}
		return finding
	}

	tests := []struct {
		name string
		a, b Finding
		same bool
	}{
		{"same words in the same place", at("unreadable", "p:1"), at("unreadable", "p:1"), true},
		{"same words nowhere in particular", at("unreadable", ""), at("unreadable", ""), true},
		{"same words in two places", at("unreadable", "p:1"), at("unreadable", "p:2"), false},
		{"same words, one of them placed", at("unreadable", "p:1"), at("unreadable", ""), false},
		{"different words in the same place", at("unreadable", "p:1"), at("too small", "p:1"), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := saysTheSame(test.a, test.b); got != test.same {
				t.Errorf("saysTheSame = %v, want %v", got, test.same)
			}
		})
	}
}

// TestOneCheckReportingAConcernInSeveralPlacesKeepsEachOfThem: a check naming
// one concern for a whole class of defect still gets every place it found it
// reported, the merge only dropping what reads the same.
func TestOneCheckReportingAConcernInSeveralPlacesKeepsEachOfThem(t *testing.T) {
	placed := Check[message]{
		Name:     "contrast",
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			first, second := "p:1", "p:2"
			return []Finding{
				{Concern: "low_contrast", Issue: model.Issue{Message: "unreadable", Location: &first}},
				{Concern: "low_contrast", Issue: model.Issue{Message: "unreadable", Location: &second}},
				{Concern: "low_contrast", Issue: model.Issue{Message: "unreadable", Location: &first}},
			}, nil
		},
	}

	issues, _ := Run(context.Background(), []Check[message]{placed}, message{})

	if len(issues) != 2 {
		t.Fatalf("reported %d issue(s), want the two places and not the repeat", len(issues))
	}
	for _, issue := range issues {
		if issue.CorroboratedBy != nil {
			t.Errorf("a check agreeing with itself was read as a corroboration: %v", *issue.CorroboratedBy)
		}
	}
}

// TestACorroborationNamesTheSymbolThatSawIt: the spam filter is named on a
// finding by the symbol that raised it, which is what a sender can look up.
func TestACorroborationNamesTheSymbolThatSawIt(t *testing.T) {
	low := model.IssueSeverityLow
	symbol := "R_SUSPICIOUS_URL"
	filter := Check[message]{
		Name:     "rspamd",
		Category: CategoryContent,
		Run: func(context.Context, message) ([]Finding, error) {
			return []Finding{{Concern: "suspicious:https://example.com/", Issue: model.Issue{Severity: low, Symbol: &symbol}}}, nil
		},
	}

	issues, _ := Run(context.Background(), []Check[message]{concerning("ours", "suspicious:https://example.com/", low), filter}, message{})

	if len(issues) != 1 || issues[0].CorroboratedBy == nil || !slices.Equal(*issues[0].CorroboratedBy, []string{symbol}) {
		t.Errorf("reported %+v, want the one finding corroborated by %q", issues, symbol)
	}
}

// TestAnObserverIsNamedOnceHoweverOftenItAgrees: a filter that saw the defect
// twice is named once on the finding.
func TestAnObserverIsNamedOnceHoweverOftenItAgrees(t *testing.T) {
	low := model.IssueSeverityLow
	checks := []Check[message]{
		concerning("ours", "dead_link:https://example.com/", low),
		concerning("filter", "dead_link:https://example.com/", low, low),
	}

	issues, _ := Run(context.Background(), checks, message{})

	if len(issues) != 1 || issues[0].CorroboratedBy == nil || !slices.Equal(*issues[0].CorroboratedBy, []string{"filter"}) {
		t.Errorf("reported %+v, want the one finding corroborated by the filter once", issues)
	}
}
