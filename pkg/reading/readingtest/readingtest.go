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

// Package readingtest holds every analysis to the rules a reading is made of:
// a defect paid for by exactly one party, a check reporting only what it
// declares, every finding filed under a reading the report groups by. An
// analysis declares its registry here and calls Registry.Test.
package readingtest

import (
	"context"
	"slices"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/pkg/reading"
)

// Registry is everything an analysis declares.
type Registry[In any] struct {
	// Checks is the registry as the analysis runs it, in its own order.
	Checks []reading.Check[In]

	// Defects is the whole vocabulary the checks may report out of.
	Defects []*reading.Defect

	// Criteria is what the score weighs. An analysis whose score is not
	// weighed on criteria leaves it nil, and the rules that read it are
	// skipped.
	Criteria []reading.Criterion[In]

	// Speaking is the observations built to make every check speak, by a name
	// the failures can point at.
	Speaking map[string]In

	// Empty is the observation every check must survive: one nothing could be
	// read off.
	Empty In
}

// Test runs every rule over the registry.
func (r Registry[In]) Test(t *testing.T) {
	t.Helper()

	t.Run("EveryDefectIsPricedOnce", r.everyDefectIsPricedOnce)
	t.Run("CriteriaAnswerKnownDefects", r.criteriaAnswerKnownDefects)
	t.Run("CriteriaSumToTheScale", r.criteriaSumToTheScale)
	t.Run("RegistryIsWellFormed", r.registryIsWellFormed)
	t.Run("ACheckOnlyReportsWhatItDeclares", r.aCheckOnlyReportsWhatItDeclares)
	t.Run("EveryIssueAnswersAReading", r.everyIssueAnswersAReading)
	t.Run("TheChecksTolerateAnEmptyObservation", r.theChecksTolerateAnEmptyObservation)
}

// everyDefectIsPricedOnce is the rule a score rests on: a defect is charged
// for by exactly one party.
//
// The score is the sum of two answers: what the criteria withhold from a
// flawless message, and what the checks deduct on top, and nothing but this
// keeps them from answering for the same thing. A defect charged twice costs
// the sender a grade for one mistake; a defect charged by nobody is reported
// and free. Both are silent, and both are what this rule refuses.
//
// It reads the registries and runs nothing.
func (r Registry[In]) everyDefectIsPricedOnce(t *testing.T) {
	answeredBy := make(map[*reading.Defect][]string, len(r.Defects))
	for _, criterion := range r.Criteria {
		for _, defect := range criterion.Answers {
			answeredBy[defect] = append(answeredBy[defect], criterion.Name)
		}
	}

	for _, defect := range r.Defects {
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

// criteriaAnswerKnownDefects keeps the two registries from drifting apart: a
// criterion answering for a defect the vocabulary does not hold prices nothing
// at all, and the rule above would never notice.
func (r Registry[In]) criteriaAnswerKnownDefects(t *testing.T) {
	for _, criterion := range r.Criteria {
		for _, defect := range criterion.Answers {
			if !slices.Contains(r.Defects, defect) {
				t.Errorf("the %s criterion answers for %q, which the defect vocabulary does not hold", criterion.Name, defect.Name)
			}
		}
	}
}

// criteriaSumToTheScale holds a score to the scale it is expressed on: a
// criterion added without taking its weight from another would quietly make a
// hundred mean something else, and the penalties the checks deduct are
// expressed in points of that hundred.
func (r Registry[In]) criteriaSumToTheScale(t *testing.T) {
	if len(r.Criteria) == 0 {
		t.Skip("this reading is not weighed on criteria")
	}

	total := 0
	seen := make(map[string]bool, len(r.Criteria))

	for i, criterion := range r.Criteria {
		if criterion.Name == "" {
			t.Errorf("criterion %d has no name", i)
		}
		if seen[criterion.Name] {
			t.Errorf("criterion %q is weighed twice", criterion.Name)
		}
		seen[criterion.Name] = true

		if criterion.Points == nil {
			t.Errorf("criterion %q has nothing to judge with", criterion.Name)
		}
		if criterion.Weight <= 0 {
			t.Errorf("criterion %q weighs %d, so nothing it judges counts", criterion.Name, criterion.Weight)
		}
		total += criterion.Weight
	}

	if total != 100 {
		t.Errorf("the criteria weigh %d in all, want 100", total)
	}
}

// registryIsWellFormed guards the registry itself: a check added without a
// name, or twice, is a mistake no fixture would catch.
func (r Registry[In]) registryIsWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(r.Checks))

	for i, check := range r.Checks {
		if check.Name == "" {
			t.Errorf("check %d has no name, so nothing can report which one failed", i)
		}
		if check.Run == nil {
			t.Errorf("check %q has nothing to run", check.Name)
		}
		if seen[check.Name] {
			t.Errorf("check %q is registered twice, so a corroboration cannot tell them apart", check.Name)
		}
		seen[check.Name] = true

		if check.Category == "" {
			t.Errorf("check %q says nothing about which reading it answers", check.Name)
		} else if !check.Category.Valid() {
			t.Errorf("check %q answers %q, which the schema does not offer a reader", check.Name, check.Category)
		}

		if len(check.Reports) == 0 {
			t.Errorf("check %q declares no defect, so nothing says what its findings cost", check.Name)
		}

		for _, defect := range check.Reports {
			if !slices.Contains(r.Defects, defect) {
				t.Errorf("check %q reports %q, which the defect vocabulary does not hold", check.Name, defect.Name)
			}
			if defect.Family != nil && defect.Family.Cap <= 0 {
				t.Errorf("defect %q belongs to family %q, whose cap of %d would silence it", defect.Name, defect.Family.Name, defect.Family.Cap)
			}
		}
	}
}

// aCheckOnlyReportsWhatItDeclares keeps a check's Reports honest, since that
// declaration is what the pricing rule is read off: a check quietly reporting
// a defect it never declared is a defect priced by nobody.
//
// A finding carrying no defect at all fails here too: it would cost nothing,
// whatever the check meant.
func (r Registry[In]) aCheckOnlyReportsWhatItDeclares(t *testing.T) {
	for _, check := range r.Checks {
		t.Run(check.Name, func(t *testing.T) {
			spoke := false

			for name, in := range r.Speaking {
				findings, err := check.Run(context.Background(), in)
				if err != nil {
					t.Fatalf("the check could not answer about %s: %v", name, err)
				}
				if len(findings) > 0 {
					spoke = true
				}

				for _, finding := range findings {
					// A finding is free to answer a reading other than its
					// check's, and several do. What it may not do is name a
					// reading the schema does not offer, which would reach the
					// report as a group no reader can be shown.
					if finding.Category != "" && !finding.Category.Valid() {
						t.Errorf("%s: %q answers %q, which the schema does not offer a reader", name, finding.Message, finding.Category)
					}

					if finding.Defect == nil {
						t.Errorf("%s: %q is reported with no defect, so nothing says what it costs", name, finding.Message)
						continue
					}
					if !slices.Contains(check.Reports, finding.Defect) {
						t.Errorf("%s: %q is reported as %q, which the check does not declare in Reports", name, finding.Message, finding.Defect.Name)
					}
				}
			}

			// A check that says nothing about any of the observations built to
			// make every check speak leaves its declaration unverified, which
			// is how a wrong one survives. Speaking is what has to grow.
			if !spoke {
				t.Error("the check reported nothing on anything built to make every check speak: add what it looks for to the speaking observations")
			}
		})
	}
}

// everyIssueAnswersAReading holds the whole pipeline to filing every finding
// under one of the readings the report groups by: the web report shows issues
// by category, so an issue carrying none would be lost in a group with no
// heading. The check's own category answers for most of them; what is guarded
// is a finding built by hand that skips that default.
func (r Registry[In]) everyIssueAnswersAReading(t *testing.T) {
	seen := false

	for name, in := range r.Speaking {
		issues, _ := reading.Run(context.Background(), r.Checks, in)
		if len(issues) > 0 {
			seen = true
		}

		for _, issue := range issues {
			if !issue.Category.Valid() {
				t.Errorf("%s: %q is filed under %q, which is not a reading the report groups by", name, issue.Message, issue.Category)
			}
		}
	}

	if !seen {
		t.Fatal("the checks reported nothing on anything built to make every check speak")
	}
}

// theChecksTolerateAnEmptyObservation covers the case every check must
// survive: something nothing could be read off. A check assuming a part, a
// link or a payload is there panics here rather than in production.
//
// Saying nothing is the only right answer: a finding about an observation that
// carries nothing would state a defect nobody saw.
func (r Registry[In]) theChecksTolerateAnEmptyObservation(t *testing.T) {
	issues, penalty := reading.Run(context.Background(), r.Checks, r.Empty)

	if len(issues) != 0 {
		t.Errorf("an empty observation drew %d issue(s): %+v", len(issues), issues)
	}
	if penalty != 0 {
		t.Errorf("an empty observation was charged %d point(s)", penalty)
	}
}
