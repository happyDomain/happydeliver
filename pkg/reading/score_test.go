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
	"slices"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// criterion builds a criterion answering a fixed number of points, or none
// at all when it cannot be judged.
func criterion(name string, weight, points int, applicable bool) Criterion[message] {
	return Criterion[message]{
		Name:   name,
		Weight: weight,
		Points: func(message) (int, bool) { return points, applicable },
	}
}

// TestWeigh holds the scale a reading is graded on: what the criteria award,
// brought back onto a hundred when some could not be judged, less what the
// checks found, and never outside the scale.
func TestWeigh(t *testing.T) {
	tests := []struct {
		name     string
		criteria []Criterion[message]
		penalty  int
		score    int
		grade    string
	}{
		{
			"a flawless message earns everything",
			[]Criterion[message]{criterion("a", 60, 60, true), criterion("b", 40, 40, true)},
			0, 100, "A",
		},
		{
			"a criterion withholds what the message did not earn",
			[]Criterion[message]{criterion("a", 60, 30, true), criterion("b", 40, 40, true)},
			0, 70, "D",
		},
		{
			"a criterion that cannot be judged leaves the scale",
			[]Criterion[message]{criterion("a", 60, 60, true), criterion("b", 40, 0, false)},
			0, 100, "A",
		},
		{
			"what is left is brought back onto a hundred",
			[]Criterion[message]{criterion("a", 60, 30, true), criterion("b", 40, 0, false)},
			0, 50, "E",
		},
		{
			"a reading no criterion could judge has no grade",
			[]Criterion[message]{criterion("a", 60, 60, false), criterion("b", 40, 40, false)},
			0, 0, "",
		},
		{
			"no criteria at all is no grade either",
			nil,
			10, 0, "",
		},
		{
			"the checks deduct from what was earned",
			[]Criterion[message]{criterion("a", 100, 100, true)},
			35, 65, "D",
		},
		{
			"the penalty never takes the score below zero",
			[]Criterion[message]{criterion("a", 100, 20, true)},
			50, 0, "F",
		},
		{
			"a criterion charging below zero is held to the scale",
			[]Criterion[message]{criterion("a", 50, -30, true), criterion("b", 50, 10, true)},
			0, 0, "F",
		},
		{
			"points past the weight are held to the scale",
			[]Criterion[message]{criterion("a", 100, 130, true)},
			0, 100, "A",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score, grade := Weigh(test.criteria, message{}, test.penalty)

			if score != test.score || grade != test.grade {
				t.Errorf("graded %d %q, want %d %q", score, grade, test.score, test.grade)
			}
		})
	}
}

func TestApportion(t *testing.T) {
	tests := []struct {
		name    string
		total   int
		weights []int
		want    []int
	}{
		{"in proportion", 10, []int{3, 2}, []int{6, 4}},
		{"the largest remainders take what is left", 10, []int{1, 1, 1}, []int{4, 3, 3}},
		{"a weight below zero takes nothing", 6, []int{-5, 2, 1}, []int{0, 4, 2}},
		{"weights adding up to nothing take nothing", 5, []int{0, 0}, []int{0, 0}},
		{"nothing to share", 0, []int{1, 2}, []int{0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apportion(tt.total, tt.weights); !slices.Equal(got, tt.want) {
				t.Errorf("apportion(%d, %v) = %v, want %v", tt.total, tt.weights, got, tt.want)
			}
		})
	}
}

// TestChargeCriteria pins that what the criteria withheld is charged to the
// findings of the defects they answer, evenly, on the full scale, on top of
// what the checks already charged them.
func TestChargeCriteria(t *testing.T) {
	answered := &Defect{Name: "answered"}
	unanswered := &Defect{Name: "unanswered"}
	charged := 2
	finding := func(defect *Defect, penalty *int) Finding {
		return Finding{Issue: model.Issue{Penalty: penalty}, Defect: defect}
	}

	evaluation := Evaluation{Findings: []Finding{
		finding(answered, nil),
		finding(unanswered, &charged),
		finding(answered, nil),
	}}
	criteria := []Criterion[message]{
		// Withholds 10 of its 20, on a scale of 50 once the third leaves it:
		// 20 points of the hundred, shared by the two findings answering it.
		{Name: "a", Weight: 20, Answers: []*Defect{answered}, Points: func(message) (int, bool) { return 10, true }},
		{Name: "b", Weight: 30, Points: func(message) (int, bool) { return 30, true }},
		{Name: "c", Weight: 50, Answers: []*Defect{answered}, Points: func(message) (int, bool) { return 0, false }},
	}

	ChargeCriteria(criteria, message{}, &evaluation)

	want := []int{10, 2, 10}
	for i, issue := range evaluation.Issues {
		if issue.Penalty == nil || *issue.Penalty != want[i] {
			t.Errorf("issue %d is charged %v, want %d", i, issue.Penalty, want[i])
		}
	}
}
