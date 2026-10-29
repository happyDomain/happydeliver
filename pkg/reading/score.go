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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/grade"
)

// Criterion is one of the things a score weighs. The checks say what is wrong
// with what was read; the criteria say what a good one is made of, which is a
// different question and deserves its own list.
//
// A criterion owns its weight, so the scale is read off the registry rather
// than reconstructed from a run of additions, and a criterion the observation
// cannot answer is withdrawn from the scale rather than failed: a body cut
// short in transit, or a file nobody was allowed to open, costs the sender
// nothing it did not do.
//
// It is written over the same In as the checks of the reading.
type Criterion[In any] struct {
	// Name identifies the criterion in the tests.
	Name string

	// Weight is what a flawless message earns here, and what leaves the scale
	// when the criterion cannot be judged.
	Weight int

	// Answers names the defects this criterion already charges for, by
	// withholding points a flawless message would have earned. A check is free
	// to report them (naming a defect is its job) but none of them may carry a
	// penalty family on top, which readingtest holds every registry to.
	Answers []*Defect

	// Points is what this observation earns of Weight, and whether the
	// criterion could be judged at all. Points above Weight are not expected;
	// points below zero are, a criterion being free to charge for what it
	// weighs.
	Points func(In) (points int, applicable bool)
}

// Weigh grades one observation out of a hundred: it awards what the criteria
// say the observation is worth, brings what could be judged back onto the
// full scale, then deducts what the checks found. A reading no criterion could
// judge answers an empty grade rather than a zero, so that the report leaves
// it out of its average.
func Weigh[In any](criteria []Criterion[In], in In, penalty int) (score int, letter string) {
	// The points a flawless message can reach. A criterion the observation
	// cannot answer is subtracted from it instead of being refused.
	attainable := 0

	for _, criterion := range criteria {
		points, applicable := criterion.Points(in)
		if !applicable {
			continue
		}
		attainable += criterion.Weight
		score += points
	}

	if attainable == 0 {
		return 0, ""
	}

	if attainable != 100 {
		score = score * 100 / attainable
	}

	// Answer for what the checks found. Each family of findings is capped on
	// its own, so that two unrelated defects are both answered for without
	// either deciding the grade by itself.
	score -= penalty

	score = min(max(score, 0), 100)

	return score, grade.Of(score)
}

// ChargeCriteria charges the findings of an evaluation what the criteria they
// answer withheld, so that the penalty an issue carries says what fixing it
// brings back, whichever way the score charged for it.
//
// What the criteria withheld is counted on the full scale, as Weigh brings the
// score back onto it, and shared between the criteria in proportion to what
// each withheld. A criterion's share is then split evenly between the
// findings of the defects it answers: each of them is one of the things that
// cost it points, a dead link or an image without alt text. A criterion that
// withheld points no finding answers for keeps them, which the registries'
// tests hold the vocabulary to.
//
// The penalty of the evaluation is left as it is: it is what the checks
// deduct on top of the criteria, which Weigh is handed apart.
func ChargeCriteria[In any](criteria []Criterion[In], in In, evaluation *Evaluation) {
	var withheld []int
	var answering [][]int
	attainable, awarded := 0, 0

	for _, criterion := range criteria {
		points, applicable := criterion.Points(in)
		if !applicable {
			continue
		}
		attainable += criterion.Weight
		awarded += points

		var findings []int
		for i, finding := range evaluation.Findings {
			if finding.Defect != nil && slices.Contains(criterion.Answers, finding.Defect) {
				findings = append(findings, i)
			}
		}
		withheld = append(withheld, criterion.Weight-points)
		answering = append(answering, findings)
	}

	if attainable == 0 {
		return
	}

	for c, share := range apportion(100-awarded*100/attainable, withheld) {
		even := make([]int, len(answering[c]))
		for i := range even {
			even[i] = 1
		}
		for i, charge := range apportion(share, even) {
			issue := &evaluation.Findings[answering[c][i]].Issue
			charged := charge
			if issue.Penalty != nil {
				charged += *issue.Penalty
			}
			issue.Penalty = &charged
		}
	}

	evaluation.Issues = make([]model.Issue, len(evaluation.Findings))
	for i, finding := range evaluation.Findings {
		evaluation.Issues[i] = finding.Issue
	}
}

// apportion splits total in proportion to weights, in whole points that add
// up to it: each takes the integer part of its share, and the points left go
// to the largest remainders, the first listed winning a tie. Weights adding
// up to nothing take nothing.
func apportion(total int, weights []int) []int {
	shares := make([]int, len(weights))

	sum := 0
	for _, weight := range weights {
		sum += max(weight, 0)
	}
	if sum == 0 || total <= 0 {
		return shares
	}

	remainders := make([]int, len(weights))
	given := 0
	for i, weight := range weights {
		weight = max(weight, 0)
		shares[i] = total * weight / sum
		remainders[i] = total * weight % sum
		given += shares[i]
	}

	order := make([]int, len(weights))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return remainders[b] - remainders[a] })
	for _, i := range order[:total-given] {
		shares[i]++
	}

	return shares
}
