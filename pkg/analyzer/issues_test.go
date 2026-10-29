// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package analyzer

import (
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// TestCheckScoreCharges pins what each issue is charged: only what the score
// lost between 0 and 100, so bonuses above 100 and points below 0 cost nothing.
func TestCheckScoreCharges(t *testing.T) {
	c := checkScore{score: 110}  // bonuses lifted it above 100
	c.deduct(15, model.Issue{})  // 110 -> 95: only the 5 below 100 count
	c.cap(90, model.Issue{})     // 95 -> 90
	c.cap(95, model.Issue{})     // already below: nothing
	c.deduct(100, model.Issue{}) // 90 -> -10: only down to 0
	c.deduct(5, model.Issue{})   // -15: nothing left to lose
	c.note(model.Issue{})

	want := []int{5, 5, 0, 90, 0, 0}
	if len(c.issues) != len(want) {
		t.Fatalf("%d issues recorded, want %d", len(c.issues), len(want))
	}
	for i, issue := range c.issues {
		if *issue.Penalty != want[i] {
			t.Errorf("issue %d is charged %d, want %d", i, *issue.Penalty, want[i])
		}
	}
	if c.score != -15 {
		t.Errorf("score = %d, want -15", c.score)
	}
}
