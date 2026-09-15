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

package attachment

import (
	"git.happydns.org/happyDeliver/pkg/reading"
)

// attachmentCriterion is one of the things the attachment score weighs,
// written over the same file the attachment checks read and weighed by
// reading.Weigh.
type attachmentCriterion = reading.Criterion[*attachmentInput]

// attachmentCriteria is what the score of one file is made of. There is one
// of them, on purpose: the qualities worth weighing are detected inside the
// checks and turned straight into findings, and a criterion reading them back
// would only restate the penalty the family already charges. The whole scale
// is the baseline, and the checks deduct from it.
var attachmentCriteria = []attachmentCriterion{
	{
		Name:   "baseline",
		Weight: 100,
		Points: func(*attachmentInput) (int, bool) { return 100, true },
	},
}

// Score grades what a message carries, out of a hundred. Every attachment is
// weighed on its own, and the message takes the worst of them rather than
// their sum: ten innocuous documents do not make up for the eleventh. A
// message carrying nothing leaves the scale rather than earning a free
// hundred.
func (a *Analyzer) Score(results *Results, readings []Reading) (int, string) {
	if results == nil || len(results.Attachments) == 0 {
		return 0, ""
	}

	score, letter := 0, ""
	for i := range results.Attachments {
		// A caller that did not read at all weighs the file on the criteria
		// alone.
		penalty := 0
		if i < len(readings) {
			penalty = readings[i].Penalty
		}

		of, grade := reading.Weigh(attachmentCriteria, &attachmentInput{Attachment: &results.Attachments[i], MaxSize: a.maxSize}, penalty)
		if letter == "" || of < score {
			score, letter = of, grade
		}
	}

	return score, letter
}
