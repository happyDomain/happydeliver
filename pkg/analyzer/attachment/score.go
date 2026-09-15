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
	"git.happydns.org/happyDeliver/pkg/grade"
)

// Score grades what a message carries, out of a hundred.
//
// Every attachment answers for itself: its findings are capped family by
// family inside its own reading, and what is left is deducted from the scale.
// A file an engine recognises costs the whole of it, which is the score saying
// that nothing else about the message matters until that is dealt with.
//
// A message carrying nothing scores a hundred. That is provisional: the day
// this reading is weighed on criteria like the content one, a message with no
// attachment will leave the scale rather than earn a free mark on it.
func (a *Analyzer) Score(results *Results, readings []Reading) (int, string) {
	if results == nil {
		return 100, grade.Of(100)
	}

	score := 100
	for _, read := range readings {
		score -= read.Penalty
	}

	score = min(max(score, 0), 100)

	return score, grade.Of(score)
}
