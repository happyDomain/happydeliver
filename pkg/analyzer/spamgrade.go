// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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

import "math"

// A spam filter's grade follows its verdict first, its score second: a message
// the filter let through never fails, however close it came to the limit.
//
//	A+  negative score
//	A   score of zero
//	B   very low score, under spamLowFraction of the limit
//	C   moderate score, under spamNearFraction of the limit
//	D   delivered but near the limit, or merely delayed (rspamd greylist)
//	E   classified as spam
//	F   classified as spam by a wide margin, or rejected outright
//
// Each letter owns a span of the 0-100 scale matching grade.Of, so that the
// number averaged into the report tells the same story as the letter.
type spamBand struct {
	grade  string
	hi, lo int
}

var (
	spamBandB = spamBand{"B", 94, 85}
	spamBandC = spamBand{"C", 84, 75}
	spamBandD = spamBand{"D", 74, 65}
	spamBandE = spamBand{"E", 64, 50}
	spamBandF = spamBand{"F", 49, 0}
)

const (
	// spamLowFraction of the limit is still a very low score.
	spamLowFraction = 0.2
	// spamNearFraction of the limit and beyond is near it.
	spamNearFraction = 0.7
	// spamAbusiveFactor times the limit is spam by a wide margin.
	spamAbusiveFactor = 2
)

// at places value within the band, from its best score at from to its worst at
// to; a value outside [from, to] is clamped to the band's ends.
func (b spamBand) at(value, from, to float64) (int, string) {
	pos := 0.0
	if to > from {
		pos = math.Max(0, math.Min(1, (value-from)/(to-from)))
	}
	return b.hi - int(math.Round(pos*float64(b.hi-b.lo))), b.grade
}

// gradeAcceptedSpamScore grades the score of a message the filter accepted,
// against the limit it did not reach.
func gradeAcceptedSpamScore(score, limit float64) (int, string) {
	switch {
	case score < 0:
		return 100, "A+"
	case score == 0:
		return 100, "A"
	}

	f := score / limit
	switch {
	case f < spamLowFraction:
		return spamBandB.at(f, 0, spamLowFraction)
	case f < spamNearFraction:
		return spamBandC.at(f, spamLowFraction, spamNearFraction)
	default:
		return spamBandD.at(f, spamNearFraction, 1)
	}
}
