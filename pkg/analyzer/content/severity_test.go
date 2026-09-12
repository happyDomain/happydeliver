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
	"testing"
)

// TestSeverityRankPutsWhatItDoesNotKnowAtTheBottom: an unknown severity ranks
// as the most modest thing, not below it.
func TestSeverityRankPutsWhatItDoesNotKnowAtTheBottom(t *testing.T) {
	if got := severityRank("unheard_of"); got != 1 {
		t.Errorf("severityRank of an unknown severity = %d, want 1", got)
	}

	lowest, highest := severityOrder[0], severityOrder[len(severityOrder)-1]
	if severityRank(highest) <= severityRank(lowest) {
		t.Errorf("%q ranks %d, want it above %q at %d", highest, severityRank(highest), lowest, severityRank(lowest))
	}
	if severityRank(lowest) < 1 {
		t.Errorf("%q ranks %d, below the unknown severity", lowest, severityRank(lowest))
	}
}
