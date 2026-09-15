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
	"slices"

	"git.happydns.org/happyDeliver/internal/model"
)

// severityOrder ranks the severities from the least to the most grave, so that
// two of them can be compared at all: the values are strings, and "high" sorts
// before "low".
//
// It is the package's only statement of that order. A check that needs to
// compare, sort or cap a severity reads it from here, so that adding a level to
// the scale is one edit rather than a hunt.
var severityOrder = []model.IssueSeverity{
	model.IssueSeverityInfo,
	model.IssueSeverityLow,
	model.IssueSeverityMedium,
	model.IssueSeverityHigh,
	model.IssueSeverityCritical,
}

// lesserSeverity is the more modest of two severities.
func lesserSeverity(a, b model.IssueSeverity) model.IssueSeverity {
	if slices.Index(severityOrder, a) <= slices.Index(severityOrder, b) {
		return a
	}

	return b
}

// severityRank orders severities from the gravest down, for sorting only. It
// is not a weight: what a finding costs is severityPenalty.
//
// A severity the scale does not name ranks at the bottom rather than below it,
// which is where slices.Index would put it: an unknown value is the most
// modest thing we can say about a finding, not something graver than silence.
func severityRank(severity model.IssueSeverity) int {
	rank := slices.Index(severityOrder, severity)
	if rank < 0 {
		return 1
	}

	return rank + 1
}
