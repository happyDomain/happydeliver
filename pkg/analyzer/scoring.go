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

import (
	"git.happydns.org/happyDeliver/internal/api"
)

// ScoreToGrade converts a percentage score (0-100) to a letter grade
func ScoreToGrade(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 85:
		return "B"
	case score >= 75:
		return "C"
	case score >= 65:
		return "D"
	case score >= 50:
		return "E"
	default:
		return "F"
	}
}

// ScoreToReportGrade converts a percentage score to an api.ReportGrade
func ScoreToReportGrade(score int) api.ReportGrade {
	return api.ReportGrade(ScoreToGrade(score))
}
