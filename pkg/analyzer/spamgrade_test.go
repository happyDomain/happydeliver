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

package analyzer

import "testing"

func TestCapSpamGrade(t *testing.T) {
	tests := []struct {
		name      string
		score     int
		grade     string
		capScore  int
		capGrade  string
		wantScore int
		wantGrade string
	}{
		{"no verdict leaves the category", 92, "B", 100, "", 92, "B"},
		{"a verdict lowers the category", 92, "B", 64, "E", 64, "E"},
		{"a verdict never raises it", 40, "F", 64, "E", 40, "F"},
		{"a verdict grades a category no filter of ours graded", 0, "", 64, "E", 64, "E"},
		{"nothing at all stays ungraded", 0, "", 100, "", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := capSpamGrade(tt.score, tt.grade, tt.capScore, tt.capGrade)
			if score != tt.wantScore || grade != tt.wantGrade {
				t.Errorf("got %d %q, want %d %q", score, grade, tt.wantScore, tt.wantGrade)
			}
		})
	}
}

// deref reads an optional field of a result, its zero value when absent.
func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
