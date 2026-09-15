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
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// TestNewFinding holds the one ceremony every check goes through: a location
// or an advice left empty is left out of the issue, not set to nothing.
func TestNewFinding(t *testing.T) {
	defect := &Defect{Name: "test"}

	full := NewFinding(defect, model.IssueType("test_issue"), model.IssueSeverityHigh, "body", "something is wrong", "fix it")

	if full.Defect != defect {
		t.Error("the finding does not carry its defect")
	}
	if full.Type != "test_issue" || full.Severity != model.IssueSeverityHigh || full.Message != "something is wrong" {
		t.Errorf("the issue reads %+v, want its type, severity and message as given", full.Issue)
	}
	if full.Location == nil || *full.Location != "body" {
		t.Errorf("the location reads %v, want %q", full.Location, "body")
	}
	if full.Advice == nil || *full.Advice != "fix it" {
		t.Errorf("the advice reads %v, want %q", full.Advice, "fix it")
	}

	bare := NewFinding(defect, model.IssueType("test_issue"), model.IssueSeverityLow, "", "noted", "")

	if bare.Location != nil {
		t.Errorf("an empty location was set to %q, want it left out", *bare.Location)
	}
	if bare.Advice != nil {
		t.Errorf("an empty advice was set to %q, want it left out", *bare.Advice)
	}
}
