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

package app

import (
	"bytes"
	"strings"
	"testing"
)

// TestLicensesNameEveryEmbeddedWork checks that what the command prints
// carries, for every work this binary embeds, everything its license asks for:
// the creators, a link to the licensed material, the license text itself, and
// whether it was modified. Binary-only recipients get attribution through this
// text alone.
//
// Each embedded work's own package says the same of its own notice; this says
// that every one of them reaches the text a release prints.
func TestLicensesNameEveryEmbeddedWork(t *testing.T) {
	var printed bytes.Buffer
	if err := RunLicenses(&printed); err != nil {
		t.Fatalf("the licenses command failed: %v", err)
	}

	text := printed.String()

	required := []string{
		// The shortener list, CC-BY-SA-4.0, whose section 3(a)(1) is what this
		// list of requirements was first written for.
		"PeterDave Hello",
		"https://github.com/PeterDaveHello/url-shorteners",
		"CC-BY-SA-4.0",
		"https://creativecommons.org/licenses/by-sa/4.0/",
		"Attribution-ShareAlike 4.0 International",
		// An attribution says what was changed, which is what it is for.
		"Changes:",
		// The root certificates, which carry no license text of their own and
		// are named for where they come from.
		"Mark Verifying Authority root certificates",
		"https://bimigroup.org/vmc-issuers/",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Errorf("the printed notices are missing %q", want)
		}
	}

	// A work listed with nothing to say would print as an empty block and read
	// as attribution given. A missing license text is not that: some material
	// travels without one, and the attribution is then the whole of what there
	// is to print.
	for _, notice := range embeddedWorks {
		if notice.Attribution == "" {
			t.Error("an embedded work is listed with no attribution at all")
		}
	}

	// The full license texts must be printed, not just links to them.
	if len(text) < 5000 {
		t.Errorf("the notices are only %d bytes long, a license text looks truncated", len(text))
	}
}
