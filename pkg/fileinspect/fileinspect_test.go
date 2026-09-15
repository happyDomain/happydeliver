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

package fileinspect

import (
	"bytes"
	"testing"
)

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

// TestInspectHeaderReadsTheTypeOffTheBytes is the first thing a file is asked:
// what it is, whatever it is called.
func TestInspectHeaderReadsTheTypeOffTheBytes(t *testing.T) {
	facts := InspectHeader(mzStub)

	if facts.Type.Detected != "application/vnd.microsoft.portable-executable" {
		t.Errorf("Expected the first bytes to name a program, got %q", facts.Type.Detected)
	}
}

func TestInspectHeaderOfNothing(t *testing.T) {
	if facts := InspectHeader(nil); facts.Type.Detected == "" {
		t.Error("Expected a file nobody could read to still be given a type")
	}
}
