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

package utils

import "testing"

func TestPtrTo(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		p := PtrTo(42)
		if p == nil {
			t.Fatal("expected non-nil pointer")
		}
		if *p != 42 {
			t.Errorf("expected 42, got %d", *p)
		}
	})

	t.Run("string", func(t *testing.T) {
		p := PtrTo("hello")
		if p == nil {
			t.Fatal("expected non-nil pointer")
		}
		if *p != "hello" {
			t.Errorf("expected %q, got %q", "hello", *p)
		}
	})

	t.Run("zero value", func(t *testing.T) {
		p := PtrTo(0)
		if p == nil {
			t.Fatal("expected non-nil pointer")
		}
		if *p != 0 {
			t.Errorf("expected 0, got %d", *p)
		}
	})

	t.Run("independent copies", func(t *testing.T) {
		a := PtrTo(1)
		b := PtrTo(1)
		if a == b {
			t.Error("expected distinct pointers for separate calls")
		}
	})
}
