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

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestUUIDToBase32(t *testing.T) {
	t.Run("is lowercase and hyphenated every 7 chars", func(t *testing.T) {
		id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
		got := UUIDToBase32(id)

		if got != strings.ToLower(got) {
			t.Errorf("expected lowercase output, got %q", got)
		}

		// 16 bytes -> 26 base32 chars without padding, hyphen after each
		// group of 7 (positions 7, 14, 21) => 3 hyphens.
		if n := strings.Count(got, "-"); n != 3 {
			t.Errorf("expected 3 hyphens, got %d in %q", n, got)
		}

		for seg := range strings.SplitSeq(got, "-") {
			if len(seg) > 7 {
				t.Errorf("segment %q longer than 7 chars in %q", seg, got)
			}
		}
	})

	t.Run("nil UUID", func(t *testing.T) {
		got := UUIDToBase32(uuid.UUID{})
		if got == "" {
			t.Fatal("expected non-empty output for nil UUID")
		}
		// Round-trip should still recover the nil UUID.
		back, err := Base32ToUUID(got)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if back != (uuid.UUID{}) {
			t.Errorf("expected nil UUID, got %v", back)
		}
	})
}

func TestBase32ToUUID(t *testing.T) {
	t.Run("with hyphens", func(t *testing.T) {
		id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
		encoded := UUIDToBase32(id)
		got, err := Base32ToUUID(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Errorf("expected %v, got %v", id, got)
		}
	})

	t.Run("without hyphens", func(t *testing.T) {
		id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
		encoded := strings.ReplaceAll(UUIDToBase32(id), "-", "")
		got, err := Base32ToUUID(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Errorf("expected %v, got %v", id, got)
		}
	})

	t.Run("uppercase input", func(t *testing.T) {
		id := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
		encoded := strings.ToUpper(UUIDToBase32(id))
		got, err := Base32ToUUID(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Errorf("expected %v, got %v", id, got)
		}
	})

	t.Run("invalid base32 encoding", func(t *testing.T) {
		// '0', '1', '8', '9' are not valid RFC 4648 base32 symbols.
		_, err := Base32ToUUID("0189")
		if err == nil {
			t.Fatal("expected error for invalid base32 input")
		}
		if !strings.Contains(err.Error(), "invalid base32 encoding") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("wrong decoded length", func(t *testing.T) {
		// "aa" decodes to a single byte, well short of 16.
		_, err := Base32ToUUID("aa")
		if err == nil {
			t.Fatal("expected error for wrong UUID length")
		}
		if !strings.Contains(err.Error(), "invalid UUID length") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := Base32ToUUID("")
		if err == nil {
			t.Fatal("expected error for empty input")
		}
	})
}

func TestUUIDRoundTrip(t *testing.T) {
	for range 100 {
		id := uuid.New()
		encoded := UUIDToBase32(id)
		got, err := Base32ToUUID(encoded)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v", id, err)
		}
		if got != id {
			t.Errorf("round trip mismatch: expected %v, got %v", id, got)
		}
	}
}
