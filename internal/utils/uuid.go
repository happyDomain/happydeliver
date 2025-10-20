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

package utils

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// UUIDToBase32 converts a UUID to a URL-safe Base32 string (without padding)
// with hyphens every 7 characters for better readability
func UUIDToBase32(id uuid.UUID) string {
	// Use RFC 4648 Base32 encoding (URL-safe)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:])
	// Convert to lowercase for better readability
	encoded = strings.ToLower(encoded)

	// Insert hyphens every 7 characters
	var result strings.Builder
	for i, char := range encoded {
		if i > 0 && i%7 == 0 {
			result.WriteRune('-')
		}
		result.WriteRune(char)
	}

	return result.String()
}

// Base32ToUUID converts a base32-encoded string back to a UUID
// Accepts strings with or without hyphens
func Base32ToUUID(encoded string) (uuid.UUID, error) {
	// Remove hyphens
	encoded = strings.ReplaceAll(encoded, "-", "")
	// Convert to uppercase for decoding
	encoded = strings.ToUpper(encoded)

	// Decode base32
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid base32 encoding: %w", err)
	}

	// Ensure we have exactly 16 bytes for a UUID
	if len(decoded) != 16 {
		return uuid.UUID{}, fmt.Errorf("invalid UUID length: expected 16 bytes, got %d", len(decoded))
	}

	// Convert byte slice to UUID
	var id uuid.UUID
	copy(id[:], decoded)
	return id, nil
}
