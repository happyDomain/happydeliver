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
	"encoding/binary"
)

// detectExecutable names the executable format the first bytes of a file are
// in, whatever it is called, and answers the empty string when they are not a
// program.
func detectExecutable(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	switch {
	case bytes.HasPrefix(data, []byte("MZ")):
		return "Windows executable (PE)"
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "Linux executable (ELF)"
	case isMachO(data):
		return "macOS executable (Mach-O)"
	}

	return ""
}

// isMachO checks the four Mach-O magic numbers (32/64 bit, both endiannesses)
// plus the universal-binary magic
func isMachO(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xfeedface, 0xcefaedfe, // 32-bit BE / LE
		0xfeedfacf, 0xcffaedfe, // 64-bit BE / LE
		0xcafebabe: // universal binary (also Java class files)
		// Java class files share 0xcafebabe: their next 4 bytes are a version
		// number >= 45, while universal binaries store a small architecture count
		if binary.BigEndian.Uint32(data[:4]) == 0xcafebabe {
			return len(data) >= 8 && binary.BigEndian.Uint32(data[4:8]) < 40
		}
		return true
	}
	return false
}
