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

package attachment

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// executableCheck reads the first bytes of a file to see whether it is a
// program, whatever it is called.
var executableCheck = attachmentCheck{
	Name:     "attachment_executable",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectExecutableContent},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		return executableFindings(in.Attachment.Data, in.Attachment.Location), nil
	},
}

// executableFindings looks for executable file magic numbers.
func executableFindings(data []byte, location string) []reading.Finding {
	if len(data) < 4 {
		return nil
	}

	var format string
	switch {
	case bytes.HasPrefix(data, []byte("MZ")):
		format = "Windows executable (PE)"
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		format = "Linux executable (ELF)"
	case isMachO(data):
		format = "macOS executable (Mach-O)"
	default:
		return nil
	}

	return []reading.Finding{finding(
		defectExecutableContent,
		model.IssueTypeExecutableContent,
		model.IssueSeverityHigh,
		location,
		fmt.Sprintf("Attachment content is a %s", format),
		"Executables delivered by email are almost always malicious; verify the sender and the file's purpose",
	)}
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
