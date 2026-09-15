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
	"archive/zip"
	"bytes"
	"strings"
)

// ole2Magic is the magic number of legacy OLE2 compound files (doc, xls, ppt, msi)
var ole2Magic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// MacroEvidence says what betrayed the VBA macros of an Office document, and
// so how firmly they were established: a part of the document that can only be
// macros, markers that usually are, or nothing but the extension.
type MacroEvidence string

const (
	// MacroNone is a document nothing said macros about, and the zero value.
	MacroNone MacroEvidence = ""

	// MacroVBAProject is an OOXML document carrying the vbaProject.bin part,
	// which is where its macros live.
	MacroVBAProject MacroEvidence = "vba_project"

	// MacroOLE2Markers is a legacy compound document whose bytes carry the
	// markers macros leave behind. It is a heuristic.
	MacroOLE2Markers MacroEvidence = "ole2_markers"

	// MacroExtension is a document only its extension says anything about, the
	// content having been unreadable: a macro-enabled format is one that may
	// carry macros, not one that does.
	MacroExtension MacroEvidence = "extension"
)

// detectMacro looks for the VBA macros an Office document may carry: an OOXML
// archive containing vbaProject.bin, a legacy OLE2 file with VBA markers, or a
// macro-enabled extension as a fallback.
//
// A document whose content could be read answers off its content alone: an
// OOXML archive that opens and carries no vbaProject.bin has none, whatever
// its extension claims.
func detectMacro(name Name, data []byte) MacroEvidence {
	// OOXML documents are zip archives; macros live in a vbaProject.bin entry
	if bytes.HasPrefix(data, []byte("PK")) {
		if reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			for _, entry := range reader.File {
				if strings.HasSuffix(strings.ToLower(entry.Name), "vbaproject.bin") {
					return MacroVBAProject
				}
			}

			return MacroNone
		}
	}

	// Legacy OLE2 compound files: heuristic marker search
	if bytes.HasPrefix(data, ole2Magic) {
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("vba")) || bytes.Contains(lower, []byte("macros")) ||
			bytes.Contains(data, []byte("\x00Attribut")) {
			return MacroOLE2Markers
		}

		return MacroNone
	}

	// Fallback on macro-enabled extensions when content inspection was inconclusive
	if name.MacroEnabledExtension() {
		return MacroExtension
	}

	return MacroNone
}
