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

// Package fileinspect reads a file for what it is, and for what it would do
// when opened. It answers facts about bytes and knows nothing of email or
// reports: pricing those facts is the caller's business.
package fileinspect

import (
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// Facts is what reading one file offline turned up. Every field is a fact
// about the file, never a verdict about it. A zero Facts is what a file nobody
// could read leaves behind.
type Facts struct {
	// Name is what the file's own name says about it.
	Name Name

	// Type is what the file turns out to be, against what it claimed.
	Type Type

	// Executable names the executable format the first bytes are in, empty
	// when they are not a program.
	Executable string

	// Macro says what, if anything, betrayed VBA macros in an Office document.
	Macro MacroEvidence

	// PDF is what a PDF would do when opened, in the order the features are
	// looked for. Empty when the file is not a PDF, or is an inert one.
	PDF []PDFFeature
}

// InspectHeader reads what can be read of a file without reading it through:
// the name it gives itself, and the type its first bytes are in. The content
// fields of the Facts are left empty.
func InspectHeader(filename, declaredMediaType string, data []byte) Facts {
	name := inspectName(filename)

	return Facts{
		Name: name,
		Type: inspectType(name, declaredMediaType, mimetype.Detect(data)),
	}
}

// Inspect reads one file: the name it gives itself, the type it claims against
// the type its bytes are in, and what its content turns out to be.
//
// declaredMediaType is what the file was announced as by whoever carried it,
// already reduced to a media type; empty when nobody announced anything, which
// is the case of a file found inside an archive.
//
// It reads the bytes it is handed and nothing else: no file is opened, no
// service is asked.
func Inspect(filename, declaredMediaType string, data []byte) Facts {
	mtype := mimetype.Detect(data)
	name := inspectName(filename)

	return Facts{
		Name:       name,
		Type:       inspectType(name, declaredMediaType, mtype),
		Executable: detectExecutable(data),
		Macro:      detectMacro(name, data),
		PDF:        inspectPDF(data),
	}
}

// mimeMatches walks the detected type's parent hierarchy looking for expected
// (e.g. text/html matches an expected text/plain parent). Structured-suffix
// equivalences like docx (zip) are handled by the hierarchy too.
func mimeMatches(mtype *mimetype.MIME, expected string) bool {
	for m := mtype; m != nil; m = m.Parent() {
		if m.Is(expected) {
			return true
		}
	}

	return false
}

// mediaTypeOf reduces a Content-Type from the standard library's extension
// table to the media type it names, dropping the charset that may follow it.
func mediaTypeOf(contentType string) string {
	mediaType, _, _ := strings.Cut(contentType, ";")

	return strings.ToLower(strings.TrimSpace(mediaType))
}
