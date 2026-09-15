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
	"mime"

	"github.com/gabriel-vasile/mimetype"
)

// executableMediaTypes are the types a program is detected as, whichever
// system it was built for.
var executableMediaTypes = []string{
	"application/vnd.microsoft.portable-executable",
	"application/x-msdownload",
	"application/x-elf",
	"application/x-executable",
	"application/x-mach-binary",
	"application/x-sharedlib",
}

// noClaimMediaType is the type that declares nothing: a file announced as a
// stream of bytes has made no claim about itself, and so cannot have
// contradicted one.
const noClaimMediaType = "application/octet-stream"

// Type is what a file turns out to be, against what it claimed to be.
type Type struct {
	// Detected is the media type the content is in, as sniffed from its first
	// bytes.
	Detected string

	// Declared is the media type the file was announced as, empty when nobody
	// announced anything.
	Declared string

	// Executable says the detected type is a program. It is read off the type
	// hierarchy rather than off a magic number, and so covers formats
	// DetectExecutable does not name one by one.
	Executable bool

	// DeclaredMismatch says the announced type and the content disagree. A
	// file announced as a plain stream of bytes never sets it: it claimed
	// nothing.
	DeclaredMismatch bool

	// ExtensionMismatch says the type the extension implies and the content
	// disagree. An extension the standard library knows no type for never sets
	// it: nothing was implied to disagree with.
	ExtensionMismatch bool
}

// inspectType compares what a file claims to be, in whatever carried it and in
// its own name, against what its first bytes say it is.
func inspectType(name Name, declared string, mtype *mimetype.MIME) Type {
	fileType := Type{
		Detected:   mtype.String(),
		Declared:   declared,
		Executable: isExecutableMediaType(mtype),
	}

	if declared != "" && declared != noClaimMediaType && !mimeMatches(mtype, declared) {
		fileType.DeclaredMismatch = true
	}

	if name.Extension != "" {
		if expected := mime.TypeByExtension("." + name.Extension); expected != "" {
			if expectedMediaType := mediaTypeOf(expected); expectedMediaType != "" && !mimeMatches(mtype, expectedMediaType) {
				fileType.ExtensionMismatch = true
			}
		}
	}

	return fileType
}

// isExecutableMediaType reports whether the detected type is an executable
// format.
func isExecutableMediaType(mtype *mimetype.MIME) bool {
	for _, executable := range executableMediaTypes {
		if mimeMatches(mtype, executable) {
			return true
		}
	}

	return false
}
