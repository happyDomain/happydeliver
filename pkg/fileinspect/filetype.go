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

// noClaimMediaType is the type that declares nothing, and so contradicts
// nothing.
const noClaimMediaType = "application/octet-stream"

// mediaTypeAliases maps the spellings an archive type goes by in the wild to
// the one the detector knows it under, for the aliases it does not resolve
// itself.
var mediaTypeAliases = map[string]string{
	"application/x-zip":            "application/zip",
	"application/x-zip-compressed": "application/zip",
	"application/x-gzip":           "application/gzip",
	"application/x-gtar":           tarMediaType,
}

// Type is what a file turns out to be, against what it claimed to be. The two
// mismatch fields are set only when the content is a program or an archive
// announced as something else: a PNG named .jpg has nothing to hide.
type Type struct {
	// Detected is the media type the content is in, as sniffed from its first
	// bytes.
	Detected string

	// Declared is the media type the file was announced as, empty when nobody
	// announced anything.
	Declared string

	// Executable says the detected type is a program. It is read off the type
	// hierarchy, and so covers formats detectExecutable does not name.
	Executable bool

	// DeclaredMismatch says the content is a program or an archive, and was
	// announced as something else.
	DeclaredMismatch bool

	// ExtensionMismatch says the content is a program or an archive, and its
	// extension implies something else.
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

	// Only a program or an archive is worth disguising, and only those are
	// held to their claims.
	if !fileType.Executable && opener(fileType.Detected) == nil {
		return fileType
	}

	fileType.DeclaredMismatch = contradicts(mtype, declared)

	if name.Extension != "" {
		if expected := mime.TypeByExtension("." + name.Extension); expected != "" {
			fileType.ExtensionMismatch = contradicts(mtype, mediaTypeOf(expected))
		}
	}

	return fileType
}

// contradicts reports whether what the content was detected as rules out what
// was claimed for it. It errs on the side of agreement: a claim nobody made
// contradicts nothing, neither does a claim the detector has never heard of,
// nor a claim more specific than the detection (a docx whose telltale entry
// lies past the sniffed prefix is detected as the zip it also is).
func contradicts(mtype *mimetype.MIME, claimed string) bool {
	claimed = canonicalMediaType(claimed)
	if claimed == "" || claimed == noClaimMediaType || mimeMatches(mtype, claimed) {
		return false
	}

	claimedType := mimetype.Lookup(claimed)

	return claimedType != nil && !mimeMatches(claimedType, mtype.String())
}

// canonicalMediaType reduces a media type to the spelling the detector knows
// it under.
func canonicalMediaType(mediaType string) string {
	if canonical, ok := mediaTypeAliases[mediaType]; ok {
		return canonical
	}

	return mediaType
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
