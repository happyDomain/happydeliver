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
	"mime"
	"path"
	"strings"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/pkg/reading"
)

// dangerousExtensions are file extensions commonly used to deliver malware.
// Values are lowercase without the leading dot.
var dangerousExtensions = map[string]bool{
	"exe": true, "scr": true, "pif": true, "com": true, "bat": true,
	"cmd": true, "js": true, "jse": true, "vbs": true, "vbe": true,
	"wsf": true, "wsh": true, "ps1": true, "psm1": true, "msi": true,
	"msp": true, "jar": true, "hta": true, "cpl": true, "lnk": true,
	"iso": true, "img": true, "vhd": true, "reg": true, "dll": true,
	"chm": true, "application": true, "appx": true,
}

// documentExtensions are innocuous-looking extensions used as decoys in
// double-extension attacks (invoice.pdf.exe)
var documentExtensions = map[string]bool{
	"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true,
	"ppt": true, "pptx": true, "odt": true, "ods": true, "txt": true,
	"rtf": true, "csv": true, "jpg": true, "jpeg": true, "png": true,
	"gif": true, "bmp": true, "html": true, "htm": true, "zip": true,
	"mp3": true, "mp4": true, "avi": true,
}

// macroEnabledExtensions are Office formats that may carry VBA macros by design
var macroEnabledExtensions = map[string]bool{
	"docm": true, "dotm": true, "xlsm": true, "xltm": true, "xlam": true,
	"pptm": true, "potm": true, "ppam": true, "ppsm": true, "sldm": true,
}

// ole2Magic is the magic number of legacy OLE2 compound files (doc, xls, ppt, msi)
var ole2Magic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// staticFindings runs every offline detection over one file: its name, its
// declared type against its content, and the harmful-content heuristics.
//
// It is what a check of the registry does to the attachment itself, and it is
// also what an archive member gets: a file inside a zip is read exactly as a
// file attached to the message would be, which is the point of looking inside
// the zip at all. The registry runs the same detections check by check so that
// each of them can be named, declared and priced on its own.
func staticFindings(filename, declaredType string, data []byte, location string) (findings []reading.Finding) {
	mtype := mimetype.Detect(data)

	findings = append(findings, deceptiveNameFindings(filename, location)...)
	findings = append(findings, typeMismatchFindings(filename, declaredType, mtype, location)...)
	findings = append(findings, executableFindings(data, location)...)
	findings = append(findings, macroFindings(filename, data, location)...)

	return findings
}

// extensionOf is the lowercased extension of a filename, without its dot.
func extensionOf(filename string) string {
	return strings.ToLower(strings.TrimPrefix(path.Ext(filename), "."))
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

// isExecutableMIME reports whether the detected type is an executable format
func isExecutableMIME(mtype *mimetype.MIME) bool {
	for _, executable := range []string{
		"application/vnd.microsoft.portable-executable",
		"application/x-msdownload",
		"application/x-elf",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
	} {
		if mimeMatches(mtype, executable) {
			return true
		}
	}
	return false
}

// parseMediaType is the media type of a Content-Type header, without its
// parameters, and empty when the header says nothing usable.
func parseMediaType(contentType string) string {
	declared, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}

	return declared
}
