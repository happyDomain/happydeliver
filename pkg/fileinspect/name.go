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
	"strings"
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

// Name is what the name of a file says about it, before anything is read of
// its content.
type Name struct {
	// Filename is the name as it was given, untouched.
	Filename string

	// Extension is the extension the file will be opened by: lowercased,
	// without its dot, and read after the trailing dots and spaces Windows
	// silently strips on save.
	Extension string

	// Dangerous says the extension names a format that runs, rather than one
	// that is merely read.
	Dangerous bool

	// Decoy is the innocuous extension placed right before a dangerous one, as
	// the pdf of invoice.pdf.exe. It is empty unless Dangerous is set.
	Decoy string

	// RTLOverride says the name carries the Unicode right-to-left override,
	// which reverses what the eye reads of the extension.
	RTLOverride bool

	// WhitespacePadding says the name carries a run of spaces long enough to
	// push its real extension out of sight.
	WhitespacePadding bool
}

// rtlOverride is the Unicode character that reverses the reading direction.
const rtlOverride = '‮'

// paddingRun is the number of consecutive spaces past which a name is padded
// rather than merely written oddly.
const paddingRun = 10

// inspectName reads what the name of a file says about it.
func inspectName(filename string) Name {
	name := Name{Filename: filename}
	if filename == "" {
		return name
	}

	// Windows silently strips trailing dots and spaces from filenames on save,
	// so "invoice.pdf.exe." reaches disk as "invoice.pdf.exe": trim before
	// extracting the extension or the reading is trivially bypassed.
	lower := strings.TrimRight(strings.ToLower(filename), " .")
	tokens := strings.Split(lower, ".")

	name.Extension = tokens[len(tokens)-1]
	name.Dangerous = dangerousExtensions[name.Extension]

	// A decoy takes three tokens at least: a stem, the extension that lies,
	// and the one that runs.
	if name.Dangerous && len(tokens) >= 3 && documentExtensions[tokens[len(tokens)-2]] {
		name.Decoy = tokens[len(tokens)-2]
	}

	name.RTLOverride = strings.ContainsRune(filename, rtlOverride)
	name.WhitespacePadding = strings.Contains(filename, strings.Repeat(" ", paddingRun))

	return name
}

// MacroEnabledExtension reports whether the name is that of an Office format
// carrying VBA macros by design. It reads Extension rather than the name as
// written, so that the same trick that hides a dangerous extension does not
// hide a macro-enabled one.
func (n Name) MacroEnabledExtension() bool {
	return macroEnabledExtensions[n.Extension]
}

// HTMLExtension reports whether the name is that of a page a browser will
// open.
func (n Name) HTMLExtension() bool {
	return n.Extension == "html" || n.Extension == "htm"
}
