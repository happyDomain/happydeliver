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

package analyzer

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"mime"
	"path"
	"strings"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/internal/model"
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

// staticCheckAttachment runs every offline detection on an attachment or
// archive member: filename tricks, declared/detected type mismatch and
// harmful-content heuristics. location identifies the file in messages
// (bare filename, or a path like "invoice.zip → payload.exe").
func staticCheckAttachment(filename, declaredType string, data []byte, location string) (detectedType string, findings []AttachmentFinding) {
	mtype := mimetype.Detect(data)
	detectedType = mtype.String()

	findings = append(findings, checkFilename(filename, location)...)
	findings = append(findings, checkTypeMismatch(filename, declaredType, mtype, location)...)
	findings = append(findings, detectExecutable(data, location)...)
	findings = append(findings, detectMacros(filename, data, location)...)

	return detectedType, findings
}

// checkFilename detects deceptive filename constructions
func checkFilename(filename, location string) (findings []AttachmentFinding) {
	if filename == "" {
		return nil
	}

	lower := strings.ToLower(filename)
	tokens := strings.Split(lower, ".")
	finalExt := tokens[len(tokens)-1]

	if dangerousExtensions[finalExt] {
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeDangerousExtension,
			Severity: model.AttachmentIssueSeverityHigh,
			Message:  fmt.Sprintf("File %q has a dangerous extension .%s", filename, finalExt),
			Location: location,
			Advice:   "Executable or script files should never be sent as email attachments; most providers reject them outright",
		})

		// Double extension: a decoy document extension right before the real one
		if len(tokens) >= 3 && documentExtensions[tokens[len(tokens)-2]] {
			findings = append(findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeDoubleExtension,
				Severity: model.AttachmentIssueSeverityHigh,
				Message:  fmt.Sprintf("Filename %q uses a deceptive double extension", filename),
				Location: location,
				Advice:   "Double extensions like .pdf.exe are a common technique to disguise executables as documents",
			})
		}
	}

	if strings.ContainsRune(filename, '‮') { // right-to-left override
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeDangerousExtension,
			Severity: model.AttachmentIssueSeverityHigh,
			Message:  fmt.Sprintf("Filename %q contains a right-to-left override character", filename),
			Location: location,
			Advice:   "The Unicode RTL override character is used to visually disguise a file's real extension",
		})
	}

	if strings.Contains(filename, strings.Repeat(" ", 10)) {
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeDangerousExtension,
			Severity: model.AttachmentIssueSeverityMedium,
			Message:  fmt.Sprintf("Filename %q contains long whitespace padding", filename),
			Location: location,
			Advice:   "Whitespace padding is used to push the real file extension out of sight",
		})
	}

	return findings
}

// checkTypeMismatch compares the sniffed content type against the declared
// Content-Type and the filename extension
func checkTypeMismatch(filename, declaredType string, mtype *mimetype.MIME, location string) (findings []AttachmentFinding) {
	detectedIsDangerous := isExecutableMIME(mtype)

	// Declared Content-Type vs magic bytes. application/octet-stream makes no claim.
	if declared, _, err := mime.ParseMediaType(declaredType); err == nil &&
		declared != "" && declared != "application/octet-stream" && !mimeMatches(mtype, declared) {
		severity := model.AttachmentIssueSeverityMedium
		if detectedIsDangerous {
			severity = model.AttachmentIssueSeverityHigh
		}
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeTypeMismatch,
			Severity: severity,
			Message:  fmt.Sprintf("Declared Content-Type %q but content is detected as %q", declared, mtype.String()),
			Location: location,
			Advice:   "The declared MIME type should match the actual file content",
		})
	}

	// Filename extension vs magic bytes
	if ext := strings.ToLower(strings.TrimPrefix(path.Ext(filename), ".")); ext != "" {
		if expected := mime.TypeByExtension("." + ext); expected != "" {
			if expectedMediaType, _, err := mime.ParseMediaType(expected); err == nil && !mimeMatches(mtype, expectedMediaType) {
				severity := model.AttachmentIssueSeverityMedium
				if detectedIsDangerous {
					severity = model.AttachmentIssueSeverityHigh
				}
				findings = append(findings, AttachmentFinding{
					Type:     model.AttachmentIssueTypeTypeMismatch,
					Severity: severity,
					Message:  fmt.Sprintf("File extension .%s does not match detected content type %q", ext, mtype.String()),
					Location: location,
					Advice:   "A file whose extension disagrees with its content is a common malware disguise",
				})
			}
		}
	}

	return findings
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

// detectExecutable looks for executable file magic numbers
func detectExecutable(data []byte, location string) (findings []AttachmentFinding) {
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

	return []AttachmentFinding{{
		Type:     model.AttachmentIssueTypeExecutableContent,
		Severity: model.AttachmentIssueSeverityHigh,
		Message:  fmt.Sprintf("Attachment content is a %s", format),
		Location: location,
		Advice:   "Executables delivered by email are almost always malicious; verify the sender and the file's purpose",
	}}
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
// detectMacros looks for VBA macros in Office documents: an OOXML archive
// containing vbaProject.bin, a legacy OLE2 file with VBA markers, or a
// macro-enabled extension as fallback
func detectMacros(filename string, data []byte, location string) (findings []AttachmentFinding) {
	// OOXML documents are zip archives; macros live in a vbaProject.bin entry
	if bytes.HasPrefix(data, []byte("PK")) {
		if reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			for _, entry := range reader.File {
				if strings.HasSuffix(entry.Name, "vbaProject.bin") {
					return []AttachmentFinding{{
						Type:     model.AttachmentIssueTypeMacroDetected,
						Severity: model.AttachmentIssueSeverityHigh,
						Message:  "Office document contains VBA macros (vbaProject.bin)",
						Location: location,
						Advice:   "Macros in email attachments are a primary malware infection vector; only enable them from fully trusted sources",
					}}
				}
			}
			return nil
		}
	}

	// Legacy OLE2 compound files: heuristic marker search
	if bytes.HasPrefix(data, ole2Magic) {
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("vba")) || bytes.Contains(lower, []byte("macros")) ||
			bytes.Contains(data, []byte("\x00Attribut")) {
			return []AttachmentFinding{{
				Type:     model.AttachmentIssueTypeMacroDetected,
				Severity: model.AttachmentIssueSeverityHigh,
				Message:  "Legacy Office document may contain VBA macros (heuristic detection)",
				Location: location,
				Advice:   "Macros in email attachments are a primary malware infection vector; only enable them from fully trusted sources",
			}}
		}
		return nil
	}

	// Fallback on macro-enabled extensions when content inspection was inconclusive
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(filename), "."))
	if macroEnabledExtensions[ext] {
		return []AttachmentFinding{{
			Type:     model.AttachmentIssueTypeMacroDetected,
			Severity: model.AttachmentIssueSeverityMedium,
			Message:  fmt.Sprintf("File extension .%s indicates a macro-enabled Office document", ext),
			Location: location,
			Advice:   "Macro-enabled Office formats should be treated with caution",
		}}
	}

	return nil
}
