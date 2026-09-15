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
	"testing"
)

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

// ooxml builds an OOXML document carrying the named parts.
func ooxml(t *testing.T, parts ...string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range parts {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("content of " + name))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestInspectNameDoubleExtension(t *testing.T) {
	name := inspectName("invoice.pdf.exe")

	if name.Extension != "exe" {
		t.Errorf("Expected the file to be opened by .exe, got .%s", name.Extension)
	}
	if !name.Dangerous {
		t.Error("Expected .exe to be read as a format that runs")
	}
	if name.Decoy != "pdf" {
		t.Errorf("Expected pdf to be read as the decoy, got %q", name.Decoy)
	}
}

// TestInspectNameTrailingDotsAreStripped: Windows drops the trailing dot on
// save, so the file that reaches disk is the one to describe.
func TestInspectNameTrailingDotsAreStripped(t *testing.T) {
	name := inspectName("invoice.pdf.exe. ")

	if name.Extension != "exe" {
		t.Errorf("Expected the trailing dot and space to be stripped, got .%s", name.Extension)
	}
	if !name.Dangerous || name.Decoy != "pdf" {
		t.Errorf("Expected the decoy to survive the trimming, got %+v", name)
	}
}

// TestInspectNameDecoyNeedsSomethingToHide: a decoy is only a decoy in front
// of an extension that runs.
func TestInspectNameDecoyNeedsSomethingToHide(t *testing.T) {
	if name := inspectName("report.pdf.txt"); name.Decoy != "" {
		t.Errorf("Expected no decoy on a name nobody will run, got %q", name.Decoy)
	}
}

func TestInspectNameRTLOverride(t *testing.T) {
	if name := inspectName("annexe‮xcod.exe"); !name.RTLOverride {
		t.Error("Expected the right-to-left override to be read off the name")
	}
}

func TestInspectNameWhitespacePadding(t *testing.T) {
	if name := inspectName("invoice" + string(bytes.Repeat([]byte(" "), 20)) + ".exe"); !name.WhitespacePadding {
		t.Error("Expected the padding to be read off the name")
	}
}

func TestInspectNameOfNothing(t *testing.T) {
	if name := inspectName(""); name != (Name{}) {
		t.Errorf("Expected a name nobody gave to say nothing, got %+v", name)
	}
}

func TestInspectTypeDeclaredMismatch(t *testing.T) {
	facts := Inspect("document.pdf", "application/pdf", mzStub)

	if !facts.Type.DeclaredMismatch {
		t.Error("Expected a file announced as a PDF and made of a program to disagree with itself")
	}
	if !facts.Type.Executable {
		t.Errorf("Expected the detected type %q to be read as a program", facts.Type.Detected)
	}
}

func TestInspectTypeOctetStreamMakesNoClaim(t *testing.T) {
	facts := Inspect("file.pdf", "application/octet-stream", []byte("%PDF-1.4 harmless"))

	if facts.Type.DeclaredMismatch {
		t.Error("Expected application/octet-stream to be read as no claim at all")
	}
}

func TestInspectTypeExtensionMismatch(t *testing.T) {
	facts := Inspect("holiday.jpg", "", mzStub)

	if !facts.Type.ExtensionMismatch {
		t.Errorf("Expected .jpg to disagree with the detected %q", facts.Type.Detected)
	}
}

func TestDetectExecutable(t *testing.T) {
	for name, data := range map[string][]byte{
		"PE":    mzStub,
		"ELF":   append([]byte("\x7fELF"), bytes.Repeat([]byte{0}, 60)...),
		"MachO": append([]byte{0xfe, 0xed, 0xfa, 0xce}, bytes.Repeat([]byte{0}, 60)...),
	} {
		t.Run(name, func(t *testing.T) {
			if format := detectExecutable(data); format == "" {
				t.Error("Expected the first bytes to name an executable format")
			}
		})
	}
}

func TestDetectExecutableJavaClassIsNotUniversal(t *testing.T) {
	class := append([]byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, bytes.Repeat([]byte{0}, 56)...)

	if format := detectExecutable(class); format != "" {
		t.Errorf("Expected a Java class file not to read as a universal binary, got %q", format)
	}
}

func TestDetectMacroOOXML(t *testing.T) {
	document := ooxml(t, "[Content_Types].xml", "word/document.xml", "word/vbaProject.bin")

	if evidence := detectMacro(inspectName("macro.docm"), document); evidence != MacroVBAProject {
		t.Errorf("Expected the vbaProject.bin part to establish the macros, got %q", evidence)
	}
}

// TestDetectMacroOOXMLWithoutMacroAnswersOffItsContent: the extension of a
// macro-enabled format says what it may carry, and the archive says what it
// does.
func TestDetectMacroOOXMLWithoutMacroAnswersOffItsContent(t *testing.T) {
	document := ooxml(t, "[Content_Types].xml", "word/document.xml")

	if evidence := detectMacro(inspectName("normal.docm"), document); evidence != MacroNone {
		t.Errorf("Expected a macro-free document to answer off its content, got %q", evidence)
	}
}

func TestDetectMacroOLE2Markers(t *testing.T) {
	document := append(append([]byte{}, ole2Magic...), []byte("...VBA...Attribut...")...)

	if evidence := detectMacro(inspectName("legacy.doc"), document); evidence != MacroOLE2Markers {
		t.Errorf("Expected the VBA markers to be found in the compound file, got %q", evidence)
	}
}

func TestDetectMacroFallsBackOnTheExtension(t *testing.T) {
	if evidence := detectMacro(inspectName("unreadable.xlsm"), []byte("not an office document")); evidence != MacroExtension {
		t.Errorf("Expected the extension to be all that is left, got %q", evidence)
	}
}

func TestInspectHeaderReadsNoContent(t *testing.T) {
	facts := InspectHeader("invoice.pdf.exe", "application/pdf", mzStub)

	if !facts.Name.Dangerous || !facts.Type.DeclaredMismatch {
		t.Errorf("Expected the name and the type to be read, got %+v", facts)
	}
	if facts.Executable != "" || facts.Macro != MacroNone {
		t.Errorf("Expected the content to be left unread, got %+v", facts)
	}
}

// TestInspectNameDecoyNeedsAStem: pdf.exe is a file called pdf, not a decoy in
// front of a program.
func TestInspectNameDecoyNeedsAStem(t *testing.T) {
	name := inspectName("pdf.exe")

	if !name.Dangerous || name.Decoy != "" {
		t.Errorf("Expected a dangerous name without a decoy, got %+v", name)
	}
}

func TestInspectNameOfAnOrdinaryFile(t *testing.T) {
	name := inspectName("Quarterly Report.PDF")

	expected := Name{Filename: "Quarterly Report.PDF", Extension: "pdf"}
	if name != expected {
		t.Errorf("Expected nothing to be said of an ordinary name, got %+v", name)
	}
}

// TestInspectTypeNamelessProgramMismatchesOnlyItsClaim: a mismatch with an
// extension takes an extension.
func TestInspectTypeNamelessProgramMismatchesOnlyItsClaim(t *testing.T) {
	facts := Inspect("", "image/png", mzStub)

	if !facts.Type.DeclaredMismatch || facts.Type.ExtensionMismatch {
		t.Errorf("Expected the claim alone to be contradicted, got %+v", facts.Type)
	}
}

func TestMediaTypeOf(t *testing.T) {
	for contentType, expected := range map[string]string{
		"text/html; charset=utf-8": "text/html",
		" Application/PDF ":        "application/pdf",
		"":                         "",
	} {
		if got := mediaTypeOf(contentType); got != expected {
			t.Errorf("Expected %q to reduce to %q, got %q", contentType, expected, got)
		}
	}
}

func TestDetectExecutableMachOMagics(t *testing.T) {
	for name, magic := range map[string][]byte{
		"32-bit BE": {0xfe, 0xed, 0xfa, 0xce},
		"32-bit LE": {0xce, 0xfa, 0xed, 0xfe},
		"64-bit BE": {0xfe, 0xed, 0xfa, 0xcf},
		"64-bit LE": {0xcf, 0xfa, 0xed, 0xfe},
		"universal": {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02},
	} {
		t.Run(name, func(t *testing.T) {
			data := append(magic, bytes.Repeat([]byte{0}, 64)...)

			if format := detectExecutable(data); format != "macOS executable (Mach-O)" {
				t.Errorf("Expected the magic to name a Mach-O, got %q", format)
			}
		})
	}
}

// TestDetectExecutableOfNothing: a few bytes, or bytes that are not a magic
// number, are not a program.
func TestDetectExecutableOfNothing(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":           nil,
		"short MZ":        []byte("MZ"),
		"short universal": {0xca, 0xfe, 0xba, 0xbe},
		"text":            []byte("hello, world\n"),
		"unrelated magic": {0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if format := detectExecutable(data); format != "" {
				t.Errorf("Expected no executable format to be named, got %q", format)
			}
		})
	}
}

// TestIsMachOOfAFewBytes: fewer bytes than a magic number is no magic number.
func TestIsMachOOfAFewBytes(t *testing.T) {
	if isMachO([]byte{0xfe, 0xed}) {
		t.Error("Expected two bytes not to be read as a Mach-O")
	}
}

// TestDetectMacroCorruptedOOXMLFallsBackOnTheExtension: an archive that does
// not open says nothing of its content, and the extension is all that is
// left.
func TestDetectMacroCorruptedOOXMLFallsBackOnTheExtension(t *testing.T) {
	corrupted := []byte("PK\x03\x04this is not the rest of a zip")

	if evidence := detectMacro(inspectName("broken.docm"), corrupted); evidence != MacroExtension {
		t.Errorf("Expected the extension to be all that is left, got %q", evidence)
	}
	if evidence := detectMacro(inspectName("broken.docx"), corrupted); evidence != MacroNone {
		t.Errorf("Expected nothing to be said of a plain extension, got %q", evidence)
	}
}

// TestDetectMacroOLE2WithoutMarkersAnswersOffItsContent: a compound file that
// opened is held to its bytes, not to its extension.
func TestDetectMacroOLE2WithoutMarkersAnswersOffItsContent(t *testing.T) {
	document := append(append([]byte{}, ole2Magic...), bytes.Repeat([]byte("plain text of a letter "), 8)...)

	if evidence := detectMacro(inspectName("legacy.doc"), document); evidence != MacroNone {
		t.Errorf("Expected a marker-free compound file to carry no macros, got %q", evidence)
	}
}

func TestDetectMacroOLE2EachMarker(t *testing.T) {
	for name, marker := range map[string][]byte{
		"vba":      []byte("...VBA_PROJECT..."),
		"macros":   []byte("...Macros..."),
		"attribut": []byte("...\x00Attribut..."),
	} {
		t.Run(name, func(t *testing.T) {
			document := append(append([]byte{}, ole2Magic...), marker...)

			if evidence := detectMacro(inspectName("legacy.xls"), document); evidence != MacroOLE2Markers {
				t.Errorf("Expected the marker to be found, got %q", evidence)
			}
		})
	}
}

func TestDetectMacroOfAnOrdinaryFile(t *testing.T) {
	if evidence := detectMacro(inspectName("notes.txt"), []byte("nothing to see")); evidence != MacroNone {
		t.Errorf("Expected nothing to be said of an ordinary file, got %q", evidence)
	}
}
