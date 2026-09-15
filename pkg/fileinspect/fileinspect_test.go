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
	"slices"
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

func TestInspectPDFActiveContent(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj")

	features := inspectPDF(pdf)
	for _, expected := range []PDFFeature{PDFJavaScript, PDFAutoAction} {
		if !slices.Contains(features, expected) {
			t.Errorf("Expected %q among the features, got %v", expected, features)
		}
	}
}

func TestInspectPDFTokenIsNotAPrefix(t *testing.T) {
	if features := inspectPDF([]byte("%PDF-1.4 << /JSFoo (bar) >>")); len(features) != 0 {
		t.Errorf("Expected /JSFoo not to match the /JS token, got %v", features)
	}
}

func TestInspectPDFOfSomethingElse(t *testing.T) {
	if features := inspectPDF([]byte("just plain text")); features != nil {
		t.Errorf("Expected nothing to be read of a file that is not a PDF, got %v", features)
	}
}

func TestInspectScriptShebang(t *testing.T) {
	facts := Inspect("run.txt", "text/plain", []byte("#!/bin/sh\nrm -rf --no-preserve-root /\n"))

	if !facts.Script.Shebang {
		t.Error("Expected the named interpreter to be read off the first bytes")
	}
}

func TestInspectScriptHTMLSmuggling(t *testing.T) {
	page := []byte(`<html><script>var payload = atob("AAAA"); var b = new Blob([payload]);</script></html>`)
	facts := Inspect("open-me.html", "text/html", page)

	if !facts.Script.HTMLScript {
		t.Error("Expected the page to be read as carrying scripts")
	}
	if !facts.Script.Smuggling {
		t.Error("Expected the decoding of an embedded payload to be read as smuggling")
	}
}

func TestInspectScriptPlainHTML(t *testing.T) {
	facts := Inspect("newsletter.html", "text/html", []byte(`<html><body><p>Hello</p></body></html>`))

	if facts.Script.HTMLScript || facts.Script.Smuggling {
		t.Errorf("Expected a page carrying no script to say so, got %+v", facts.Script)
	}
}

func TestInspectCleanPDFFindsNothing(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")

	facts := Inspect("report.pdf", "application/pdf", pdf)

	if facts.Name.Dangerous || facts.Type.DeclaredMismatch || facts.Type.ExtensionMismatch ||
		facts.Executable != "" || facts.Macro != MacroNone || len(facts.PDF) != 0 ||
		facts.Script != (Script{}) {
		t.Errorf("Expected nothing to be found in a clean PDF, got %+v", facts)
	}
}

func TestInspectHeaderReadsNoContent(t *testing.T) {
	facts := InspectHeader("invoice.pdf.exe", "application/pdf", mzStub)

	if !facts.Name.Dangerous || !facts.Type.DeclaredMismatch {
		t.Errorf("Expected the name and the type to be read, got %+v", facts)
	}
	if facts.Executable != "" || facts.Macro != MacroNone || len(facts.PDF) != 0 || facts.Script != (Script{}) {
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

// TestInspectPDFEachFeature reads every feature on its own, under every
// spelling it is looked for.
func TestInspectPDFEachFeature(t *testing.T) {
	for token, expected := range map[string]PDFFeature{
		"/JavaScript":   PDFJavaScript,
		"/JS":           PDFJavaScript,
		"/Launch":       PDFLaunch,
		"/OpenAction":   PDFAutoAction,
		"/AA":           PDFAutoAction,
		"/EmbeddedFile": PDFEmbeddedFile,
	} {
		t.Run(token, func(t *testing.T) {
			pdf := []byte("%PDF-1.7\n1 0 obj\n<< " + token + " 2 0 R >>\nendobj")

			if features := inspectPDF(pdf); !slices.Equal(features, []PDFFeature{expected}) {
				t.Errorf("Expected %s to be read as %q alone, got %v", token, expected, features)
			}
		})
	}
}

// TestInspectPDFFeaturesComeInOrder: the order the features come back in is
// the order they are looked for, not the order they appear in.
func TestInspectPDFFeaturesComeInOrder(t *testing.T) {
	pdf := []byte("%PDF-1.7\n<< /EmbeddedFile 1 0 R /AA 2 0 R /Launch 3 0 R /JS (x) >>")

	expected := []PDFFeature{PDFJavaScript, PDFLaunch, PDFAutoAction, PDFEmbeddedFile}
	if features := inspectPDF(pdf); !slices.Equal(features, expected) {
		t.Errorf("Expected %v, got %v", expected, features)
	}
}

// TestInspectPDFTokenDelimiters: a name token ends at the delimiters the
// syntax knows, and at the end of the file.
func TestInspectPDFTokenDelimiters(t *testing.T) {
	for name, pdf := range map[string]string{
		"space":        "%PDF-1.4 /JS (x)",
		"newline":      "%PDF-1.4 /JS\n(x)",
		"slash":        "%PDF-1.4 /JS/Foo",
		"dict open":    "%PDF-1.4 /JS<<>>",
		"dict close":   "%PDF-1.4 <</S /JS>>",
		"array":        "%PDF-1.4 [/JS]",
		"end of file":  "%PDF-1.4 /JS",
		"after a miss": "%PDF-1.4 /JSFoo /JS (x)",
	} {
		t.Run(name, func(t *testing.T) {
			if features := inspectPDF([]byte(pdf)); !slices.Contains(features, PDFJavaScript) {
				t.Errorf("Expected the /JS token to be found, got %v", features)
			}
		})
	}
}

// TestInspectPDFHeaderWindow: readers accept a preamble before the header,
// within reason.
func TestInspectPDFHeaderWindow(t *testing.T) {
	body := []byte("%PDF-1.4\n<< /Launch (cmd) >>")

	if features := inspectPDF(append(bytes.Repeat([]byte("."), 512), body...)); len(features) != 1 {
		t.Errorf("Expected a PDF behind a short preamble to be read, got %v", features)
	}
	if features := inspectPDF(append(bytes.Repeat([]byte("."), 2048), body...)); features != nil {
		t.Errorf("Expected a header past the window not to be looked for, got %v", features)
	}
	if features := inspectPDF(nil); features != nil {
		t.Errorf("Expected nothing to be read of an empty file, got %v", features)
	}
}

// TestInspectNameExtensionsAreReadAfterTrimming: the trick that hides a
// dangerous extension hides a macro-enabled or an HTML one no better.
func TestInspectNameExtensionsAreReadAfterTrimming(t *testing.T) {
	if !inspectName("budget.XLSM.").MacroEnabledExtension() {
		t.Error("Expected .XLSM. to be read as a macro-enabled format")
	}
	if !inspectName("page.HTM ").HTMLExtension() || !inspectName("page.html").HTMLExtension() {
		t.Error("Expected .HTM and .html to be read as pages")
	}
	if inspectName("page.xhtml").HTMLExtension() || inspectName("budget.xlsx").MacroEnabledExtension() {
		t.Error("Expected neither .xhtml nor .xlsx to be read as such")
	}
}

// TestInspectScriptShebangIsNoPage: a file that names its interpreter is a
// script, whatever it says further down.
func TestInspectScriptShebangIsNoPage(t *testing.T) {
	facts := Inspect("page.html", "text/html", []byte("#!/bin/sh\n<html><script>atob('x')</script></html>"))

	if facts.Script != (Script{Shebang: true}) {
		t.Errorf("Expected the shebang alone to be read, got %+v", facts.Script)
	}
}

// TestInspectScriptPageByContentOrByName: a page is one by its bytes or by
// its name, either will do.
func TestInspectScriptPageByContentOrByName(t *testing.T) {
	page := []byte(`<!DOCTYPE html><html><head><script>alert(1)</script></head></html>`)

	for name, tc := range map[string]struct {
		filename string
		data     []byte
	}{
		"by content": {"attachment.bin", page},
		"by name":    {"page.htm", []byte(`<SCRIPT>alert(1)</SCRIPT>`)},
	} {
		t.Run(name, func(t *testing.T) {
			facts := Inspect(tc.filename, "", tc.data)

			if !facts.Script.HTMLScript || facts.Script.Smuggling {
				t.Errorf("Expected a scripted page without smuggling, got %+v", facts.Script)
			}
		})
	}
}

// TestInspectScriptTagOutsideAPageIsNoScript: a script tag in something that
// is not a page is text.
func TestInspectScriptTagOutsideAPageIsNoScript(t *testing.T) {
	facts := Inspect("notes.txt", "text/plain", []byte("remember to escape <script> in the template\n"))

	if facts.Script != (Script{}) {
		t.Errorf("Expected nothing to be read of a text file, got %+v", facts.Script)
	}
}

func TestInspectScriptSmugglingByBlob(t *testing.T) {
	page := []byte(`<html><script>var b = new Blob([bytes], {type: "octet/stream"});</script></html>`)

	if facts := Inspect("open-me.html", "text/html", page); !facts.Script.Smuggling {
		t.Errorf("Expected building a Blob to be read as smuggling, got %+v", facts.Script)
	}
}

// TestInspectOfNothing: an empty file nobody named is the zero Facts, but for
// the type its emptiness is detected as.
func TestInspectOfNothing(t *testing.T) {
	facts := Inspect("", "", nil)

	if facts.Name != (Name{}) || facts.Executable != "" || facts.Macro != MacroNone ||
		len(facts.PDF) != 0 || facts.Script != (Script{}) {
		t.Errorf("Expected nothing to be said of nothing, got %+v", facts)
	}
	if facts.Type.DeclaredMismatch || facts.Type.ExtensionMismatch || facts.Type.Executable {
		t.Errorf("Expected nothing to be held against nothing, got %+v", facts.Type)
	}
}
