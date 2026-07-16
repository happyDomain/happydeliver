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
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

func TestStaticCheckCleanPDF(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")
	detected, findings := staticCheckAttachment("report.pdf", "application/pdf", pdf, "report.pdf")

	if !strings.HasPrefix(detected, "application/pdf") {
		t.Errorf("Expected detected type application/pdf, got %q", detected)
	}
	if len(findings) != 0 {
		t.Errorf("Expected no findings for a clean PDF, got %+v", findings)
	}
}

func TestStaticCheckDoubleExtension(t *testing.T) {
	_, findings := staticCheckAttachment("invoice.pdf.exe", "application/octet-stream", mzStub, "invoice.pdf.exe")

	types := findingTypes(findings)
	for _, expected := range []model.AttachmentIssueType{
		model.AttachmentIssueTypeDoubleExtension,
		model.AttachmentIssueTypeDangerousExtension,
		model.AttachmentIssueTypeExecutableContent,
	} {
		if types[expected] == 0 {
			t.Errorf("Expected a %s finding, got %+v", expected, findings)
		}
	}
}

func TestStaticCheckTypeMismatchPDFIsExecutable(t *testing.T) {
	_, findings := staticCheckAttachment("document.pdf", "application/pdf", mzStub, "document.pdf")

	found := false
	for _, f := range findings {
		if f.Type == model.AttachmentIssueTypeTypeMismatch {
			found = true
			if f.Severity != model.AttachmentIssueSeverityHigh {
				t.Errorf("Mismatch hiding an executable should be high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("Expected a type_mismatch finding, got %+v", findings)
	}
}

func TestStaticCheckOctetStreamMakesNoClaim(t *testing.T) {
	pdf := []byte("%PDF-1.4 harmless")
	_, findings := staticCheckAttachment("file.pdf", "application/octet-stream", pdf, "file.pdf")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeTypeMismatch] != 0 {
		t.Errorf("application/octet-stream should not trigger declared-type mismatch, got %+v", findings)
	}
}

func TestStaticCheckRTLOverride(t *testing.T) {
	_, findings := staticCheckAttachment("annexe‮xcod.exe", "application/octet-stream", []byte("data"), "x")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeDangerousExtension] == 0 {
		t.Errorf("Expected dangerous_extension finding for RTL override, got %+v", findings)
	}
}

func TestStaticCheckELFExecutable(t *testing.T) {
	elf := append([]byte("\x7fELF"), bytes.Repeat([]byte{0}, 60)...)
	_, findings := staticCheckAttachment("tool", "application/octet-stream", elf, "tool")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeExecutableContent] == 0 {
		t.Errorf("Expected executable_content finding for ELF, got %+v", findings)
	}
}

func TestStaticCheckOOXMLMacro(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("content of " + name))
	}
	writer.Close()

	_, findings := staticCheckAttachment("macro.docm", "", buf.Bytes(), "macro.docm")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeMacroDetected] == 0 {
		t.Errorf("Expected macro_detected finding, got %+v", findings)
	}
}

func TestStaticCheckOOXMLWithoutMacro(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "word/document.xml"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("content"))
	}
	writer.Close()

	_, findings := staticCheckAttachment("normal.docx", "", buf.Bytes(), "normal.docx")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeMacroDetected] != 0 {
		t.Errorf("Expected no macro finding for macro-free docx, got %+v", findings)
	}
}

func TestStaticCheckOLE2Macro(t *testing.T) {
	doc := append(append([]byte{}, ole2Magic...), []byte("...VBA...Attribut...")...)
	_, findings := staticCheckAttachment("legacy.doc", "application/msword", doc, "legacy.doc")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeMacroDetected] == 0 {
		t.Errorf("Expected macro_detected finding for OLE2 with VBA marker, got %+v", findings)
	}
}

func TestStaticCheckPDFJavaScript(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj")
	_, findings := staticCheckAttachment("active.pdf", "application/pdf", pdf, "active.pdf")

	types := findingTypes(findings)
	if types[model.AttachmentIssueTypePdfActiveContent] < 2 {
		t.Errorf("Expected JavaScript + OpenAction findings, got %+v", findings)
	}
}

func TestStaticCheckPDFTokenNotPrefix(t *testing.T) {
	// /JSFoo must not match the /JS token
	pdf := []byte("%PDF-1.4 << /JSFoo (bar) >>")
	_, findings := staticCheckAttachment("x.pdf", "application/pdf", pdf, "x.pdf")

	if types := findingTypes(findings); types[model.AttachmentIssueTypePdfActiveContent] != 0 {
		t.Errorf("Expected no PDF active content finding, got %+v", findings)
	}
}

func TestStaticCheckHTMLSmuggling(t *testing.T) {
	html := []byte(`<html><script>var payload = atob("AAAA"); var b = new Blob([payload]);</script></html>`)
	_, findings := staticCheckAttachment("open-me.html", "text/html", html, "open-me.html")

	found := false
	for _, f := range findings {
		if f.Type == model.AttachmentIssueTypeScriptContent && f.Severity == model.AttachmentIssueSeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected high-severity script_content finding for HTML smuggling, got %+v", findings)
	}
}

func TestStaticCheckShebang(t *testing.T) {
	script := []byte("#!/bin/sh\nrm -rf --no-preserve-root /\n")
	_, findings := staticCheckAttachment("run.txt", "text/plain", script, "run.txt")

	if types := findingTypes(findings); types[model.AttachmentIssueTypeScriptContent] == 0 {
		t.Errorf("Expected script_content finding for shebang, got %+v", findings)
	}
}
