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
	"archive/zip"
	"bytes"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

// findingTypes counts what a run of findings reported, by issue type.
func findingTypes(findings []reading.Finding) map[model.IssueType]int {
	types := make(map[model.IssueType]int)
	for _, f := range findings {
		types[f.Type]++
	}
	return types
}

// locationOf is where a finding says it was found, or the empty string when it
// named no place.
func locationOf(f reading.Finding) string {
	if f.Location == nil {
		return ""
	}
	return *f.Location
}

func TestStaticCheckCleanPDF(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")

	if findings := staticFindings("report.pdf", "application/pdf", pdf, "report.pdf"); len(findings) != 0 {
		t.Errorf("Expected no findings for a clean PDF, got %+v", findings)
	}
}

func TestStaticCheckDoubleExtension(t *testing.T) {
	findings := staticFindings("invoice.pdf.exe", "application/octet-stream", mzStub, "invoice.pdf.exe")

	types := findingTypes(findings)
	for _, expected := range []model.IssueType{
		model.IssueTypeDoubleExtension,
		model.IssueTypeDangerousExtension,
		model.IssueTypeExecutableContent,
	} {
		if types[expected] == 0 {
			t.Errorf("Expected a %s finding, got %+v", expected, findings)
		}
	}
}

func TestStaticCheckTypeMismatchPDFIsExecutable(t *testing.T) {
	findings := staticFindings("document.pdf", "application/pdf", mzStub, "document.pdf")

	found := false
	for _, f := range findings {
		if f.Type == model.IssueTypeTypeMismatch {
			found = true
			if f.Severity != model.IssueSeverityHigh {
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
	findings := staticFindings("file.pdf", "application/octet-stream", pdf, "file.pdf")

	if types := findingTypes(findings); types[model.IssueTypeTypeMismatch] != 0 {
		t.Errorf("application/octet-stream should not trigger declared-type mismatch, got %+v", findings)
	}
}

func TestStaticCheckRTLOverride(t *testing.T) {
	findings := staticFindings("annexe‮xcod.exe", "application/octet-stream", []byte("data"), "x")

	if types := findingTypes(findings); types[model.IssueTypeDangerousExtension] == 0 {
		t.Errorf("Expected dangerous_extension finding for RTL override, got %+v", findings)
	}
}

func TestStaticCheckELFExecutable(t *testing.T) {
	elf := append([]byte("\x7fELF"), bytes.Repeat([]byte{0}, 60)...)
	findings := staticFindings("tool", "application/octet-stream", elf, "tool")

	if types := findingTypes(findings); types[model.IssueTypeExecutableContent] == 0 {
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

	findings := staticFindings("macro.docm", "", buf.Bytes(), "macro.docm")

	if types := findingTypes(findings); types[model.IssueTypeMacroDetected] == 0 {
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

	findings := staticFindings("normal.docx", "", buf.Bytes(), "normal.docx")

	if types := findingTypes(findings); types[model.IssueTypeMacroDetected] != 0 {
		t.Errorf("Expected no macro finding for macro-free docx, got %+v", findings)
	}
}

func TestStaticCheckOLE2Macro(t *testing.T) {
	doc := append(append([]byte{}, ole2Magic...), []byte("...VBA...Attribut...")...)
	findings := staticFindings("legacy.doc", "application/msword", doc, "legacy.doc")

	if types := findingTypes(findings); types[model.IssueTypeMacroDetected] == 0 {
		t.Errorf("Expected macro_detected finding for OLE2 with VBA marker, got %+v", findings)
	}
}
