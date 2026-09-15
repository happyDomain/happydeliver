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
	"context"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// What is held here is the reading of a file turning into findings: the defect
// a fact is filed under, how grave it is, and where it was found. Reading the
// facts themselves off a zip, a PDF or a name is tested in fileinspect.

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

// readFile is what the checks make of one file handed to them directly,
// without going through a message.
func readFile(filename, declaredMediaType string, data []byte) []reading.Finding {
	return staticFindings(fileinspect.Inspect(filename, declaredMediaType, data), filename)
}

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

// zipOf builds a zip holding one member.
func zipOf(t *testing.T, name string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	entry.Write(content)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestAFileThatIsWhatItClaimsIsReportedForNothing(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")

	if findings := readFile("report.pdf", "application/pdf", pdf); len(findings) != 0 {
		t.Errorf("Expected no findings for a clean PDF, got %+v", findings)
	}
}

// TestOneFileAnswersForEachThingWrongWithIt: a program called invoice.pdf.exe
// and announced as a PDF is three separate things to tell a reader, not one.
func TestOneFileAnswersForEachThingWrongWithIt(t *testing.T) {
	types := findingTypes(readFile("invoice.pdf.exe", "application/pdf", mzStub))

	for _, expected := range []model.IssueType{
		model.IssueTypeDangerousExtension,
		model.IssueTypeDoubleExtension,
		model.IssueTypeTypeMismatch,
		model.IssueTypeExecutableContent,
	} {
		if types[expected] == 0 {
			t.Errorf("Expected a %s finding, got %v", expected, types)
		}
	}
}

func TestAMismatchHidingAProgramIsGraver(t *testing.T) {
	for name, file := range map[string]struct {
		filename string
		declared string
		data     []byte
		expected model.IssueSeverity
	}{
		"a program announced as a document":  {"document.pdf", "application/pdf", mzStub, model.IssueSeverityHigh},
		"an archive announced as a document": {"document.pdf", "application/pdf", zipOf(t, "payload.txt", []byte("hello")), model.IssueSeverityMedium},
	} {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, f := range readFile(file.filename, file.declared, file.data) {
				if f.Type != model.IssueTypeTypeMismatch {
					continue
				}
				found = true
				if f.Severity != file.expected {
					t.Errorf("Expected severity %s, got %s", file.expected, f.Severity)
				}
			}
			if !found {
				t.Error("Expected a type_mismatch finding")
			}
		})
	}
}

// TestAHarmlessMismatchIsNoFinding: a disagreement between two types is
// charged for what it hides, and an "Excel" export that is an HTML table hides
// nothing.
func TestAHarmlessMismatchIsNoFinding(t *testing.T) {
	table := []byte("<html><body><table><tr><td>1</td></tr></table></body></html>")

	if types := findingTypes(readFile("export.xls", "application/vnd.ms-excel", table)); types[model.IssueTypeTypeMismatch] != 0 {
		t.Errorf("Expected an HTML table called a spreadsheet to be no mismatch, got %v", types)
	}
}

func TestMacrosEstablishedAndMacrosMerelyAllowed(t *testing.T) {
	var carried bytes.Buffer
	writer := zip.NewWriter(&carried)
	for _, name := range []string{"[Content_Types].xml", "word/vbaProject.bin"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("content"))
	}
	writer.Close()

	for name, file := range map[string]struct {
		filename string
		data     []byte
		expected model.IssueSeverity
	}{
		"carried": {"macro.docm", carried.Bytes(), model.IssueSeverityHigh},
		"allowed": {"unreadable.xlsm", []byte("not an office document"), model.IssueSeverityMedium},
	} {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, f := range readFile(file.filename, "", file.data) {
				if f.Type != model.IssueTypeMacroDetected {
					continue
				}
				found = true
				if f.Severity != file.expected {
					t.Errorf("Expected severity %s, got %s", file.expected, f.Severity)
				}
			}
			if !found {
				t.Error("Expected a macro_detected finding")
			}
		})
	}
}

func TestEachActiveFeatureOfAPDFIsReported(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj")

	if types := findingTypes(readFile("active.pdf", "application/pdf", pdf)); types[model.IssueTypePdfActiveContent] < 2 {
		t.Errorf("Expected the JavaScript and the automatic action to be reported apart, got %v", types)
	}
}

func TestHTMLSmugglingIsGraverThanAScriptedPage(t *testing.T) {
	smuggling := []byte(`<html><script>var payload = atob("AAAA"); var b = new Blob([payload]);</script></html>`)

	found := false
	for _, f := range readFile("open-me.html", "text/html", smuggling) {
		if f.Type == model.IssueTypeScriptContent {
			found = true
			if f.Severity != model.IssueSeverityHigh {
				t.Errorf("Expected a high-severity script_content finding, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected a script_content finding for an HTML smuggling attachment")
	}
}

func TestAScriptIsReportedWhateverItIsCalled(t *testing.T) {
	script := []byte("#!/bin/sh\nrm -rf --no-preserve-root /\n")

	if types := findingTypes(readFile("run.txt", "text/plain", script)); types[model.IssueTypeScriptContent] == 0 {
		t.Errorf("Expected script_content finding for a shebang, got %v", types)
	}
}

// TestAFindingInAnArchiveNamesTheWayToIt: the location is the path a reader
// would double-click through, starting from the attachment they were sent.
func TestAFindingInAnArchiveNamesTheWayToIt(t *testing.T) {
	outer := zipOf(t, "inner.zip", zipOf(t, "payload.pdf.exe", mzStub))

	findings := archiveFindings(fileinspect.Walk(outer, archiveLimits), "outer.zip")
	types := findingTypes(findings)

	if types[model.IssueTypeNestedArchive] == 0 {
		t.Errorf("Expected nested_archive finding, got %v", types)
	}
	if types[model.IssueTypeExecutableContent] == 0 {
		t.Errorf("Expected executable_content finding inside nested zip, got %v", types)
	}
	if types[model.IssueTypeDoubleExtension] == 0 {
		t.Errorf("Expected double_extension finding inside nested zip, got %v", types)
	}

	located := false
	for _, f := range findings {
		if f.Type == model.IssueTypeExecutableContent &&
			locationOf(f) == "outer.zip → inner.zip → payload.pdf.exe" {
			located = true
		}
	}
	if !located {
		t.Errorf("Expected the full archive path in the location, got %+v", findings)
	}
}

// TestAnArchiveAnswersForItselfAtItsOwnName: a locked zip is the attachment
// being locked, not a member of it.
func TestAnArchiveAnswersForItselfAtItsOwnName(t *testing.T) {
	entries := []fileinspect.Entry{{Kind: fileinspect.KindEncrypted}}

	findings := archiveFindings(entries, "locked.zip")
	if len(findings) != 1 {
		t.Fatalf("Expected the archive to be reported locked once, got %+v", findings)
	}
	if got := locationOf(findings[0]); got != "locked.zip" {
		t.Errorf("Expected the finding at the attachment itself, got %q", got)
	}
}

func TestTheDepthTheWalkStoppedAtIsTheOneItIsHeldTo(t *testing.T) {
	entries := []fileinspect.Entry{{Kind: fileinspect.KindTooDeep, At: []string{"level.zip"}, Name: "level.zip"}}

	findings := archiveFindings(entries, "deep.zip")
	if len(findings) != 1 {
		t.Fatalf("Expected one finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "exceeds 3 levels") {
		t.Errorf("Expected the message to name the depth the walk goes to, got %q", findings[0].Message)
	}
}

// TestWhatWasNotReadIsNamedWhetherOrNotAMemberCanBe is the difference between
// a zip, which names the member it gave up on, and a gzip stream, which has no
// member to name.
func TestWhatWasNotReadIsNamedWhetherOrNotAMemberCanBe(t *testing.T) {
	findings := archiveFindings([]fileinspect.Entry{
		{Kind: fileinspect.KindTruncated, Name: "huge.iso"},
		{Kind: fileinspect.KindTruncated},
		{Kind: fileinspect.KindBomb, Name: "zeros.bin"},
		{Kind: fileinspect.KindBomb},
		{Kind: fileinspect.KindBudgetExhausted},
	}, "archive.zip")

	if len(findings) != 5 {
		t.Fatalf("Expected every place the reading stopped to be reported, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, `"huge.iso"`) {
		t.Errorf("Expected the member to be named, got %q", findings[0].Message)
	}
	if strings.Contains(findings[1].Message, `""`) {
		t.Errorf("Expected no member to be named when there is none, got %q", findings[1].Message)
	}
	if !strings.Contains(findings[2].Message, `"zeros.bin"`) {
		t.Errorf("Expected the member to be named, got %q", findings[2].Message)
	}
}

func TestACleanArchiveIsReportedForNothing(t *testing.T) {
	clean := zipOf(t, "notes.txt", []byte("meeting notes"))

	if findings := archiveFindings(fileinspect.Walk(clean, archiveLimits), "notes.zip"); len(findings) != 0 {
		t.Errorf("Expected no findings for a clean zip, got %+v", findings)
	}
}

func TestAFileThatIsNoArchiveIsReportedForNothing(t *testing.T) {
	entries := fileinspect.Walk([]byte("just plain text"), archiveLimits)

	if findings := archiveFindings(entries, "note.txt"); findings != nil {
		t.Errorf("Expected nil findings for non-archive data, got %+v", findings)
	}
}

// TestEveryWayOfDisguisingANameIsReported covers the tricks the other tests
// do not reach: a name that reads backwards and one padded out of sight.
func TestEveryWayOfDisguisingANameIsReported(t *testing.T) {
	cases := map[string]struct {
		name fileinspect.Name
		want string
	}{
		"rtl":     {fileinspect.Name{Filename: "invoice‮fdp.exe", RTLOverride: true}, "right-to-left override"},
		"padding": {fileinspect.Name{Filename: "invoice.pdf" + strings.Repeat(" ", 40) + ".exe", WhitespacePadding: true}, "whitespace padding"},
	}

	for name, tc := range cases {
		findings := deceptiveNameFindings(tc.name, tc.name.Filename)
		if len(findings) != 1 {
			t.Errorf("%s: expected one finding, got %+v", name, findings)
			continue
		}
		if findings[0].Issue.Type != model.IssueTypeDangerousExtension || !strings.Contains(findings[0].Issue.Message, tc.want) {
			t.Errorf("%s: expected a dangerous extension finding about the %s, got %+v", name, tc.want, findings[0].Issue)
		}
	}

	if findings := deceptiveNameFindings(fileinspect.Name{}, "attachment #1"); findings != nil {
		t.Errorf("Expected nothing said of a file with no name, got %+v", findings)
	}
}

// TestALegacyDocumentWithMacroMarkersIsReportedAsAHeuristic: markers in a
// compound file are reported as likely macros, and worth the same as
// established ones.
func TestALegacyDocumentWithMacroMarkersIsReportedAsAHeuristic(t *testing.T) {
	document := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, []byte("some content with VBA inside")...)
	attachment := observed("report.doc", "application/msword", document)

	findings, err := macroCheck.check().Run(context.Background(), &attachmentInput{Attachment: attachment})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("Expected one macro finding, got %+v", findings)
	}
	if findings[0].Issue.Severity != model.IssueSeverityHigh || !strings.Contains(findings[0].Issue.Message, "heuristic") {
		t.Errorf("Expected a high finding said to be heuristic, got %+v", findings[0].Issue)
	}
}

// TestAPDFFeatureTheCheckDoesNotPriceIsPassedOver: a feature fileinspect
// learns to see tomorrow is not reported with a blank message.
func TestAPDFFeatureTheCheckDoesNotPriceIsPassedOver(t *testing.T) {
	findings := pdfActiveContentFindings([]fileinspect.PDFFeature{"holograms", fileinspect.PDFEmbeddedFile}, "doc.pdf")
	if len(findings) != 1 || findings[0].Issue.Severity != model.IssueSeverityInfo {
		t.Errorf("Expected only the known feature reported, got %+v", findings)
	}
}
