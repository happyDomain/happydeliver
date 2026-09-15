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
	"bytes"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// What is held here is the reading of a file turning into findings: the defect
// a fact is filed under, and how grave it is said to be. What the facts
// themselves are worth reading off a name, or off the first bytes of a file,
// is fileinspect's own business, and is tested there.

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
		"a program announced as a document": {"document.pdf", "application/pdf", mzStub, model.IssueSeverityHigh},
		"a page announced as a document":    {"document.pdf", "application/pdf", []byte("<html><body>hello</body></html>"), model.IssueSeverityMedium},
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
