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
