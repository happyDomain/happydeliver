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
	"bytes"
	"testing"
)

// mzStub is a minimal PE-looking payload (MZ magic)
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

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

// TestInspectHeaderReadsTheNameAndTheType is what a caller declining to open a
// payload is entitled to.
func TestInspectHeaderReadsTheNameAndTheType(t *testing.T) {
	facts := InspectHeader("invoice.pdf.exe", "application/pdf", mzStub)

	if !facts.Name.Dangerous || !facts.Type.DeclaredMismatch {
		t.Errorf("Expected the name and the type to be read, got %+v", facts)
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
