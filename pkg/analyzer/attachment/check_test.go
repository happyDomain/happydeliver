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
	"slices"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
	"git.happydns.org/happyDeliver/pkg/reading/readingtest"
)

// observed builds an attachment as Analyze would have, so that a test can hand
// the checks a file without going through a message.
func observed(filename, declaredType string, data []byte) *Attachment {
	attachment := &Attachment{
		Filename:          filename,
		DeclaredType:      declaredType,
		DeclaredMediaType: mailmsg.MediaType(declaredType),
		Size:              int64(len(data)),
		Location:          filename,
		Data:              data,
	}
	attachment.facts = fileinspect.Inspect(filename, attachment.DeclaredMediaType, data)
	attachment.DetectedType = attachment.facts.Type.Detected

	return attachment
}

// speakingInputs is one file per thing the registry looks for: together they
// make every check speak, so that what each of them reports can be held to
// what it declares.
func speakingInputs(t *testing.T) map[string]*attachmentInput {
	t.Helper()

	// A file too large to look at, kept as Analyze keeps it: name and type,
	// no content.
	oversize := observed("big.bin", "application/octet-stream", bytes.Repeat([]byte("A"), 64))
	oversize.Data = nil
	oversize.facts = fileinspect.InspectHeader(oversize.Filename, oversize.DeclaredMediaType, nil)

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("payload.pdf.exe")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write(mzStub)
	writer.Close()

	var macro bytes.Buffer
	macroWriter := zip.NewWriter(&macro)
	for _, name := range []string{"[Content_Types].xml", "word/vbaProject.bin"} {
		entry, err := macroWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("content"))
	}
	macroWriter.Close()

	recognised := observed("sample.bin", "application/octet-stream", []byte("sample"))
	recognised.Scans = []Scan{
		{Scanner: "clamav", Status: model.ScanResultStatusMalicious, Verdict: "Eicar-Signature"},
		{Scanner: "virustotal", Status: model.ScanResultStatusMalicious, EnginesFlagged: 51, EnginesTotal: 70},
	}

	unanswered := observed("unknown.bin", "application/octet-stream", []byte("unknown"))
	unanswered.Scans = []Scan{
		{Scanner: "clamav", Status: model.ScanResultStatusError, Detail: "connection refused"},
		{Scanner: "virustotal", Status: model.ScanResultStatusSkipped, Detail: "file larger than the engine accepts"},
	}

	inputs := map[string]*Attachment{
		"oversize":   oversize,
		"disguised":  observed("invoice.pdf.exe", "application/pdf", mzStub),
		"macro":      observed("macro.docm", "", macro.Bytes()),
		"pdf":        observed("active.pdf", "application/pdf", []byte("%PDF-1.4 << /OpenAction << /JS (x) >> >>")),
		"html":       observed("open-me.html", "text/html", []byte(`<html><script>atob("AAAA")</script></html>`)),
		"archive":    observed("invoice.zip", "application/zip", archive.Bytes()),
		"recognised": recognised,
		"unanswered": unanswered,
	}

	speaking := make(map[string]*attachmentInput, len(inputs))
	for name, attachment := range inputs {
		maxSize := int64(0)
		if attachment.Data == nil {
			maxSize = 16
		}
		speaking[name] = &attachmentInput{Attachment: attachment, MaxSize: maxSize}
	}

	return speaking
}

// TestAttachmentRegistry holds the attachment analysis to the rules every
// reading is made of, which live in readingtest.
func TestAttachmentRegistry(t *testing.T) {
	readingtest.Registry[*attachmentInput]{
		Checks:   attachmentChecks,
		Defects:  attachmentDefects,
		Criteria: attachmentCriteria,
		Speaking: speakingInputs(t),
		// A part carrying no name, no type and no bytes.
		Empty: &attachmentInput{Attachment: observed("", "", nil)},
	}.Test(t)
}

// TestTwoEnginesAgreeingReportOnce is what the merge exists for: a sample both
// scanners recognise is one fact about one file, not two alerts.
func TestTwoEnginesAgreeingReportOnce(t *testing.T) {
	attachment := observed("sample.bin", "application/octet-stream", []byte("sample"))
	attachment.Scans = []Scan{
		{Scanner: "clamav", Status: model.ScanResultStatusMalicious, Verdict: "Eicar-Signature"},
		{Scanner: "virustotal", Status: model.ScanResultStatusMalicious, EnginesFlagged: 51, EnginesTotal: 70},
	}

	issues, penalty := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})

	malware := []model.Issue{}
	for _, issue := range issues {
		if issue.Type == model.IssueTypeMalwareDetected {
			malware = append(malware, issue)
		}
	}

	if len(malware) != 1 {
		t.Fatalf("Expected one malware finding for one file, got %d: %+v", len(malware), malware)
	}
	if !strings.Contains(malware[0].Message, "ClamAV") {
		t.Errorf("Expected the local scanner's own words to be kept, got %q", malware[0].Message)
	}
	if malware[0].CorroboratedBy == nil || !slices.Contains(*malware[0].CorroboratedBy, "virustotal") {
		t.Errorf("Expected virustotal to be named as agreeing, got %v", malware[0].CorroboratedBy)
	}

	// One defect, charged once, however many engines saw it.
	if penalty != 100 {
		t.Errorf("Expected the file to cost the whole scale once, got %d", penalty)
	}
}

func TestASuspiciousVerdictCostsLessThanARecognisedSample(t *testing.T) {
	attachment := observed("sample.bin", "application/octet-stream", []byte("sample"))
	attachment.Scans = []Scan{
		{Scanner: "virustotal", Status: model.ScanResultStatusSuspicious, EnginesFlagged: 3, EnginesTotal: 70},
	}

	_, penalty := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})

	if penalty != 40 {
		t.Errorf("Expected a suspicious verdict to cost 40, got %d", penalty)
	}
}

// TestAScannerThatCouldNotAnswerLeavesTheReportStanding checks that a scanner
// being down is reported as a caveat, costs nothing, and does not silence the
// rest of the registry.
func TestAScannerThatCouldNotAnswerLeavesTheReportStanding(t *testing.T) {
	attachment := observed("invoice.pdf.exe", "application/pdf", mzStub)
	attachment.Scans = []Scan{
		{Scanner: "clamav", Status: model.ScanResultStatusError, Detail: "connection refused"},
	}

	issues, penalty := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})

	types := issueTypes(issues)
	if types[model.IssueTypeScanError] == 0 {
		t.Errorf("Expected the reader to be told the file went unverified, got %+v", issues)
	}
	if types[model.IssueTypeExecutableContent] == 0 {
		t.Errorf("Expected what we read for ourselves to stand, got %+v", issues)
	}

	// The executable, the deceptive name and the type it lies about, and
	// nothing for the scanner.
	if penalty != 50+40+40 {
		t.Errorf("Expected a scanner being down to cost nothing, got a penalty of %d", penalty)
	}
}

// TestAMalformedContentTypeStillDeclaresSomething holds the type check to
// reading a header no parser agrees on: an unquoted filename with a space in
// it defeats mime.ParseMediaType, and a file whose declared type is thrown
// away for that would be free to lie about what it is.
func TestAMalformedContentTypeStillDeclaresSomething(t *testing.T) {
	// The name agrees with the content: only the header can reveal the
	// disagreement.
	attachment := observed("setup.exe", "text/plain; name=Rapport contexte.txt", mzStub)

	issues, _ := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})

	if types := issueTypes(issues); types[model.IssueTypeTypeMismatch] == 0 {
		t.Errorf("Expected the declared type to be compared against the content, got %+v", issues)
	}
}

// TestOneDeceptiveNameIsChargedOnce holds a family to answering once: a
// filename written to be misread is a single decision, however many findings
// name it.
func TestOneDeceptiveNameIsChargedOnce(t *testing.T) {
	attachment := observed("invoice.pdf.exe", "application/octet-stream", []byte("harmless"))

	findings, err := filenameCheck.check().Run(context.Background(), &attachmentInput{Attachment: attachment})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("Expected the name to be read two ways, got %+v", findings)
	}

	_, penalty := reading.Run(context.Background(), []attachmentCheck{filenameCheck.check()}, &attachmentInput{Attachment: attachment})
	if penalty != 40 {
		t.Errorf("Expected one answer for one name, got a penalty of %d", penalty)
	}
}
