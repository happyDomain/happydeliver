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
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/clamav"
	"git.happydns.org/happyDeliver/pkg/reading"
	"git.happydns.org/happyDeliver/pkg/virustotal"
)

// fakeVirusTotal answers CheckHash with whatever a test decided, and records
// what it was asked.
type fakeVirusTotal struct {
	answer *virustotal.Scan

	askedHash    string
	askedContent []byte
}

func (f *fakeVirusTotal) CheckHash(_ context.Context, sha256 string, content []byte) *virustotal.Scan {
	f.askedHash = sha256
	f.askedContent = content
	return f.answer
}

// closedPort is an address nothing listens on, for a scanner that must fail to
// connect.
func closedPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()

	return address
}

// TestNewRunsTheEnginesTheOperatorConfigured holds New to reading the
// registry: an engine with an address or a key is run, one without is absent,
// and a caller naming no timeout gets the default.
func TestNewRunsTheEnginesTheOperatorConfigured(t *testing.T) {
	// The flags are package state: what this test sets, it puts back.
	savedClamav, savedKey := clamavAddress, virustotalAPIKey
	t.Cleanup(func() { clamavAddress, virustotalAPIKey = savedClamav, savedKey })

	clamavAddress, virustotalAPIKey = "", ""
	if analyzer := New(Options{}); len(analyzer.scanners) != 0 {
		t.Errorf("Expected no engine without configuration, got %d", len(analyzer.scanners))
	} else if analyzer.scanTimeout != defaultScanTimeout {
		t.Errorf("Expected the default timeout for a caller naming none, got %v", analyzer.scanTimeout)
	}

	clamavAddress, virustotalAPIKey = "127.0.0.1:3310", "secret"
	analyzer := New(Options{ScanTimeout: time.Second})
	if len(analyzer.scanners) != len(knownScanners) {
		t.Fatalf("Expected every known engine once configured, got %d", len(analyzer.scanners))
	}
	for _, def := range knownScanners {
		engine := analyzer.scannerFor(def.Name)
		if engine == nil {
			t.Errorf("Expected %s to be run, it is absent", def.Name)
			continue
		}
		if engine.info() != def.scannerInfo {
			t.Errorf("Expected %s to answer under its own name, got %+v", def.Name, engine.info())
		}
	}
	if analyzer.scannerFor("nobody") != nil {
		t.Error("Expected no engine under a name the registry does not know")
	}
}

// TestClamAVTranslatesEveryAnswer holds the ClamAV adapter to the report's
// vocabulary: a clean bill, a recognised sample, a file the daemon declined
// for its size, and a daemon that could not be reached.
func TestClamAVTranslatesEveryAnswer(t *testing.T) {
	scanOf := func(address string, data []byte) Scan {
		engine := clamavScanner{client: clamav.New(address, time.Second)}
		return engine.scan(context.Background(), &Attachment{Data: data})
	}

	daemon := fakeClamd(t)

	if scan := scanOf(daemon, []byte("harmless")); scan.Status != model.ScanResultStatusClean || scan.Scanner != "clamav" {
		t.Errorf("Expected a clean bill from clamav, got %+v", scan)
	}

	if scan := scanOf(daemon, []byte(infectedMarker)); scan.Status != model.ScanResultStatusMalicious || scan.Verdict != "Eicar-Signature" {
		t.Errorf("Expected the sample to be recognised by name, got %+v", scan)
	}

	// Declined is a skip, not an error.
	if scan := scanOf(daemon, []byte(oversizeMarker)); scan.Status != model.ScanResultStatusSkipped || scan.Detail == "" {
		t.Errorf("Expected a declined file reported as skipped with the daemon's reason, got %+v", scan)
	}

	if scan := scanOf(closedPort(t), []byte("harmless")); scan.Status != model.ScanResultStatusError || scan.Detail == "" {
		t.Errorf("Expected an unreachable daemon reported as an error with its reason, got %+v", scan)
	}
}

// TestVirusTotalTranslatesEveryAnswer holds the VirusTotal adapter to the
// report's vocabulary: counts and details are carried over, and a status the
// report has no word for is an error.
func TestVirusTotalTranslatesEveryAnswer(t *testing.T) {
	attachment := &Attachment{SHA256: "abc123", Data: []byte("sample")}

	scanOf := func(answer *virustotal.Scan) (Scan, *fakeVirusTotal) {
		client := &fakeVirusTotal{answer: answer}
		engine := virustotalScanner{client: client}
		return engine.scan(context.Background(), attachment), client
	}

	scan, client := scanOf(&virustotal.Scan{Status: "malicious", Malicious: 51, Positives: 51, Total: 70, Permalink: "https://www.virustotal.com/gui/file/abc123"})
	if client.askedHash != attachment.SHA256 || !bytes.Equal(client.askedContent, attachment.Data) {
		t.Errorf("Expected the hash and the bytes to be handed over, got %q / %q", client.askedHash, client.askedContent)
	}
	if scan.Scanner != "virustotal" || scan.Status != model.ScanResultStatusMalicious {
		t.Errorf("Expected a malicious verdict under virustotal's name, got %+v", scan)
	}
	if scan.EnginesFlagged != 51 || scan.EnginesTotal != 70 || scan.Link == "" {
		t.Errorf("Expected the engine count and the link carried over, got %+v", scan)
	}

	// One engine out of seventy is a heuristic firing, not a detection: the
	// file is worth a warning, not a failing grade. The count is still shown.
	scan, _ = scanOf(&virustotal.Scan{Status: "malicious", Malicious: 1, Positives: 1, Total: 70})
	if scan.Status != model.ScanResultStatusSuspicious || scan.EnginesFlagged != 1 || scan.EnginesTotal != 70 {
		t.Errorf("Expected a lone engine's detection read as suspicious, got %+v", scan)
	}

	// Engines that only find the file suspicious never make it malicious,
	// however many of them there are.
	scan, _ = scanOf(&virustotal.Scan{Status: "malicious", Malicious: virustotalMaliciousEngines, Suspicious: 10, Positives: 13, Total: 70})
	if scan.Status != model.ScanResultStatusMalicious {
		t.Errorf("Expected the bar reached on malicious verdicts alone, got %+v", scan)
	}

	// An engine that never saw the file counts nothing: the zero stays zero
	// rather than reading as "0 of 0 engines".
	scan, _ = scanOf(&virustotal.Scan{Status: "unknown"})
	if scan.Status != model.ScanResultStatusUnknown || scan.EnginesTotal != 0 || scan.Detail != "" {
		t.Errorf("Expected an unknown hash reported as such and nothing more, got %+v", scan)
	}

	scan, _ = scanOf(&virustotal.Scan{Status: "error", Error: "VirusTotal rate limit exceeded"})
	if scan.Status != model.ScanResultStatusError || scan.Detail != "VirusTotal rate limit exceeded" {
		t.Errorf("Expected the client's explanation kept, got %+v", scan)
	}

	scan, _ = scanOf(&virustotal.Scan{Status: "whatever"})
	if scan.Status != model.ScanResultStatusError || !strings.Contains(scan.Detail, `"whatever"`) {
		t.Errorf("Expected a status the report has no word for reported as an error naming it, got %+v", scan)
	}
}

// TestAConfiguredScannerIsNotAskedAboutAFileNobodyRead holds Analyze to
// skipping the engines for a file too large to look at, and the scanner check
// to saying nothing about it: the size check already told the reader.
func TestAConfiguredScannerIsNotAskedAboutAFileNobodyRead(t *testing.T) {
	analyzer := New(Options{ScanTimeout: time.Second, MaxSize: 16, scanners: []scanner{clamavScanner{client: clamav.New(closedPort(t), time.Second)}}})
	rawEmail := buildAttachmentEmail("big.bin", "application/octet-stream", bytes.Repeat([]byte("A"), 64))

	results, readings := read(t, analyzer, rawEmail)

	scan := results.Attachments[0].ScanBy("clamav")
	if scan == nil || scan.Status != model.ScanResultStatusSkipped || !strings.Contains(scan.Detail, "16 bytes") {
		t.Fatalf("Expected the engine skipped with the size it was held to, got %+v", scan)
	}

	// The daemon is unreachable: had it been asked, the scan would be an
	// error rather than a skip.
	types := issueTypes(readings[0].Issues)
	if types[model.IssueTypeScanError] != 0 {
		t.Errorf("Expected the unreachable daemon never to be asked, got %+v", readings[0].Issues)
	}
	if types[model.IssueTypeScanSkipped] != 1 {
		t.Errorf("Expected the reader told once that the file went unread, got %+v", readings[0].Issues)
	}
}

// TestAScannerDecliningAFileWeReadIsWorthALine holds the scanner check to the
// one skip worth reporting: a file read here that one engine would not look
// at.
func TestAScannerDecliningAFileWeReadIsWorthALine(t *testing.T) {
	attachment := observed("big.bin", "application/octet-stream", []byte("harmless"))
	attachment.Scans = []Scan{
		{Scanner: "clamav", Status: model.ScanResultStatusSkipped, Detail: "INSTREAM size limit exceeded. ERROR"},
		{Scanner: "virustotal", Status: model.ScanResultStatusSkipped},
	}

	issues, penalty := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})

	skipped := []model.Issue{}
	for _, issue := range issues {
		if issue.Type == model.IssueTypeScanSkipped {
			skipped = append(skipped, issue)
		}
	}
	if len(skipped) != 2 {
		t.Fatalf("Expected one line per declining engine, got %+v", issues)
	}
	if !strings.HasSuffix(skipped[0].Message, ": INSTREAM size limit exceeded. ERROR") {
		t.Errorf("Expected the engine's reason kept when it gave one, got %q", skipped[0].Message)
	}
	if strings.Contains(skipped[1].Message, ":") {
		t.Errorf("Expected no reason appended when the engine gave none, got %q", skipped[1].Message)
	}
	if penalty != 0 {
		t.Errorf("Expected a declined file to cost nothing, got %d", penalty)
	}
}

// TestAVerdictIsSupportedByWhatTheEngineOffers holds the evidence to the
// engine's own terms: a name when it gave one, a count when it aggregates,
// nothing when it has neither.
func TestAVerdictIsSupportedByWhatTheEngineOffers(t *testing.T) {
	cases := map[string]struct {
		scan Scan
		want string
	}{
		"named":   {Scan{Verdict: "Eicar-Signature", EnginesFlagged: 3, EnginesTotal: 70}, ": Eicar-Signature"},
		"counted": {Scan{EnginesFlagged: 3, EnginesTotal: 70}, " (3/70 engines)"},
		"bare":    {Scan{}, ""},
	}

	for name, tc := range cases {
		if got := scanEvidence(&tc.scan); got != tc.want {
			t.Errorf("%s: expected %q, got %q", name, tc.want, got)
		}
	}

	// The count is what a check quotes when a verdict has no name.
	attachment := observed("sample.bin", "application/octet-stream", []byte("sample"))
	attachment.Scans = []Scan{{Scanner: "virustotal", Status: model.ScanResultStatusMalicious, EnginesFlagged: 51, EnginesTotal: 70}}

	issues, _ := reading.Run(context.Background(), attachmentChecks, &attachmentInput{Attachment: attachment})
	for _, issue := range issues {
		if issue.Type == model.IssueTypeMalwareDetected && !strings.Contains(issue.Message, "(51/70 engines)") {
			t.Errorf("Expected the engine count quoted, got %q", issue.Message)
		}
	}
}
