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
)

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
