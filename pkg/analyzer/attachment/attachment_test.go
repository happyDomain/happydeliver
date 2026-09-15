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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/clamav"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// infectedMarker is what a payload carries to have the fake clamd report it
// as infected. It is deliberately not the EICAR string: that one is meant to
// trip real engines, which would quarantine this file and the test binary on
// any machine running an on-access scanner.
const infectedMarker = "FAKE-CLAMD-INFECTED-MARKER"

// oversizeMarker is what a payload carries to have the fake clamd decline it
// for its size.
const oversizeMarker = "CLAMD-STREAM-TOO-LARGE"

// fakeClamd starts an in-process clamd simulator and returns its address. It
// answers FOUND when the streamed payload contains infectedMarker, the size
// limit error when it carries oversizeMarker, and OK otherwise.
func fakeClamd(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake clamd: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				reader := bufio.NewReader(conn)
				command, err := reader.ReadString('\x00')
				if err != nil || strings.TrimRight(command, "\x00") != "zINSTREAM" {
					return
				}

				var payload bytes.Buffer
				for {
					var sizeBuf [4]byte
					if _, err := io.ReadFull(reader, sizeBuf[:]); err != nil {
						return
					}
					size := binary.BigEndian.Uint32(sizeBuf[:])
					if size == 0 {
						break
					}
					if _, err := io.CopyN(&payload, reader, int64(size)); err != nil {
						return
					}
				}

				if bytes.Contains(payload.Bytes(), []byte(infectedMarker)) {
					conn.Write([]byte("stream: Eicar-Signature FOUND\x00"))
					return
				}
				if bytes.Contains(payload.Bytes(), []byte(oversizeMarker)) {
					conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
					return
				}
				conn.Write([]byte("stream: OK\x00"))
			}(conn)
		}
	}()

	return listener.Addr().String()
}

// buildAttachmentEmail assembles a multipart email with one attachment
func buildAttachmentEmail(filename, contentType string, payload []byte) string {
	var sb strings.Builder
	sb.WriteString("From: sender@example.com\r\n")
	sb.WriteString("To: recipient@example.com\r\n")
	sb.WriteString("Subject: Attachment analysis test\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n")
	sb.WriteString("\r\n")
	sb.WriteString("--BOUNDARY\r\n")
	sb.WriteString("Content-Type: text/plain\r\n")
	sb.WriteString("\r\n")
	sb.WriteString("Please find the file attached.\r\n")
	sb.WriteString("--BOUNDARY\r\n")
	fmt.Fprintf(&sb, "Content-Type: %s; name=\"%s\"\r\n", contentType, filename)
	sb.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&sb, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename)
	sb.WriteString("\r\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(payload))
	sb.WriteString("\r\n--BOUNDARY--\r\n")
	return sb.String()
}

// read observes a test message, then reads what was observed.
func read(t *testing.T, analyzer *Analyzer, rawEmail string) (*Results, []Reading) {
	t.Helper()

	email, err := mailmsg.Parse([]byte(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	results := analyzer.Analyze(email)

	return results, analyzer.Read(results)
}

func newOfflineAnalyzer() *Analyzer {
	return New(Options{ScanTimeout: time.Second, MaxSize: 25 << 20})
}

// issueTypes counts what a reading reported, by issue type.
func issueTypes(issues []model.Issue) map[model.IssueType]int {
	types := make(map[model.IssueType]int)
	for _, issue := range issues {
		types[issue.Type]++
	}
	return types
}

func TestAnalyzeAttachmentsNone(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	rawEmail := "From: sender@example.com\r\nSubject: no attachment\r\n\r\nJust text.\r\n"

	results, readings := read(t, analyzer, rawEmail)
	if len(results.Attachments) != 0 {
		t.Fatalf("Expected no attachments, got %d", len(results.Attachments))
	}
	if readings != nil {
		t.Errorf("Expected no reading without attachments, got %+v", readings)
	}

	// A message carrying nothing leaves the scale rather than earning a free
	// hundred.
	score, grade := analyzer.Score(results, readings)
	if grade != "" {
		t.Errorf("Expected no grade without attachments, got %q", grade)
	}
	if score != 0 {
		t.Errorf("Expected the score of a reading that did not happen to be 0, got %d", score)
	}

	analysis := analyzer.Analysis(results, readings)
	if analysis.HasAttachments {
		t.Error("HasAttachments should be false")
	}
}

func TestAnalyzeAttachmentsCleanPDF(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")
	rawEmail := buildAttachmentEmail("report.pdf", "application/pdf", pdf)

	results, readings := read(t, analyzer, rawEmail)
	if len(results.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(results.Attachments))
	}

	att := results.Attachments[0]
	if att.Filename != "report.pdf" {
		t.Errorf("Expected filename report.pdf, got %q", att.Filename)
	}
	if att.SHA256 == "" || att.Size == 0 {
		t.Errorf("Expected sha256 and size to be set, got %q / %d", att.SHA256, att.Size)
	}
	if !strings.HasPrefix(att.DetectedType, "application/pdf") {
		t.Errorf("Expected detected type application/pdf, got %q", att.DetectedType)
	}
	if len(readings[0].Issues) != 0 {
		t.Errorf("Expected no findings, got %+v", readings[0].Issues)
	}

	if score, _ := analyzer.Score(results, readings); score != 100 {
		t.Errorf("Expected score 100 for clean PDF, got %d", score)
	}
}

func TestAnalyzeAttachmentsWithClamAV(t *testing.T) {
	analyzer := New(Options{ScanTimeout: 5 * time.Second, MaxSize: 25 << 20, scanners: []scanner{clamavScanner{client: clamav.New(fakeClamd(t), 5*time.Second)}}})

	rawEmail := buildAttachmentEmail("virus.txt", "text/plain", []byte(infectedMarker))

	results, readings := read(t, analyzer, rawEmail)
	if len(results.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(results.Attachments))
	}

	att := results.Attachments[0]
	if scan := att.ScanBy("clamav"); scan == nil || scan.Status != model.ScanResultStatusMalicious {
		t.Fatalf("Expected a malicious verdict from ClamAV, got %+v", scan)
	}

	if types := issueTypes(readings[0].Issues); types[model.IssueTypeMalwareDetected] == 0 {
		t.Errorf("Expected malware_detected finding, got %+v", readings[0].Issues)
	}

	score, grade := analyzer.Score(results, readings)
	if score != 0 || grade != "F" {
		t.Errorf("Expected 0/F for infected attachment, got %d/%s", score, grade)
	}
}

func TestAnalyzeAttachmentsScannersDisabled(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	rawEmail := buildAttachmentEmail("notes.txt", "text/plain", []byte("meeting notes"))

	results, readings := read(t, analyzer, rawEmail)
	analysis := analyzer.Analysis(results, readings)

	// An instance that runs no scanner reports none: which engines it leaves
	// unconfigured never reaches the reader.
	check := (*analysis.Attachments)[0]
	if check.Scans != nil {
		t.Errorf("Expected no scan entry from an instance running no scanner, got %+v", *check.Scans)
	}

	// Disabled scanners must not cost any points
	if score, _ := analyzer.Score(results, readings); score != 100 {
		t.Errorf("Expected score 100 with scanners disabled, got %d", score)
	}
}

func TestAnalyzeAttachmentsOversize(t *testing.T) {
	analyzer := New(Options{ScanTimeout: time.Second, MaxSize: 16})
	rawEmail := buildAttachmentEmail("big.bin", "application/octet-stream", bytes.Repeat([]byte("A"), 64))

	results, readings := read(t, analyzer, rawEmail)

	if types := issueTypes(readings[0].Issues); types[model.IssueTypeScanSkipped] == 0 {
		t.Errorf("Expected scan_skipped finding for oversize attachment, got %+v", readings[0].Issues)
	}
	if results.Attachments[0].Data != nil {
		t.Error("An attachment too large to analyse must not be handed to the checks")
	}
	if results.Attachments[0].DetectedType == "" {
		t.Error("An attachment too large to analyse is still named, sized and typed")
	}

	if score, _ := analyzer.Score(results, readings); score != 100 {
		t.Errorf("Oversize attachments should not be penalized, got %d", score)
	}
}

func TestAnalysisModel(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	pdf := []byte("%PDF-1.4 << /JavaScript (x) /JS (y) >>")
	rawEmail := buildAttachmentEmail("active.pdf", "application/pdf", pdf)

	results, readings := read(t, analyzer, rawEmail)
	analysis := analyzer.Analysis(results, readings)

	if !analysis.HasAttachments {
		t.Fatal("Expected HasAttachments true")
	}
	check := (*analysis.Attachments)[0]
	if check.Filename == nil || *check.Filename != "active.pdf" {
		t.Errorf("Unexpected filename: %v", check.Filename)
	}
	if check.Issues == nil || len(*check.Issues) == 0 {
		t.Fatal("Expected issues in the generated analysis")
	}
	if (*check.Issues)[0].Type != model.IssueTypePdfActiveContent {
		t.Errorf("Expected pdf_active_content issue, got %s", (*check.Issues)[0].Type)
	}
	if (*check.Issues)[0].Category != model.IssueCategorySecurity {
		t.Errorf("Expected the finding to be filed under security, got %q", (*check.Issues)[0].Category)
	}
}

// TestAnUnnamedAttachmentIsNamedOnce holds every finding about one attachment
// to the same name for it, whether it comes from a static check or a scanner.
func TestAnUnnamedAttachmentIsNamedOnce(t *testing.T) {
	analyzer := New(Options{ScanTimeout: 5 * time.Second, MaxSize: 25 << 20, scanners: []scanner{clamavScanner{client: clamav.New(fakeClamd(t), 5*time.Second)}}})

	var sb strings.Builder
	sb.WriteString("From: sender@example.com\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n")
	sb.WriteString("--BOUNDARY\r\n")
	sb.WriteString("Content-Type: application/octet-stream\r\n")
	sb.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	sb.WriteString(base64.StdEncoding.EncodeToString([]byte(infectedMarker)))
	sb.WriteString("\r\n--BOUNDARY--\r\n")

	results, readings := read(t, analyzer, sb.String())
	if len(readings) != 1 || len(readings[0].Issues) == 0 {
		t.Fatalf("Expected findings about the unnamed attachment, got %+v", readings)
	}

	for _, issue := range readings[0].Issues {
		if issue.Location == nil || *issue.Location != results.Attachments[0].Location {
			t.Errorf("Finding %q names %v, want %q", issue.Type, issue.Location, results.Attachments[0].Location)
		}
	}
}
