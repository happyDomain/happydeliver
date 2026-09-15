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
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

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

// TestAnalysisModel checks that what the report shows of a file says what the
// file is, whether or not anything was found in it.
func TestAnalysisModel(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")
	rawEmail := buildAttachmentEmail("report.pdf", "application/pdf", pdf)

	results, readings := read(t, analyzer, rawEmail)
	analysis := analyzer.Analysis(results, readings)

	if !analysis.HasAttachments {
		t.Fatal("Expected HasAttachments true")
	}
	check := (*analysis.Attachments)[0]
	if check.Filename == nil || *check.Filename != "report.pdf" {
		t.Errorf("Unexpected filename: %v", check.Filename)
	}
	if check.DeclaredContentType == nil || !strings.HasPrefix(*check.DeclaredContentType, "application/pdf") {
		t.Errorf("Unexpected declared type: %v", check.DeclaredContentType)
	}
	if check.DetectedContentType == nil || !strings.HasPrefix(*check.DetectedContentType, "application/pdf") {
		t.Errorf("Unexpected detected type: %v", check.DetectedContentType)
	}
	if check.Sha256 == "" || check.Size == 0 {
		t.Errorf("Expected sha256 and size to be set, got %q / %d", check.Sha256, check.Size)
	}
}
