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
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
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

func analyzeTestEmail(t *testing.T, analyzer *AttachmentAnalyzer, rawEmail string) *AttachmentResults {
	t.Helper()
	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}
	return analyzer.AnalyzeAttachments(email)
}

func newOfflineAnalyzer() *AttachmentAnalyzer {
	return NewAttachmentAnalyzer("", "", false, time.Second, 25<<20)
}

func findingTypes(findings []AttachmentFinding) map[model.AttachmentIssueType]int {
	types := make(map[model.AttachmentIssueType]int)
	for _, f := range findings {
		types[f.Type]++
	}
	return types
}

func TestAnalyzeAttachmentsNone(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	rawEmail := "From: sender@example.com\r\nSubject: no attachment\r\n\r\nJust text.\r\n"

	results := analyzeTestEmail(t, analyzer, rawEmail)
	if len(results.Attachments) != 0 {
		t.Fatalf("Expected no attachments, got %d", len(results.Attachments))
	}

	score, grade := analyzer.CalculateAttachmentScore(results)
	if score != 100 {
		t.Errorf("Expected score 100 without attachments, got %d", score)
	}
	if grade != "A" {
		t.Errorf("Expected grade A, got %q", grade)
	}

	analysis := analyzer.GenerateAttachmentAnalysis(results)
	if analysis.HasAttachments {
		t.Error("HasAttachments should be false")
	}
}

func TestAnalyzeAttachmentsCleanPDF(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF")
	rawEmail := buildAttachmentEmail("report.pdf", "application/pdf", pdf)

	results := analyzeTestEmail(t, analyzer, rawEmail)
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
	if len(att.Findings) != 0 {
		t.Errorf("Expected no findings, got %+v", att.Findings)
	}

	score, _ := analyzer.CalculateAttachmentScore(results)
	if score != 100 {
		t.Errorf("Expected score 100 for clean PDF, got %d", score)
	}
}

func TestAnalyzeAttachmentsZippedExecutable(t *testing.T) {
	analyzer := newOfflineAnalyzer()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entry, _ := writer.Create("invoice.pdf.exe")
	entry.Write(mzStub)
	writer.Close()

	rawEmail := buildAttachmentEmail("invoice.zip", "application/zip", buf.Bytes())

	results := analyzeTestEmail(t, analyzer, rawEmail)
	if len(results.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(results.Attachments))
	}

	types := findingTypes(results.Attachments[0].Findings)
	if types[model.AttachmentIssueTypeExecutableContent] == 0 ||
		types[model.AttachmentIssueTypeDoubleExtension] == 0 {
		t.Errorf("Expected executable and double-extension findings, got %+v", results.Attachments[0].Findings)
	}

	score, grade := analyzer.CalculateAttachmentScore(results)
	if score > 30 {
		t.Errorf("Expected heavily degraded score, got %d (%s)", score, grade)
	}
}

func TestAnalyzeAttachmentsWithClamAV(t *testing.T) {
	analyzer := NewAttachmentAnalyzer(fakeClamd(t), "", false, 5*time.Second, 25<<20)

	rawEmail := buildAttachmentEmail("virus.txt", "text/plain", []byte(eicarTestString))

	results := analyzeTestEmail(t, analyzer, rawEmail)
	if !results.ClamAVEnabled {
		t.Fatal("Expected ClamAV enabled")
	}
	if len(results.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(results.Attachments))
	}

	att := results.Attachments[0]
	if att.ClamAV == nil || att.ClamAV.Status != "infected" {
		t.Fatalf("Expected infected ClamAV status, got %+v", att.ClamAV)
	}

	types := findingTypes(att.Findings)
	if types[model.AttachmentIssueTypeMalwareDetected] == 0 {
		t.Errorf("Expected malware_detected finding, got %+v", att.Findings)
	}

	score, grade := analyzer.CalculateAttachmentScore(results)
	if score != 0 || grade != "F" {
		t.Errorf("Expected 0/F for infected attachment, got %d/%s", score, grade)
	}
}

func TestAnalyzeAttachmentsScannersDisabled(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	rawEmail := buildAttachmentEmail("notes.txt", "text/plain", []byte("meeting notes"))

	results := analyzeTestEmail(t, analyzer, rawEmail)
	analysis := analyzer.GenerateAttachmentAnalysis(results)

	if *analysis.ClamavEnabled || *analysis.VirustotalEnabled {
		t.Error("Expected both scanners reported as disabled")
	}

	check := (*analysis.Attachments)[0]
	if check.Clamav == nil || check.Clamav.Status != model.ClamAVResultStatusSkipped {
		t.Errorf("Expected skipped ClamAV status, got %+v", check.Clamav)
	}
	if check.Virustotal == nil || check.Virustotal.Status != model.VirusTotalResultStatusSkipped {
		t.Errorf("Expected skipped VirusTotal status, got %+v", check.Virustotal)
	}

	// Disabled scanners must not cost any points
	score, _ := analyzer.CalculateAttachmentScore(results)
	if score != 100 {
		t.Errorf("Expected score 100 with scanners disabled, got %d", score)
	}
}

func TestAnalyzeAttachmentsOversize(t *testing.T) {
	analyzer := NewAttachmentAnalyzer("", "", false, time.Second, 16)
	rawEmail := buildAttachmentEmail("big.bin", "application/octet-stream", bytes.Repeat([]byte("A"), 64))

	results := analyzeTestEmail(t, analyzer, rawEmail)
	att := results.Attachments[0]

	types := findingTypes(att.Findings)
	if types[model.AttachmentIssueTypeScanSkipped] == 0 {
		t.Errorf("Expected scan_skipped finding for oversize attachment, got %+v", att.Findings)
	}

	score, _ := analyzer.CalculateAttachmentScore(results)
	if score != 100 {
		t.Errorf("Oversize attachments should not be penalized, got %d", score)
	}
}

func TestGenerateAttachmentAnalysisModel(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	pdf := []byte("%PDF-1.4 << /JavaScript (x) /JS (y) >>")
	rawEmail := buildAttachmentEmail("active.pdf", "application/pdf", pdf)

	results := analyzeTestEmail(t, analyzer, rawEmail)
	analysis := analyzer.GenerateAttachmentAnalysis(results)

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
	if (*check.Issues)[0].Type != model.AttachmentIssueTypePdfActiveContent {
		t.Errorf("Expected pdf_active_content issue, got %s", (*check.Issues)[0].Type)
	}
}

func TestCalculateAttachmentScoreDeduplication(t *testing.T) {
	analyzer := newOfflineAnalyzer()
	results := &AttachmentResults{
		Attachments: []AttachmentResult{{
			Filename: "twice.pdf",
			Findings: []AttachmentFinding{
				{Type: model.AttachmentIssueTypePasswordProtected, Severity: model.AttachmentIssueSeverityMedium},
				{Type: model.AttachmentIssueTypePasswordProtected, Severity: model.AttachmentIssueSeverityMedium},
			},
		}},
	}

	score, _ := analyzer.CalculateAttachmentScore(results)
	if score != 85 {
		t.Errorf("Duplicate finding types should count once (expected 85), got %d", score)
	}
}
