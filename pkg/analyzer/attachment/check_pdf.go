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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// pdfActiveContentCheck reads a PDF for what it would do when opened.
var pdfActiveContentCheck = attachmentCheck{
	Name:     "attachment_pdf_active_content",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectPDFActiveContent},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		return pdfActiveContentFindings(in.Attachment.Data, in.Attachment.Location), nil
	},
}

// pdfActiveContentFindings looks for active-content tokens in PDF files.
func pdfActiveContentFindings(data []byte, location string) (findings []reading.Finding) {
	if !bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF")) {
		return nil
	}

	if containsPDFToken(data, "/JavaScript") || containsPDFToken(data, "/JS") {
		findings = append(findings, finding(
			defectPDFActiveContent,
			model.IssueTypePdfActiveContent,
			model.IssueSeverityHigh,
			location,
			"PDF contains embedded JavaScript",
			"JavaScript in PDF files is frequently used to exploit reader vulnerabilities",
		))
	}
	if containsPDFToken(data, "/Launch") {
		findings = append(findings, finding(
			defectPDFActiveContent,
			model.IssueTypePdfActiveContent,
			model.IssueSeverityHigh,
			location,
			"PDF contains a /Launch action (can execute external programs)",
			"Launch actions allow a PDF to start external programs and should not appear in legitimate documents",
		))
	}
	if containsPDFToken(data, "/OpenAction") || containsPDFToken(data, "/AA") {
		findings = append(findings, finding(
			defectPDFActiveContent,
			model.IssueTypePdfActiveContent,
			model.IssueSeverityMedium,
			location,
			"PDF contains automatic actions (/OpenAction or /AA)",
			"Automatic actions run when the document opens and are often combined with embedded JavaScript",
		))
	}
	if containsPDFToken(data, "/EmbeddedFile") {
		findings = append(findings, finding(
			defectPDFActiveContent,
			model.IssueTypePdfActiveContent,
			model.IssueSeverityInfo,
			location,
			"PDF contains embedded files",
			"Embedded files inside PDFs can smuggle payloads past filters",
		))
	}

	return findings
}

// containsPDFToken searches for a PDF name token ensuring it is not merely a
// prefix of a longer name (e.g. /JS must not match /JSFoo)
func containsPDFToken(data []byte, token string) bool {
	for offset := 0; ; {
		idx := bytes.Index(data[offset:], []byte(token))
		if idx < 0 {
			return false
		}
		after := offset + idx + len(token)
		if after >= len(data) || isPDFDelimiter(data[after]) {
			return true
		}
		offset = after
	}
}

// isPDFDelimiter reports whether the byte ends a PDF name token
func isPDFDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\f', '\x00', '/', '<', '>', '[', ']', '(', ')':
		return true
	}
	return false
}
