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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// pdfActiveContentCheck reads a PDF for what it would do when opened.
var pdfActiveContentCheck = staticCheck{
	Name:    "attachment_pdf_active_content",
	Reports: []*reading.Defect{defectPDFActiveContent},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return pdfActiveContentFindings(facts.PDF, location)
	},
}

// pdfActiveContent says what each thing a PDF would do when opened is worth.
var pdfActiveContent = map[fileinspect.PDFFeature]struct {
	severity model.IssueSeverity
	message  string
	advice   string
}{
	fileinspect.PDFJavaScript: {
		model.IssueSeverityHigh,
		"PDF contains embedded JavaScript",
		"JavaScript in PDF files is frequently used to exploit reader vulnerabilities",
	},
	fileinspect.PDFLaunch: {
		model.IssueSeverityHigh,
		"PDF contains a /Launch action (can execute external programs)",
		"Launch actions allow a PDF to start external programs and should not appear in legitimate documents",
	},
	fileinspect.PDFAutoAction: {
		model.IssueSeverityMedium,
		"PDF contains automatic actions (/OpenAction or /AA)",
		"Automatic actions run when the document opens and are often combined with embedded JavaScript",
	},
	fileinspect.PDFEmbeddedFile: {
		model.IssueSeverityInfo,
		"PDF contains embedded files",
		"Embedded files inside PDFs can smuggle payloads past filters",
	},
}

// pdfActiveContentFindings says what a PDF that acts when opened is worth.
func pdfActiveContentFindings(features []fileinspect.PDFFeature, location string) (findings []reading.Finding) {
	for _, feature := range features {
		said, known := pdfActiveContent[feature]
		if !known {
			continue
		}

		findings = append(findings, reading.NewFinding(
			defectPDFActiveContent,
			model.IssueTypePdfActiveContent,
			said.severity,
			location,
			said.message,
			said.advice,
		))
	}

	return findings
}
