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
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// macroCheck looks for the VBA macros an Office document may carry.
var macroCheck = attachmentCheck{
	Name:     "attachment_macro",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectMacro},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		return macroFindings(in.Attachment.Filename, in.Attachment.Data, in.Attachment.Location), nil
	},
}

// macroFindings looks for VBA macros in Office documents: an OOXML archive
// containing vbaProject.bin, a legacy OLE2 file with VBA markers, or a
// macro-enabled extension as fallback.
func macroFindings(filename string, data []byte, location string) []reading.Finding {
	// OOXML documents are zip archives; macros live in a vbaProject.bin entry
	if bytes.HasPrefix(data, []byte("PK")) {
		if reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			for _, entry := range reader.File {
				if strings.HasSuffix(strings.ToLower(entry.Name), "vbaproject.bin") {
					return []reading.Finding{finding(
						defectMacro,
						model.IssueTypeMacroDetected,
						model.IssueSeverityHigh,
						location,
						"Office document contains VBA macros (vbaProject.bin)",
						"Macros in email attachments are a primary malware infection vector; only enable them from fully trusted sources",
					)}
				}
			}
			return nil
		}
	}

	// Legacy OLE2 compound files: heuristic marker search
	if bytes.HasPrefix(data, ole2Magic) {
		lower := bytes.ToLower(data)
		if bytes.Contains(lower, []byte("vba")) || bytes.Contains(lower, []byte("macros")) ||
			bytes.Contains(data, []byte("\x00Attribut")) {
			return []reading.Finding{finding(
				defectMacro,
				model.IssueTypeMacroDetected,
				model.IssueSeverityHigh,
				location,
				"Legacy Office document may contain VBA macros (heuristic detection)",
				"Macros in email attachments are a primary malware infection vector; only enable them from fully trusted sources",
			)}
		}
		return nil
	}

	// Fallback on macro-enabled extensions when content inspection was inconclusive
	if ext := extensionOf(filename); macroEnabledExtensions[ext] {
		return []reading.Finding{finding(
			defectMacro,
			model.IssueTypeMacroDetected,
			model.IssueSeverityMedium,
			location,
			fmt.Sprintf("File extension .%s indicates a macro-enabled Office document", ext),
			"Macro-enabled Office formats should be treated with caution",
		)}
	}

	return nil
}
