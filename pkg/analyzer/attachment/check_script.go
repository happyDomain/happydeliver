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

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// scriptCheck reads a file for the script it is, or the one it carries.
var scriptCheck = attachmentCheck{
	Name:     "attachment_script",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectScriptContent},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		attachment := in.Attachment
		if attachment.mime == nil {
			return nil, nil
		}

		return scriptFindings(attachment.Filename, attachment.mime, attachment.Data, attachment.Location), nil
	},
}

// scriptFindings flags script payloads and HTML-smuggling attachments.
func scriptFindings(filename string, mtype *mimetype.MIME, data []byte, location string) (findings []reading.Finding) {
	if bytes.HasPrefix(data, []byte("#!")) {
		return []reading.Finding{finding(
			defectScriptContent,
			model.IssueTypeScriptContent,
			model.IssueSeverityMedium,
			location,
			"Attachment is an executable script (shebang)",
			"Scripts delivered by email should be treated as hostile",
		)}
	}

	ext := extensionOf(filename)
	isHTML := ext == "html" || ext == "htm" || mimeMatches(mtype, "text/html")
	if isHTML && bytes.Contains(bytes.ToLower(data), []byte("<script")) {
		severity := model.IssueSeverityMedium
		message := "HTML attachment contains scripts"
		lower := bytes.ToLower(data)
		// HTML smuggling: scripted attachment that decodes an embedded payload
		if bytes.Contains(lower, []byte("atob")) || bytes.Contains(lower, []byte("blob")) {
			severity = model.IssueSeverityHigh
			message = "HTML attachment contains scripts that decode an embedded payload (HTML smuggling pattern)"
		}
		findings = append(findings, finding(
			defectScriptContent,
			model.IssueTypeScriptContent,
			severity,
			location,
			message,
			"HTML attachments with scripts are used to assemble malware in the recipient's browser",
		))
	}

	return findings
}
