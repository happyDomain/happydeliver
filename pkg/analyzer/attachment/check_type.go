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
	"context"
	"fmt"
	"mime"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// typeMismatchCheck compares what a file claims to be, in the message and in
// its own name, against what its first bytes say it is.
var typeMismatchCheck = attachmentCheck{
	Name:     "attachment_type_mismatch",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectTypeMismatch},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		attachment := in.Attachment
		if attachment.mime == nil {
			return nil, nil
		}

		return typeMismatchFindings(attachment.Filename, attachment.DeclaredType, attachment.mime, attachment.Location), nil
	},
}

// typeMismatchFindings compares the sniffed content type against the declared
// Content-Type and the filename extension.
func typeMismatchFindings(filename, declaredType string, mtype *mimetype.MIME, location string) (findings []reading.Finding) {
	// A file whose content is a program has the most to gain from lying about
	// what it is, so a mismatch that reveals one is read as a disguise rather
	// than as carelessness.
	detectedIsDangerous := isExecutableMIME(mtype)

	severity := func() model.IssueSeverity {
		if detectedIsDangerous {
			return model.IssueSeverityHigh
		}
		return model.IssueSeverityMedium
	}

	// Declared Content-Type vs magic bytes. application/octet-stream makes no claim.
	if declared := parseMediaType(declaredType); declared != "" &&
		declared != "application/octet-stream" && !mimeMatches(mtype, declared) {
		findings = append(findings, finding(
			defectTypeMismatch,
			model.IssueTypeTypeMismatch,
			severity(),
			location,
			fmt.Sprintf("Declared Content-Type %q but content is detected as %q", declared, mtype.String()),
			"The declared MIME type should match the actual file content",
		))
	}

	// Filename extension vs magic bytes
	if ext := extensionOf(filename); ext != "" {
		if expected := mime.TypeByExtension("." + ext); expected != "" {
			if expectedMediaType := parseMediaType(expected); expectedMediaType != "" && !mimeMatches(mtype, expectedMediaType) {
				findings = append(findings, finding(
					defectTypeMismatch,
					model.IssueTypeTypeMismatch,
					severity(),
					location,
					fmt.Sprintf("File extension .%s does not match detected content type %q", ext, mtype.String()),
					"A file whose extension disagrees with its content is a common malware disguise",
				))
			}
		}
	}

	return findings
}
