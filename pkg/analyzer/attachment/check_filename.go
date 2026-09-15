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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// filenameCheck reads the name a file gives itself, looking for one written to
// be misread.
var filenameCheck = attachmentCheck{
	Name:     "attachment_filename",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectDangerousExtension, defectDoubleExtension},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		return deceptiveNameFindings(in.Attachment.Filename, in.Attachment.Location), nil
	},
}

// deceptiveNameFindings detects deceptive filename constructions.
func deceptiveNameFindings(filename, location string) (findings []reading.Finding) {
	if filename == "" {
		return nil
	}

	// Windows silently strips trailing dots/spaces from filenames on save, so
	// "invoice.pdf.exe." reaches disk as "invoice.pdf.exe": trim before
	// extracting the extension or the check is trivially bypassed.
	lower := strings.TrimRight(strings.ToLower(filename), " .")
	tokens := strings.Split(lower, ".")
	finalExt := tokens[len(tokens)-1]

	if dangerousExtensions[finalExt] {
		findings = append(findings, finding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityHigh,
			location,
			fmt.Sprintf("File %q has a dangerous extension .%s", filename, finalExt),
			"Executable or script files should never be sent as email attachments; most providers reject them outright",
		))

		// Double extension: a decoy document extension right before the real one
		if len(tokens) >= 3 && documentExtensions[tokens[len(tokens)-2]] {
			findings = append(findings, finding(
				defectDoubleExtension,
				model.IssueTypeDoubleExtension,
				model.IssueSeverityHigh,
				location,
				fmt.Sprintf("Filename %q uses a deceptive double extension", filename),
				"Double extensions like .pdf.exe are a common technique to disguise executables as documents",
			))
		}
	}

	if strings.ContainsRune(filename, '‮') { // right-to-left override
		findings = append(findings, finding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityHigh,
			location,
			fmt.Sprintf("Filename %q contains a right-to-left override character", filename),
			"The Unicode RTL override character is used to visually disguise a file's real extension",
		))
	}

	if strings.Contains(filename, strings.Repeat(" ", 10)) {
		findings = append(findings, finding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityMedium,
			location,
			fmt.Sprintf("Filename %q contains long whitespace padding", filename),
			"Whitespace padding is used to push the real file extension out of sight",
		))
	}

	return findings
}
