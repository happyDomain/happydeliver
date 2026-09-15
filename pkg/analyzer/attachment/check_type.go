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
	"fmt"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// typeMismatchCheck compares what a file claims to be, in the message and in
// its own name, against what its first bytes say it is.
var typeMismatchCheck = staticCheck{
	Name:    "attachment_type_mismatch",
	Reports: []*reading.Defect{defectTypeMismatch},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return typeMismatchFindings(facts.Type, facts.Name, location)
	},
}

// typeMismatchFindings says what a file disagreeing with its own claims is
// worth.
func typeMismatchFindings(fileType fileinspect.Type, name fileinspect.Name, location string) (findings []reading.Finding) {
	// A file whose content is a program has the most to gain from lying about
	// what it is, so a mismatch that reveals one is read as a disguise rather
	// than as carelessness.
	severity := model.IssueSeverityMedium
	if fileType.Executable {
		severity = model.IssueSeverityHigh
	}

	if fileType.DeclaredMismatch {
		findings = append(findings, reading.NewFinding(
			defectTypeMismatch,
			model.IssueTypeTypeMismatch,
			severity,
			location,
			fmt.Sprintf("Declared Content-Type %q but content is detected as %q", fileType.Declared, fileType.Detected),
			"Declare the Content-Type the file actually has, or let your mailer pick it from the file",
		))
	}

	if fileType.ExtensionMismatch {
		findings = append(findings, reading.NewFinding(
			defectTypeMismatch,
			model.IssueTypeTypeMismatch,
			severity,
			location,
			fmt.Sprintf("File extension .%s does not match detected content type %q", name.Extension, fileType.Detected),
			"Give the file the extension of what it actually is",
		))
	}

	return findings
}
