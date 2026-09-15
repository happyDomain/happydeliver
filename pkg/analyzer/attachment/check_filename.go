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

// filenameCheck reads the name a file gives itself, looking for one written to
// be misread.
var filenameCheck = staticCheck{
	Name:    "attachment_filename",
	Reports: []*reading.Defect{defectDangerousExtension, defectDoubleExtension},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return deceptiveNameFindings(facts.Name, location)
	},
}

// deceptiveNameFindings says what a name written to be misread is worth.
func deceptiveNameFindings(name fileinspect.Name, location string) (findings []reading.Finding) {
	if name.Filename == "" {
		return nil
	}

	if name.Dangerous {
		findings = append(findings, reading.NewFinding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityHigh,
			location,
			fmt.Sprintf("File %q has a dangerous extension .%s", name.Filename, name.Extension),
			"Host the file and link to it instead; most providers reject these extensions outright",
		))
	}

	// A decoy document extension right before the real one, reported apart
	// from the dangerous extension itself.
	if name.Decoy != "" {
		findings = append(findings, reading.NewFinding(
			defectDoubleExtension,
			model.IssueTypeDoubleExtension,
			model.IssueSeverityHigh,
			location,
			fmt.Sprintf("Filename %q uses a deceptive double extension", name.Filename),
			"Rename the file so it carries its real extension only",
		))
	}

	if name.RTLOverride {
		findings = append(findings, reading.NewFinding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityHigh,
			location,
			fmt.Sprintf("Filename %q contains a right-to-left override character", name.Filename),
			"Remove the U+202E character from the filename",
		))
	}

	if name.WhitespacePadding {
		findings = append(findings, reading.NewFinding(
			defectDangerousExtension,
			model.IssueTypeDangerousExtension,
			model.IssueSeverityMedium,
			location,
			fmt.Sprintf("Filename %q contains long whitespace padding", name.Filename),
			"Strip the padding from the filename",
		))
	}

	return findings
}
