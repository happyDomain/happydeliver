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

// executableCheck reads the first bytes of a file to see whether it is a
// program, whatever it is called.
var executableCheck = staticCheck{
	Name:    "attachment_executable",
	Reports: []*reading.Defect{defectExecutableContent},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return executableFindings(facts.Executable, location)
	},
}

// executableFindings says what a program sent by email is worth. format is the
// executable format the file is in, empty when it is not a program.
func executableFindings(format, location string) []reading.Finding {
	if format == "" {
		return nil
	}

	return []reading.Finding{reading.NewFinding(
		defectExecutableContent,
		model.IssueTypeExecutableContent,
		model.IssueSeverityHigh,
		location,
		fmt.Sprintf("Attachment content is a %s", format),
		"Host the program and link to it instead; most providers drop a message carrying one",
	)}
}
