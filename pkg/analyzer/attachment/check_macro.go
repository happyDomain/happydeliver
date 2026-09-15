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

// macroAdvice is what a sender is told to do about macros however they were found.
const macroAdvice = "Save the document in its macro-free format (.docx, .xlsx, .pptx) before attaching it, or host it and link to it"

// macroCheck looks for the VBA macros an Office document may carry.
var macroCheck = staticCheck{
	Name:    "attachment_macro",
	Reports: []*reading.Defect{defectMacro},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return macroFindings(facts.Macro, facts.Name, location)
	},
}

// macroFindings says what a document carrying macros is worth, and how firmly
// that was established: a part of the document that can only be macros is
// reported as a fact, an extension that merely allows them as a caution.
func macroFindings(evidence fileinspect.MacroEvidence, name fileinspect.Name, location string) []reading.Finding {
	switch evidence {
	case fileinspect.MacroVBAProject:
		return []reading.Finding{reading.NewFinding(
			defectMacro,
			model.IssueTypeMacroDetected,
			model.IssueSeverityHigh,
			location,
			"Office document contains VBA macros (vbaProject.bin)",
			macroAdvice,
		)}

	case fileinspect.MacroOLE2Markers:
		return []reading.Finding{reading.NewFinding(
			defectMacro,
			model.IssueTypeMacroDetected,
			model.IssueSeverityHigh,
			location,
			"Legacy Office document may contain VBA macros (heuristic detection)",
			macroAdvice,
		)}

	case fileinspect.MacroExtension:
		return []reading.Finding{reading.NewFinding(
			defectMacro,
			model.IssueTypeMacroDetected,
			model.IssueSeverityMedium,
			location,
			fmt.Sprintf("File extension .%s indicates a macro-enabled Office document", name.Extension),
			"Save the document in its macro-free format (.docx, .xlsx, .pptx) if it carries no macro",
		)}
	}

	return nil
}
