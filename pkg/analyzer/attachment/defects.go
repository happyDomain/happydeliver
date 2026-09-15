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
	"git.happydns.org/happyDeliver/pkg/reading"
)

// attachmentDefects is the whole vocabulary. A defect missing from it is
// priced by nobody, and the tests say so.
var attachmentDefects = []*reading.Defect{
	defectMalware,
	defectExecutableContent,
	defectDangerousExtension,
	defectDoubleExtension,
	defectTypeMismatch,
	defectMacro,
	defectPDFActiveContent,
	defectScanSkipped,
	defectScanError,
}

var (
	// familyMalware answers for an engine saying outright that the file is
	// malicious. It is the one family that can decide the grade on its own.
	// What a verdict costs is read off its gravity: "this is a known sample"
	// and "several engines are uneasy about this" are different statements.
	familyMalware = &reading.Family{
		Name: "malware",
		Cap:  100,
		PerSeverity: map[model.IssueSeverity]int{
			model.IssueSeverityCritical: 100,
			model.IssueSeverityHigh:     40,
		},
	}

	// familyExecutable answers for an attachment whose content is a program.
	// There is nothing to weigh: either the magic bytes say it is one or they
	// do not.
	familyExecutable = &reading.Family{Name: "executable", Cap: 50, PerItem: 50}

	// familyDeceptiveName answers for a filename written to be misread: a
	// dangerous extension, a document extension placed in front of it, an
	// override character, padding that pushes the real extension out of sight.
	//
	// They are capped together, and charged once, because they are one
	// decision: a sender who names a file invoice.pdf.exe has not made two
	// mistakes.
	familyDeceptiveName = &reading.Family{Name: "deceptive_name", Cap: 40, PerItem: 40}

	// familyTypeMismatch answers for a file whose content is not what it
	// claims. A mismatch that reveals an executable is a disguise; one between
	// two document formats is usually a sender's tooling being careless, and
	// the gap between the two is wider than a severity step.
	familyTypeMismatch = &reading.Family{
		Name: "type_mismatch",
		Cap:  40,
		PerSeverity: map[model.IssueSeverity]int{
			model.IssueSeverityHigh:   40,
			model.IssueSeverityMedium: 20,
		},
	}

	// familyMacro answers for an Office document carrying VBA macros.
	familyMacro = &reading.Family{Name: "macro", Cap: 30, PerItem: 30}

	// familyActiveContent answers for a document that does something when it
	// is opened. It is priced by gravity because the same defect covers what
	// runs by itself and what merely could: an embedded file inside a PDF is
	// worth telling the sender about and worth nothing on the scale.
	familyActiveContent = &reading.Family{
		Name: "active_content",
		Cap:  30,
		PerSeverity: map[model.IssueSeverity]int{
			model.IssueSeverityHigh:   30,
			model.IssueSeverityMedium: 15,
		},
	}
)

var (
	// defectMalware: an engine recognised the file.
	defectMalware = &reading.Defect{Name: "malware", Family: familyMalware}

	// defectExecutableContent: the payload is a program, whatever it is called.
	defectExecutableContent = &reading.Defect{Name: "executable_content", Family: familyExecutable}

	// defectDangerousExtension: a name ending in something a recipient's system
	// would run, or written so that the ending cannot be seen.
	defectDangerousExtension = &reading.Defect{Name: "dangerous_extension", Family: familyDeceptiveName}

	// defectDoubleExtension: a document extension placed in front of the real
	// one, so the file reads as a report and opens as a program.
	defectDoubleExtension = &reading.Defect{Name: "double_extension", Family: familyDeceptiveName}

	// defectTypeMismatch: content that is not what the message or the filename
	// says it is.
	defectTypeMismatch = &reading.Defect{Name: "type_mismatch", Family: familyTypeMismatch}

	// defectMacro: an Office document carrying VBA macros.
	defectMacro = &reading.Defect{Name: "macro_detected", Family: familyMacro}

	// defectPDFActiveContent: a PDF that runs something when it is opened.
	defectPDFActiveContent = &reading.Defect{Name: "pdf_active_content", Family: familyActiveContent}

	// defectScanSkipped: something was not looked at, and the reader is told so
	// rather than left to read silence as a clean bill.
	//
	// It is what our own limits cost, not what the message did: an attachment
	// larger than the analysis will read. Charging for it would bill a sender
	// for our ceilings.
	defectScanSkipped = &reading.Defect{
		Name:      "scan_skipped",
		Uncharged: "it reports a limit of this analysis rather than a defect of the message, and a sender cannot answer for our ceilings",
	}

	// defectScanError: a scanner was asked and could not answer.
	defectScanError = &reading.Defect{
		Name:      "scan_error",
		Uncharged: "a verdict nobody reached says nothing about the file, and a service being down is not the sender's doing",
	}
)
