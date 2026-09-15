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

	"git.happydns.org/happyDeliver/pkg/reading"
)

// archiveCheck looks inside an archive, and reports what it finds there as it
// would report an attachment: a member of a zip is a file the recipient will
// open, and the only thing between it and them is a double click.
//
// It therefore reports the whole static vocabulary, plus what is particular to
// archives: one that is locked, one nested inside another, one that expands
// out of proportion, and what the extraction budget kept it from reaching.
var archiveCheck = attachmentCheck{
	Name:     "attachment_archive",
	Category: reading.CategorySecurity,
	Reports: []*reading.Defect{
		defectDangerousExtension,
		defectDoubleExtension,
		defectTypeMismatch,
		defectExecutableContent,
		defectMacro,
		defectPDFActiveContent,
		defectScriptContent,
		defectPasswordProtected,
		defectNestedArchive,
		defectArchiveBomb,
		defectScanSkipped,
	},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		return inspectArchive(in.Attachment.Data, in.Attachment.Location, 0, nil), nil
	},
}
