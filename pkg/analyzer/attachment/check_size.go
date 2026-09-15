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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// sizeCheck reports an attachment the analysis did not open, because it is
// larger than it will read. It answers the deliverability reading rather than
// the security one: a large file is a sending decision, not a threat.
var sizeCheck = attachmentCheck{
	Name:     "attachment_size",
	Category: reading.CategoryDeliverability,
	Reports:  []*reading.Defect{defectScanSkipped},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		attachment := in.Attachment
		if !attachment.tooLarge(in.MaxSize) {
			return nil, nil
		}

		return []reading.Finding{reading.NewFinding(
			defectScanSkipped,
			model.IssueTypeScanSkipped,
			model.IssueSeverityInfo,
			attachment.Location,
			fmt.Sprintf("Attachment is too large to analyze (%d bytes)", attachment.Size),
			"Large attachments hurt deliverability; consider linking to a download instead",
		)}, nil
	},
}
