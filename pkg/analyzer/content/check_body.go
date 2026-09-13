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

package content

import (
	"context"
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// truncatedBodyCheck reports a body that stopped before its end.
//
// It deducts nothing: the criteria such a body cannot answer are withdrawn
// from the score's denominator rather than failed (see Score),
// which is a heavier and fairer answer than a penalty. What is missing from
// the parts that arrived says nothing about the message that was sent.
var truncatedBodyCheck = contentCheck{
	Name:     "truncated_body",
	Category: reading.CategoryDeliverability,
	Reports:  []*reading.Defect{defectTruncatedBody},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if !in.Results.BodyTruncated {
			return nil, nil
		}

		return []reading.Finding{{Defect: defectTruncatedBody, ContentIssue: model.ContentIssue{
			Type:     model.ContentIssueTypeTruncatedBody,
			Severity: model.ContentIssueSeverityMedium,
			Message:  "The message body stops before its end: it was cut short in transit, or its MIME structure announces a part that never follows. Only the parts that arrived were analysed.",
			Advice:   utils.PtrTo("Check the message size against the limits of the relays it goes through, and that the MIME boundaries it declares are all closed"),
		}}}, nil
	},
}
