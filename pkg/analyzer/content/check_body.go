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

		return []reading.Finding{reading.NewFinding(
			defectTruncatedBody,
			model.IssueTypeTruncatedBody,
			model.IssueSeverityMedium,
			"",
			"The message body stops before its end: it was cut short in transit, or its MIME structure announces a part that never follows. Only the parts that arrived were analysed.",
			"Check the message size against the limits of the relays it goes through, and that the MIME boundaries it declares are all closed",
		)}, nil
	},
}

// missingPlaintextCheck reports a message carrying no plain text part: an
// HTML message without its alternative, or one carrying no readable text at
// all.
//
// It deducts nothing here: the plaintext_alternative criterion of Score
// withholds its ten points for the same absence, which this finding says.
var missingPlaintextCheck = contentCheck{
	Name:     "missing_plaintext",
	Category: reading.CategoryDeliverability,
	Reports:  []*reading.Defect{defectMissingPlaintext},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.Results.HasPlaintext() {
			return nil, nil
		}

		message := "The message carries no plain text part."
		if in.Results.HTMLContent == "" {
			// Nothing observed at all is not a message without text: there
			// is no message.
			if in.Message == nil {
				return nil, nil
			}
			message = "The message carries no readable text: neither a plain text nor an HTML part."
		}

		return []reading.Finding{reading.NewFinding(
			defectMissingPlaintext,
			model.IssueTypeMissingPlaintext,
			model.IssueSeverityMedium,
			"",
			message,
			"Send a text/plain part, generated from the HTML when there is one; clients and readers preferring text display it, and filters expect it",
		)}, nil
	},
}
