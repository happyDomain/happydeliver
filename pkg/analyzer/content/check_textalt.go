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
	"fmt"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// textAlternativeCheck reports a plain text part that does not say what the
// HTML part says.
//
// The defect was measured long before it was reported: the consistency
// criterion of Score has always withheld its fifteen points
// from a message whose parts disagree, and nothing in the report said so
// unless the receiving MTA's spam filter happened to raise R_PARTS_DIFFER. A
// sender losing a grade was left to guess why.
//
// It deducts nothing here, that criterion answering for it.
var textAlternativeCheck = contentCheck{
	Name:     "text_alternative",
	Category: reading.CategoryContent,
	Reports:  []*reading.Defect{defectTextHTMLMismatch},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		var message, advice string

		switch in.Results.TextAlternative {
		case textAltStub:
			message = "The plain text part carries a fraction of what the HTML says, rather than an alternative to it."
			advice = "Generate the text part from the HTML at send time, or send HTML alone; a text part that only announces the message is in HTML is what clients preferring text display"

		case textAltStale:
			message = "The plain text and HTML parts do not say the same thing."
			advice = "Generate the text part from the HTML at send time rather than maintaining it by hand; two parts this far apart usually mean the text of a previous campaign was left in place while the HTML was rewritten"

		default:
			// ok, absent and unknown alike. A message with no text part at all
			// is answered for by the plaintext_alternative criterion, which
			// has already said what there is to say about it; repeating it
			// here would charge the reader's attention twice for one absence.
			return nil, nil
		}

		return []reading.Finding{{
			Defect: defectTextHTMLMismatch,
			Issue: model.Issue{
				Type:     model.IssueTypeTextHtmlMismatch,
				Severity: model.IssueSeverityHigh,
				Message:  message,
				Advice:   utils.PtrTo(advice),
			},
			// A statement about the whole message, which needs no instance
			// key: rspamd's R_PARTS_DIFFER says the same of the same message,
			// and there is only ever one of each.
			Concern: "text_html_mismatch",
		}}, nil
	},
}

// textLinkParityCheck reports a destination the text part offers and the HTML
// part does not.
//
// Only that direction is looked at: the text part is the poorer of the two in
// links, so one it carries alone suggests the two parts were not generated
// together, while an HTML that links more than the text spells out is the
// ordinary shape of a mailing.
var textLinkParityCheck = contentCheck{
	Name:     "text_link_parity",
	Category: reading.CategoryContent,
	Reports:  []*reading.Defect{defectTextLinkMissing},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		// Nothing to compare against: a message without HTML has no second
		// list of destinations, and one nothing could be read off, a body that
		// stopped short first among them, may be missing the very part that
		// carried them. That is the same "nothing to compare" the level
		// already holds, so it is read there rather than judged again here.
		if in.Results.HTMLContent == "" || in.Results.TextAlternative == textAltUnknown {
			return nil, nil
		}

		var issues []reading.Finding
		for _, missing := range textLinksMissingFromHTML(in.Results.Links) {
			location := missing
			issues = append(issues, reading.Finding{
				Defect: defectTextLinkMissing,
				Issue: model.Issue{
					Type:     model.IssueTypeTextHtmlMismatch,
					Severity: model.IssueSeverityLow,
					Message:  fmt.Sprintf("The plain text part offers a destination the HTML part does not: %s", missing),
					Location: &location,
					Advice:   utils.PtrTo("Check that both parts lead to the same places; clients preferring text otherwise offer a destination the HTML does not, and filters compare the two parts"),
				},
			})
		}

		return issues, nil
	},
}
