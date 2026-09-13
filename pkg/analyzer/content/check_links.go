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

// templatePlaceholderCheck reports a link whose URL still carries a merge
// field, which means the send went out before the field was substituted.
//
// It deducts nothing here: such a URL designates no destination, so it is
// counted as a broken link by the links criterion of Score.
var templatePlaceholderCheck = contentCheck{
	Name:     "unreplaced_template",
	Category: reading.CategoryContent,
	Run: func(_ context.Context, in *contentInput) ([]model.ContentIssue, error) {
		var issues []model.ContentIssue

		for _, link := range in.Results.Links {
			if !link.IsTemplate {
				continue
			}

			location := link.URL
			issues = append(issues, model.ContentIssue{
				Type:     model.ContentIssueTypeUnreplacedTemplate,
				Severity: model.ContentIssueSeverityHigh,
				Message:  fmt.Sprintf("Link contains an unreplaced template placeholder: %s", link.URL),
				Location: &location,
				Advice:   utils.PtrTo("Ensure all merge fields and template placeholders are substituted before sending"),
			})
		}

		return issues, nil
	},
}

// linkSuspicionCheck reports what the shape of a destination says, before
// anything is fetched: a public shortener, a user field, an obfuscated host.
var linkSuspicionCheck = contentCheck{
	Name:     "link_suspicion",
	Category: reading.CategorySecurity,
	Family:   familyURLSuspicion,
	Run: func(_ context.Context, in *contentInput) ([]model.ContentIssue, error) {
		var issues []model.ContentIssue

		for _, link := range in.Results.Links {
			for _, suspicion := range link.Suspicions {
				issues = append(issues, model.ContentIssue{
					Type:     model.ContentIssueTypeSuspiciousLink,
					Severity: suspicion.Severity,
					Message:  suspicion.Message,
					Location: &link.URL,
					Advice:   utils.PtrTo(suspicion.Advice),
				})
			}
		}

		return issues, nil
	},
}

// probeFindingCheck reports what fetching the URLs revealed, for links, image
// sources and the addresses of the List-Unsubscribe header alike. Each
// distinct URL is reported once, however many times the message writes it.
//
// It answers under a cap of its own rather than the URL-suspicion one: a
// message whose links are at once deceptive and dead has two independent
// defects, and answers for each.
var probeFindingCheck = contentCheck{
	Name:     "probe_finding",
	Category: reading.CategoryDeliverability,
	Family:   familyHTTPProbe,
	Run: func(_ context.Context, in *contentInput) ([]model.ContentIssue, error) {
		var issues []model.ContentIssue

		for _, probed := range in.Results.probedURLs() {
			issues = append(issues, httpFindingIssues(probed.Location, probed.HTTPFindings)...)
		}

		return issues, nil
	},
}

// unprobedURLsCheck says what was left unfetched, so that the URLs reported
// above are not read as the whole of what the message carries.
//
// It deducts nothing: it describes a limit of the analysis, not a defect of
// the message. The advice it carries is the only part addressed to the sender.
var unprobedURLsCheck = contentCheck{
	Name:     "unprobed_urls",
	Category: reading.CategoryDeliverability,
	Run: func(_ context.Context, in *contentInput) ([]model.ContentIssue, error) {
		if in.Results.UnprobedURLs <= 0 {
			return nil, nil
		}

		return []model.ContentIssue{{
			Type:     model.ContentIssueTypeUnreachableLink,
			Severity: model.ContentIssueSeverityInfo,
			Message:  fmt.Sprintf("The message carries more distinct URLs than one analysis fetches: %d of them were left unchecked", in.Results.UnprobedURLs),
			Advice:   utils.PtrTo("Cut the number of distinct destinations down; a message with hundreds of them is harder to check, for this report and for the filters that do the same"),
		}}, nil
	},
}
