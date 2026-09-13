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

// missingAltCheck reports the images carrying no alt attribute, as one finding
// for the message rather than one per image: the answer is the same for all of
// them, and a message of thirty bare images would otherwise bury the rest of
// the report.
//
// It deducts nothing here: the images criterion of Score
// already awards its fifteen points in proportion to how many carry an alt.
var missingAltCheck = contentCheck{
	Name:     "missing_alt",
	Category: reading.CategoryAccessibility,
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		missing := 0
		for _, img := range in.Results.Images {
			if !img.HasAlt {
				missing++
			}
		}
		if missing == 0 {
			return nil, nil
		}

		return []reading.Finding{{ContentIssue: model.ContentIssue{
			Type:     model.ContentIssueTypeMissingAlt,
			Severity: model.ContentIssueSeverityMedium,
			Message:  fmt.Sprintf("%d image(s) missing alt attributes", missing),
			Advice:   utils.PtrTo("Add descriptive alt text to all images for better accessibility and deliverability"),
		}}}, nil
	},
}

// excessiveImagesCheck reports a message carrying far more image than text.
//
// It deducts nothing here: the image-ratio criterion of Score
// grades the same ratio on a scale of its own.
var excessiveImagesCheck = contentCheck{
	Name:     "excessive_images",
	Category: reading.CategoryDeliverability,
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.Results.ImageTextRatio <= 10.0 {
			return nil, nil
		}

		return []reading.Finding{{
			ContentIssue: model.ContentIssue{
				Type:     model.ContentIssueTypeExcessiveImages,
				Severity: model.ContentIssueSeverityMedium,
				Message:  "Email is excessively image-heavy",
				Advice:   utils.PtrTo("Reduce the number of images relative to text content"),
			},
			// A statement about the whole message, which needs no instance
			// key: rspamd's R_SUSPICIOUS_IMAGES says the same of the same
			// message, and there is only ever one of each.
			Concern: "excessive_images",
		}}, nil
	},
}

// imageSuspicionCheck reports what the shape of an image source says.
//
// Only the insecure-scheme suspicion applies to an image: the other kinds
// describe a destination a recipient may click. It shares the URL-suspicion
// cap with the links, the defect being of one nature whether it is written in
// an href or in a src.
var imageSuspicionCheck = contentCheck{
	Name:     "image_suspicion",
	Category: reading.CategorySecurity,
	Family:   familyURLSuspicion,
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		var issues []reading.Finding

		for _, img := range in.Results.Images {
			for _, suspicion := range img.Suspicions {
				location := img.Src
				issues = append(issues, reading.Finding{
					ContentIssue: model.ContentIssue{
						Type:     model.ContentIssueTypeSuspiciousLink,
						Severity: suspicion.Severity,
						Message:  suspicion.Message,
						Location: &location,
						Advice:   utils.PtrTo(suspicion.Advice),
					},
					Concern: suspicionConcern(suspicion.Kind, img.Src),
				})
			}
		}

		return issues, nil
	},
}
