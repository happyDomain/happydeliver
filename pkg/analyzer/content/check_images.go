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

// missingAltCheck reports each image carrying no alt attribute, on the row of
// that image.
//
// It deducts nothing here: the images criterion of Score
// already awards its fifteen points in proportion to how many carry an alt.
var missingAltCheck = contentCheck{
	Name:     "missing_alt",
	Category: reading.CategoryAccessibility,
	Reports:  []*reading.Defect{defectMissingAlt},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		var issues []reading.Finding

		for _, img := range in.Results.VisibleImages() {
			if img.HasAlt {
				continue
			}

			found := reading.NewFinding(
				defectMissingAlt,
				model.IssueTypeMissingAlt,
				model.IssueSeverityMedium,
				shortSource(img.Src),
				"The image carries no alt attribute: a recipient who cannot see it is told nothing of it.",
				"Add an alt text saying what the image shows, or an empty one (alt=\"\") for a decoration",
			)
			// Placed by its full source, the location only quoting it: a
			// data: URI would otherwise be copied whole into the issue, when
			// the image row already holds it.
			found.Subject = img.Src

			issues = append(issues, found)
		}

		return issues, nil
	},
}

// excessiveImagesCheck reports a message carrying far more image than text.
//
// It deducts nothing here: the image-ratio criterion of Score
// grades the same ratio on a scale of its own.
var excessiveImagesCheck = contentCheck{
	Name:     "excessive_images",
	Category: reading.CategoryDeliverability,
	Reports:  []*reading.Defect{defectExcessiveImages},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.Results.ImageTextRatio <= 5.0 {
			return nil, nil
		}

		severity, message := model.IssueSeverityLow, "Email carries much image for its text"
		if in.Results.ImageTextRatio > 10.0 {
			severity, message = model.IssueSeverityMedium, "Email is excessively image-heavy"
		}

		found := reading.NewFinding(
			defectExcessiveImages,
			model.IssueTypeExcessiveImages,
			severity,
			"",
			message,
			"Reduce the number of images relative to text content",
		)
		// A statement about the whole message, which needs no instance key:
		// rspamd's R_SUSPICIOUS_IMAGES says the same of the same message, and
		// there is only ever one of each.
		found.Concern = "excessive_images"

		return []reading.Finding{found}, nil
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
	Reports:  []*reading.Defect{defectSuspiciousURL},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		var issues []reading.Finding

		for _, img := range in.Results.Images {
			for _, suspicion := range img.Suspicions {
				found := reading.NewFinding(
					defectSuspiciousURL,
					model.IssueTypeSuspiciousLink,
					suspicion.Severity,
					img.Src,
					suspicion.Message,
					suspicion.Advice,
				)
				found.Concern = suspicionConcern(suspicion.Kind, img.Src)

				issues = append(issues, found)
			}
		}

		return issues, nil
	},
}
