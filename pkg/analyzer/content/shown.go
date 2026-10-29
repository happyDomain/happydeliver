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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// shownUnder is the check of the report an issue is shown on, one of the
// lists of model.ContentIssues.
//
// It is what the issue is about, which is neither the reader it is addressed
// to (its category) nor what it costs (its defect's family): a dead link, a
// suspicious one and a merge field left in a URL are three readings of the
// message, and all three are about its links.
type shownUnder int

const (
	shownStructure shownUnder = iota
	shownTextAlternative
	shownLinks
	shownImages
	shownUnsubscribe
	shownRendering
	shownMarkup
	shownAttachments
)

// defectShownUnder places each defect of the vocabulary. The tests hold every
// defect of contentDefects to having a place.
var defectShownUnder = map[*reading.Defect]shownUnder{
	defectTruncatedBody:      shownStructure,
	defectBrokenHTML:         shownStructure,
	defectTextHTMLMismatch:   shownTextAlternative,
	defectTextLinkMissing:    shownTextAlternative,
	defectUnreplacedTemplate: shownLinks,
	defectSuspiciousURL:      shownLinks,
	defectDeadLink:           shownLinks,
	defectExcessiveLinks:     shownLinks,
	defectRedirectChain:      shownLinks,
	defectOffDomainLinks:     shownLinks,
	defectUnprobedURLs:       shownLinks,
	defectMissingAlt:         shownImages,
	defectExcessiveImages:    shownImages,
	defectDeadImage:          shownImages,
	defectDeadUnsubscribe:    shownUnsubscribe,
	defectHTMLRemark:         shownRendering,
	defectClientCompat:       shownRendering,
	defectLowContrast:        shownRendering,
	defectDangerousHTML:      shownMarkup,
	defectEventHandler:       shownMarkup,
}

// observationShownUnder places what the spam filter observed and no defect of
// ours names, by the type the catalogue files it under: one defect answers
// for all of them, and they are about everything a message is made of. The
// tests hold every type of rspamdFindingCatalog to having a place.
var observationShownUnder = map[model.IssueType]shownUnder{
	model.IssueTypeHiddenText:       shownMarkup,
	model.IssueTypeObfuscatedUrl:    shownLinks,
	model.IssueTypeHomographUrl:     shownLinks,
	model.IssueTypeLinkReputation:   shownLinks,
	model.IssueTypeSuspiciousLink:   shownLinks,
	model.IssueTypeImageOnlyContent: shownImages,
	model.IssueTypeExcessiveImages:  shownImages,
	model.IssueTypeTextHtmlMismatch: shownTextAlternative,
	model.IssueTypeClientCompat:     shownRendering,
	model.IssueTypeAttachmentRisk:   shownAttachments,
}

// shownUnderOf is where a finding is shown when it is about no link or image
// of the message. One nothing places is shown with the structure of the
// message, which is where a reader looks first, rather than dropped.
func shownUnderOf(finding reading.Finding) shownUnder {
	if finding.Defect == defectRspamdObservation {
		if shown, ok := observationShownUnder[finding.Type]; ok {
			return shown
		}
	} else if shown, ok := defectShownUnder[finding.Defect]; ok {
		return shown
	}

	return shownStructure
}

// placeIssues shows each finding where it belongs: on the link or the image
// it is about, when it is located at the URL of one of them, and otherwise
// under the check of its defect.
//
// A URL written several times is shown once with its issues, on its first
// occurrence: the issue is about the URL, and repeating it on every row would
// count it, and what it costs, as many times.
func placeIssues(findings []reading.Finding, links []model.LinkCheck, images []model.ImageCheck) *model.ContentIssues {
	linkAt := make(map[string]int, len(links))
	for i, link := range links {
		if _, seen := linkAt[link.Url]; !seen {
			linkAt[link.Url] = i
		}
	}
	imageAt := make(map[string]int, len(images))
	for i, image := range images {
		if image.Src == nil {
			continue
		}
		if _, seen := imageAt[*image.Src]; !seen {
			imageAt[*image.Src] = i
		}
	}

	byCheck := make(map[shownUnder][]model.Issue)
	for _, finding := range findings {
		if finding.Location != nil {
			if i, ok := linkAt[*finding.Location]; ok {
				links[i].Issues = appendIssue(links[i].Issues, finding.Issue)
				continue
			}
			if i, ok := imageAt[*finding.Location]; ok {
				images[i].Issues = appendIssue(images[i].Issues, finding.Issue)
				continue
			}
		}

		shown := shownUnderOf(finding)
		byCheck[shown] = append(byCheck[shown], finding.Issue)
	}

	if len(byCheck) == 0 {
		return nil
	}

	listed := func(shown shownUnder) *[]model.Issue {
		if issues := byCheck[shown]; len(issues) > 0 {
			return &issues
		}
		return nil
	}

	return &model.ContentIssues{
		Structure:       listed(shownStructure),
		TextAlternative: listed(shownTextAlternative),
		Links:           listed(shownLinks),
		Images:          listed(shownImages),
		Unsubscribe:     listed(shownUnsubscribe),
		Rendering:       listed(shownRendering),
		Markup:          listed(shownMarkup),
		Attachments:     listed(shownAttachments),
	}
}

func appendIssue(issues *[]model.Issue, issue model.Issue) *[]model.Issue {
	if issues == nil {
		return &[]model.Issue{issue}
	}

	*issues = append(*issues, issue)
	return issues
}

// Issues is every issue of a content analysis, those of the checks first in
// the order of ContentIssues, then those of the links and of the images. A
// report from before issues were listed by check has them all in HtmlIssues.
func Issues(analysis *model.ContentAnalysis) []model.Issue {
	if analysis == nil {
		return nil
	}

	var all []model.Issue
	if analysis.HtmlIssues != nil {
		all = append(all, *analysis.HtmlIssues...)
	}
	if checks := analysis.Issues; checks != nil {
		for _, list := range []*[]model.Issue{
			checks.Structure, checks.TextAlternative, checks.Links, checks.Images,
			checks.Unsubscribe, checks.Rendering, checks.Markup, checks.Attachments,
		} {
			if list != nil {
				all = append(all, *list...)
			}
		}
	}
	if analysis.Links != nil {
		for _, link := range *analysis.Links {
			if link.Issues != nil {
				all = append(all, *link.Issues...)
			}
		}
	}
	if analysis.Images != nil {
		for _, image := range *analysis.Images {
			if image.Issues != nil {
				all = append(all, *image.Issues...)
			}
		}
	}

	return all
}
