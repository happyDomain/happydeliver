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
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// Every defect is shown somewhere on purpose, not on the structure check for
// want of a place.
func TestEveryDefectIsShown(t *testing.T) {
	for _, defect := range contentDefects {
		if defect == defectRspamdObservation {
			continue
		}
		if _, ok := defectShownUnder[defect]; !ok {
			t.Errorf("defect %q is shown under no check", defect.Name)
		}
	}

	for symbol, finding := range rspamdFindingCatalog {
		if finding.Defect != nil {
			continue
		}
		if _, ok := observationShownUnder[finding.Issue]; !ok {
			t.Errorf("%s is filed as %q, which is shown under no check", symbol, finding.Issue)
		}
	}
}

func TestPlaceIssues(t *testing.T) {
	issue := func(defect *reading.Defect, issueType model.IssueType, location string) reading.Finding {
		return reading.NewFinding(defect, issueType, model.IssueSeverityMedium, location, "found", "")
	}

	links := []model.LinkCheck{
		{Url: "https://example.com/a"},
		{Url: "https://example.com/b"},
		{Url: "https://example.com/a"},
	}
	images := []model.ImageCheck{{Src: utils.PtrTo("https://example.com/logo.png")}}

	placed := placeIssues([]reading.Finding{
		issue(defectDeadLink, model.IssueTypeUnreachableLink, "https://example.com/a"),
		issue(defectSuspiciousURL, model.IssueTypeSuspiciousLink, "https://example.com/logo.png"),
		issue(defectDeadUnsubscribe, model.IssueTypeUnreachableLink, "https://example.com/unsubscribe"),
		issue(defectMissingAlt, model.IssueTypeMissingAlt, ""),
		issue(defectRspamdObservation, model.IssueTypeHiddenText, ""),
	}, links, images)

	if links[0].Issues == nil || len(*links[0].Issues) != 1 {
		t.Errorf("the dead link is not shown on its row: %+v", links[0].Issues)
	}
	if links[2].Issues != nil {
		t.Errorf("the dead link is shown again on the URL's second occurrence: %+v", *links[2].Issues)
	}
	if images[0].Issues == nil || (*images[0].Issues)[0].Type != model.IssueTypeSuspiciousLink {
		t.Errorf("the image's suspicion is not shown on its row: %+v", images[0].Issues)
	}

	if placed == nil {
		t.Fatal("nothing was placed under a check")
	}
	if placed.Links != nil {
		t.Errorf("an issue shown on its row is listed under the links again: %+v", *placed.Links)
	}
	for name, list := range map[string]*[]model.Issue{
		"unsubscribe": placed.Unsubscribe,
		"images":      placed.Images,
		"markup":      placed.Markup,
	} {
		if list == nil || len(*list) != 1 {
			t.Errorf("%s holds %v, want one issue", name, list)
		}
	}

	if all := Issues(&model.ContentAnalysis{Issues: placed, Links: &links, Images: &images}); len(all) != 5 {
		t.Errorf("Issues lists %d issues, want the 5 placed", len(all))
	}
}

// A report from before issues were listed by check keeps them in HtmlIssues,
// which Issues still reads; a new analysis no longer fills it.
func TestIssuesReadsReportsFromBeforeTheChecks(t *testing.T) {
	legacy := []model.Issue{{Type: model.IssueTypeMissingAlt}}
	if got := Issues(&model.ContentAnalysis{HtmlIssues: &legacy}); len(got) != 1 || got[0].Type != model.IssueTypeMissingAlt {
		t.Errorf("Issues = %v, want the issue of HtmlIssues", got)
	}

	if analysis := NewAnalyzer(time.Second).analysisOf(speakingResults()); analysis.HtmlIssues != nil {
		t.Errorf("a new analysis fills HtmlIssues: %v", *analysis.HtmlIssues)
	}
}

// Nothing is listed under a check when every issue is on a row. An image
// without a source holds none, and a URL that is both a link and an image
// source is shown on the link.
func TestPlaceIssuesOnRowsOnly(t *testing.T) {
	links := []model.LinkCheck{{Url: "https://example.com/a"}}
	images := []model.ImageCheck{{}, {Src: utils.PtrTo("https://example.com/a")}}
	dead := reading.NewFinding(defectDeadLink, model.IssueTypeUnreachableLink, model.IssueSeverityMedium, "https://example.com/a", "found", "")

	if placed := placeIssues([]reading.Finding{dead}, links, images); placed != nil {
		t.Errorf("placed = %+v, want nothing listed under a check", placed)
	}
	if links[0].Issues == nil || images[0].Issues != nil || images[1].Issues != nil {
		t.Errorf("the issue is not on the link alone: link %v, images %v and %v", links[0].Issues, images[0].Issues, images[1].Issues)
	}
}

// An image inlined without an alt is located by a short name rather than by
// its whole data: URI, which its row already holds, and is still shown on
// that row.
func TestMissingAltOnInlineImage(t *testing.T) {
	src := "data:image/png;base64," + strings.Repeat("iVBORw0KGgo", 100)
	in := &contentInput{Results: &Results{Images: []ImageCheck{{Src: src}}}}

	findings, err := missingAltCheck.Run(context.Background(), in)
	if err != nil || len(findings) != 1 {
		t.Fatalf("missingAltCheck = %v, %v; want one finding", findings, err)
	}
	if loc := findings[0].Location; loc == nil || *loc != shortSource(src) {
		t.Errorf("location = %v, want %q", loc, shortSource(src))
	}

	images := []model.ImageCheck{{Src: &src}}
	if placed := placeIssues(findings, nil, images); placed != nil {
		t.Errorf("placed = %+v, want the issue on the image's row", placed)
	}
	if images[0].Issues == nil || len(*images[0].Issues) != 1 {
		t.Errorf("the missing alt is not shown on the image: %v", images[0].Issues)
	}
}
