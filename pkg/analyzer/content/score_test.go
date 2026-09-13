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
	"fmt"
	"testing"
	"time"
)

// TestAURLThatNamesNoDestinationCountsAsBroken covers a link the criterion
// used to count among the working ones.
//
// A link left with an unsubstituted merge field is never fetched: there is
// nothing to fetch, so it carries no status code, and a criterion reading
// status codes alone reads it as fine. The check that names such a link
// deducts nothing, on the grounds that this criterion answers for it: this is
// that criterion doing so.
func TestAURLThatNamesNoDestinationCountsAsBroken(t *testing.T) {
	analyzer := NewAnalyzer(time.Second)

	links := func(second LinkCheck) *Results {
		return &Results{
			HTMLValid:       true,
			TextContent:     "Newsletter",
			TextAlternative: textAltOK,
			Links: []LinkCheck{
				{URL: "https://example.com/a", Valid: true, IsSafe: true, probedURL: probedURL{Status: 200}},
				second,
			},
		}
	}

	working, _ := analyzer.scoreOf(links(
		LinkCheck{URL: "https://example.com/b", Valid: true, IsSafe: true, probedURL: probedURL{Status: 200}},
	))
	templated, _ := analyzer.scoreOf(links(
		LinkCheck{URL: "https://example.com/{{UNSUB}}", IsTemplate: true, IsSafe: true},
	))

	if templated >= working {
		t.Errorf("a link still carrying a merge field scored %d, as much as a working one (%d)", templated, working)
	}
}

// TestAnImageThatDoesNotLoadCostsTheImagesCriterion covers the other half of
// what this criterion is for: an image nobody sees is as lost to the reader as
// one nothing is said about, and IsBroken, which the probe fills in, was read
// by nobody.
func TestAnImageThatDoesNotLoadCostsTheImagesCriterion(t *testing.T) {
	analyzer := NewAnalyzer(time.Second)

	images := func(second ImageCheck) *Results {
		return &Results{
			HTMLValid:       true,
			TextContent:     "Newsletter",
			TextAlternative: textAltOK,
			Images: []ImageCheck{
				{Src: "https://example.com/a.png", HasAlt: true, AltText: "a"},
				second,
			},
		}
	}

	loading, _ := analyzer.scoreOf(images(
		ImageCheck{Src: "https://example.com/b.png", HasAlt: true, AltText: "b"},
	))
	dead, _ := analyzer.scoreOf(images(
		ImageCheck{Src: "https://example.com/b.png", HasAlt: true, AltText: "b", IsBroken: true},
	))

	if dead >= loading {
		t.Errorf("an image that does not load scored %d, as much as one that does (%d)", dead, loading)
	}
}

// TestAMessageMostlyMadeOfLinksEarnsLess: past thirty links, a message is
// mostly destinations, and the links criterion says so.
func TestAMessageMostlyMadeOfLinksEarnsLess(t *testing.T) {
	analyzer := NewAnalyzer(time.Second)

	results := func(count int) *Results {
		links := make([]LinkCheck, 0, count)
		for i := range count {
			links = append(links, LinkCheck{URL: fmt.Sprintf("https://example.com/%d", i), Valid: true, IsSafe: true, probedURL: probedURL{Status: 200}})
		}
		return &Results{HTMLValid: true, TextContent: "Newsletter", TextAlternative: textAltOK, Links: links}
	}

	few, _ := analyzer.scoreOf(results(30))
	many, _ := analyzer.scoreOf(results(31))

	if many >= few {
		t.Errorf("a message of 31 links scored %d, as much as one of 30 (%d)", many, few)
	}
}

// TestImagesDrowningTheTextCostTheRatioCriterion pins the three steps of the
// image-to-text ratio: fine, heavy, and mostly pictures.
func TestImagesDrowningTheTextCostTheRatioCriterion(t *testing.T) {
	analyzer := NewAnalyzer(time.Second)

	scoreAt := func(ratio float32) int {
		score, _ := analyzer.scoreOf(&Results{HTMLValid: true, TextContent: "Newsletter", TextAlternative: textAltOK, ImageTextRatio: ratio})
		return score
	}

	fine, heavy, pictures := scoreAt(5), scoreAt(10), scoreAt(20)
	if !(fine > heavy && heavy > pictures) {
		t.Errorf("the ratio criterion scored %d, %d and %d for ratios of 5, 10 and 20, want each step below the last", fine, heavy, pictures)
	}
}
