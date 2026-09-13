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
	"git.happydns.org/happyDeliver/pkg/reading"

	"git.happydns.org/happyDeliver/pkg/grade"
)

// contentCriterion is one of the things the content score weighs. The checks
// say what is wrong with a message; the criteria say what a good one is made
// of, which is a different question and deserves its own list.
//
// A criterion owns its weight, so the scale is read here rather than
// reconstructed from a run of additions, and a criterion the received bytes
// cannot answer is withdrawn from the scale rather than failed: a body cut
// short in transit costs the sender nothing it did not do.
type contentCriterion struct {
	// Name identifies the criterion in the tests, and is what the report will
	// show beside its points the day the score is broken down for the reader.
	Name string

	// Weight is what a flawless message earns here, and what leaves the scale
	// when the criterion cannot be judged.
	Weight int

	// Answers names the defects this criterion already charges for, by
	// withholding points a flawless message would have earned. A check is free
	// to report them (naming a defect is its job) but none of them may carry
	// a penalty family on top, which TestEveryDefectIsPricedOnce holds the
	// vocabulary to.
	Answers []*reading.Defect

	// Points is what this message earns of Weight, and whether the criterion
	// could be judged at all. Points above Weight are not expected; points
	// below zero are, a criterion being free to charge for what it weighs.
	Points func(*contentInput) (points int, applicable bool)
}

// contentCriteria is what the content score is made of. Their weights sum to a
// hundred, which TestContentCriteriaSumToTheScale holds them to: the score is
// expressed on that scale, and the penalties the checks deduct are expressed
// in points of it.
//
// A defect already answered for here is not to be charged again on top. That
// is why most defects carry no penalty family: a missing alt attribute is
// answered for by the images criterion, a dead link by the links one. Each
// criterion names what it answers for in its Answers, so that the rule is read
// off the two registries rather than trusted to a comment.
var contentCriteria = []contentCriterion{
	{
		// Every message starts with ten points. It is named here rather than
		// hidden in the sum so that the scale adds up to what it claims.
		Name:   "baseline",
		Weight: 10,
		Points: func(*contentInput) (int, bool) { return 10, true },
	},
	{
		// HTML that parses, or a message that is plain text and says so.
		Name:    "html_validity",
		Weight:  10,
		Answers: []*reading.Defect{defectBrokenHTML},
		Points: func(in *contentInput) (int, bool) {
			if in.Results.HTMLValid || (!in.Results.IsMultipart && in.Results.HasPlaintext()) {
				return 10, true
			}
			return 0, true
		},
	},
	{
		// A plain text alternative, for the clients and the readers that want
		// one.
		Name:   "plaintext_alternative",
		Weight: 10,
		Points: func(in *contentInput) (int, bool) {
			if in.Results.HasPlaintext() {
				return 10, true
			}
			return 0, true
		},
	},
	{
		// Links that lead somewhere (a destination that answers, and a URL
		// that designates one at all) and not so many of them that the
		// message is mostly destinations.
		Name:    "links",
		Weight:  25,
		Answers: []*reading.Defect{defectDeadLink, defectUnreplacedTemplate},
		Points: func(in *contentInput) (int, bool) {
			if len(in.Results.Links) == 0 {
				// A truncated body earns no credit for links it does not
				// appear to have: that would reward an absence of evidence,
				// not an absence of links. The criterion leaves the scale
				// instead.
				if in.Results.BodyTruncated {
					return 0, false
				}
				// No link at all is the safest a message can be.
				return 25, true
			}

			broken := 0
			for _, link := range in.Results.Links {
				// A link whose redirections never end is as dead as one
				// answering 404, though it carries no status code of its own.
				// So is one that was never fetchable in the first place: a URL
				// left with an unsubstituted merge field, or one that does not
				// parse, designates no destination at all.
				if !link.Valid || link.Status >= 400 || link.hasFinding(LinkHTTPRedirectLoop) {
					broken++
				}
			}

			points := 20 * (len(in.Results.Links) - broken) / len(in.Results.Links)
			if len(in.Results.Links) > 30 {
				points -= 10
			}

			return points, true
		},
	},
	{
		// Images that reach the recipient: they load, and the one who cannot
		// see them is told what they showed.
		Name:    "images",
		Weight:  15,
		Answers: []*reading.Defect{defectMissingAlt, defectDeadImage},
		Points: func(in *contentInput) (int, bool) {
			if len(in.Results.Images) == 0 {
				// Same caveat as the links above.
				if in.Results.BodyTruncated {
					return 0, false
				}
				return 15, true
			}

			// An image earns its share when the recipient gets something out
			// of it: it loads, or it says what it would have shown. One that
			// does neither is a hole in the message, whether the client blocks
			// it or the server never answered.
			lost := 0
			for _, img := range in.Results.Images {
				if !img.HasAlt || img.IsBroken {
					lost++
				}
			}

			return 15 * (len(in.Results.Images) - lost) / len(in.Results.Images), true
		},
	},
	{
		// A plain text part that says what the HTML says. A truncated body
		// cannot be judged on it: the counterpart may simply never have
		// arrived.
		Name:    "text_consistency",
		Weight:  15,
		Answers: []*reading.Defect{defectTextHTMLMismatch},
		Points: func(in *contentInput) (int, bool) {
			if in.Results.BodyTruncated {
				return 0, false
			}
			if in.Results.TextPlainRatio >= 0.3 {
				return 15, true
			}
			return 0, true
		},
	},
	{
		// Text a filter can read, rather than a message that is one big image.
		Name:    "image_ratio",
		Weight:  15,
		Answers: []*reading.Defect{defectExcessiveImages},
		Points: func(in *contentInput) (int, bool) {
			switch {
			case in.Results.ImageTextRatio <= 5.0:
				return 15, true
			case in.Results.ImageTextRatio <= 10.0:
				return 7, true
			default:
				return 0, true
			}
		},
	},
}

// Score grades the content of a message out of a hundred.
//
// It awards what the criteria say the message is worth, brings what could be
// judged back onto the full scale, then deducts what the checks found. The two
// halves answer different questions and are kept apart: what a good message is
// made of, and what is wrong with this one.
func (c *Analyzer) Score(results *Results, read Reading) (int, string) {
	if results == nil {
		return 0, ""
	}

	in := results.checkInput()

	score := 0
	// The points a flawless message can reach. A criterion the received bytes
	// cannot answer is subtracted from it instead of being refused.
	attainable := 0

	for _, criterion := range contentCriteria {
		points, applicable := criterion.Points(in)
		if !applicable {
			continue
		}
		attainable += criterion.Weight
		score += points
	}

	if attainable > 0 && attainable != 100 {
		score = score * 100 / attainable
	}

	// Answer for what the checks found. Each family of findings is capped on
	// its own, so that a message with two unrelated defects answers for both
	// without either deciding the grade by itself.
	score -= read.Penalty

	score = min(max(score, 0), 100)

	return score, grade.Of(score)
}
