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

// Package reading is the machinery a reading of a message is made of: a check
// declares what it looks for, a family bounds what a kind of defect may cost,
// and running a registry of them answers what was found and what it costs.
//
// It knows nothing of email. What a check is handed is the caller's business,
// which is why Check is written over it: the content analysis hands its checks
// the facts gathered about a message, and another reading hands its own checks
// whatever it has gathered. What they share is this: the order their findings
// are read in, and a family of defects never deciding a grade on its own.
package reading

import (
	"context"
	"log"
	"slices"

	"git.happydns.org/happyDeliver/internal/model"
)

// Finding is one thing a check found: the issue as the report will
// show it, plus the key under which it may be recognised as the same defect
// another check also found.
//
// The issue's Category is the one field a check may leave to the machinery:
// left empty, Run fills it with the category of the check that reported it,
// which is the answer for most findings. A check whose findings do not all
// answer the same reading sets it on the finding instead, and that is what is
// kept.
type Finding struct {
	model.Issue

	// Defect says what is wrong, at the grain at which it is paid for, and so
	// who pays for it: a family of penalties, a criterion of the score, or
	// nobody. It is carried by the finding rather than by the check because a
	// check may report several defects at once, priced differently: a URL
	// that does not answer costs nothing when it is a body link the links
	// criterion already grades, and costs points when it is the unsubscribe
	// address nothing else looks at.
	//
	// Every finding must carry one: a finding nobody prices is a defect
	// reported for free, which the registry's own tests refuse.
	Defect *Defect

	// Concern names the defect, not the observation. Two findings sharing a
	// concern describe the same thing about the same object, so only the first
	// is reported and the others are named in its corroborated_by.
	//
	// It is empty by default, and empty means never merged. That is the safe
	// default: showing one defect twice is untidy, while merging two distinct
	// defects loses one of them. A key is therefore declared only where the
	// two producers can be counted on to agree on it, which for anything
	// scoped to a URL means agreeing on the URL itself.
	Concern string
}

// Category says which reading of a message a check answers, and so which of
// happyDeliver's readers it is addressed to: the newsletter editor before a
// send, the developer of a transactional message, the analyst looking at a
// message that arrived.
//
// It is declared per check rather than derived from the issue type, because
// the same type serves several readings: a suspicious link is a security
// finding, a link nobody can reach is a deliverability one.
//
// It travels to the report on every issue, which is what lets a reader take
// the findings by the reading they answer rather than in the order the checks
// happened to run. It is therefore an alias of the schema's own type rather
// than a second vocabulary kept in step with it by hand.
type Category = model.IssueCategory

const (
	// CategoryContent answers for what the message says and whether it says it
	// coherently: a merge field never substituted, a text alternative that does
	// not match its HTML.
	CategoryContent = model.IssueCategoryContent

	// CategoryDeliverability answers for what will keep the message out of the
	// inbox: what filters read, what reputation follows.
	CategoryDeliverability = model.IssueCategoryDeliverability

	// CategoryAccessibility answers for the recipients a message can leave out.
	CategoryAccessibility = model.IssueCategoryAccessibility

	// CategoryRendering answers for what an email client will not render as the
	// sender saw it.
	CategoryRendering = model.IssueCategoryRendering

	// CategorySecurity answers for what a message may do to whoever opens it.
	CategorySecurity = model.IssueCategorySecurity
)

// Check[In] is what a check file exposes. It is a value rather than an
// interface: a new check has nothing to implement, only to declare.
type Check[In any] struct {
	// Name identifies the check in the tests and in the pipeline's own logs.
	// It is never shown to a reader of the report.
	Name string

	// Reports is every defect this check may name. What each of them costs is
	// the defect's business, not the check's: most cost nothing here, their
	// price being already borne by one of the weighted criteria the reading is graded on.
	//
	// It is declared so that the vocabulary can be read without running
	// anything, which is how a registry can be held to
	// charging for a defect once, and a check to reporting only what it says
	// it may.
	Reports []*Defect

	// Category says which reading of the message this check answers, and so
	// which reader it is addressed to.
	Category Category

	// Run reports what the check found, in the order it is to be read.
	//
	// The context bounds it: a check is free to fetch a URL, ask a scanner
	// about an attachment or a resolver about a domain, and must stop when the
	// analysis will not wait any longer.
	//
	// An error means the check could not reach a verdict. It is written to the
	// log and its findings are dropped, the rest of the report standing: the
	// analysis of a message is not lost because one service was down. A caveat
	// the *reader* must see is not an error but a finding, which is how a check
	// says "I could not verify this" in the report.
	Run func(ctx context.Context, in In) ([]Finding, error)
}

// Family groups the defects that answer for the same kind of thing, and
// bounds together what they may cost.
//
// The cap is what keeps one family from deciding the grade on its own: a
// message whose links are at once deceptive and dead has two independent
// defects and answers for each, but neither alone can sink the content score.
type Family struct {
	// Name identifies the family in the tests.
	Name string

	// Cap bounds what the whole family may deduct, however many findings it
	// produced.
	Cap int

	// PerItem is what one finding costs. Zero weighs each finding by its
	// severity instead, which is the usual case: a family charges a flat rate
	// only when its findings are of one kind and of one gravity.
	PerItem int

	// PerSeverity is what one finding costs at each severity, for families
	// whose gaps between gravities are wider than SeverityPenalty spreads. A
	// severity the map does not name costs nothing. Nil falls back to PerItem,
	// and then to SeverityPenalty.
	PerSeverity map[model.IssueSeverity]int
}

// Defect names one thing that can be wrong with a message, at the
// grain at which it is paid for.
//
// It is not the issue type, which says how the report files a finding: three
// distinct defects are filed under unreachable_link (a dead link, a dead
// image, a dead unsubscribe address) and they are not paid for by the same
// party. Nor is it the check, which may report several defects at once.
//
// Every defect names its payer, because the score is the sum of two answers
// that must never overlap: what the weighted criteria of the reading already charge for, and what the checks deduct on top. A defect charged twice costs
// the sender a grade for one mistake, silently, which is what
// the registry's own tests exist to prevent.
type Defect struct {
	// Name identifies the defect in the tests and in the registries below. It
	// is never shown to a reader of the report.
	Name string

	// Family is the pot this defect's findings deduct from, and the cap they
	// share with the other defects of the same family.
	//
	// A nil Family means nothing is deducted here: either a criterion already
	// charges for it, and says so in its Answers, or nobody does, which
	// Uncharged spells out. Those are the only two ways, and the tests hold
	// the vocabulary to them.
	Family *Family

	// Uncharged says why this defect costs nothing on purpose. It is written
	// out rather than left to a nil Family, so that "nobody charges for this,
	// and here is why" cannot be read as "nobody got around to it".
	Uncharged string
}

// SeverityPenalty is what one finding costs when its family weighs findings by
// gravity rather than at a flat rate.
func SeverityPenalty(severity model.IssueSeverity) int {
	switch severity {
	case model.IssueSeverityCritical, model.IssueSeverityHigh:
		return 3
	case model.IssueSeverityMedium:
		return 2
	default:
		return 1
	}
}

// Evaluation is what the checks found about one message: the findings
// the report shows, and what they cost the content score.
//
// The two are produced together because they answer the same question, and
// kept together because the message is only looked at once. Asking the checks
// again for the score would be wasted work today, and unaffordable tomorrow: a
// check that fetches a URL or hands a file to a scanner cannot be asked to
// answer twice for one message.
type Evaluation struct {
	// Issues is what the report shows, in the order the checks were run.
	Issues []model.Issue

	// Penalty is what those findings deduct from the score, each
	// family already capped.
	Penalty int
}

// saysTheSame answers whether two findings of one concern are the same
// observation reported twice, rather than two observations of one kind of
// defect. What a reader would see is the whole answer: findings reading alike
// in the same place are the same finding.
func saysTheSame(a, b Finding) bool {
	if a.Message != b.Message {
		return false
	}

	if a.Location == nil || b.Location == nil {
		return a.Location == b.Location
	}

	return *a.Location == *b.Location
}

// Run runs the given checks and returns what they found, in
// their order, together with what it costs the content score.
//
// The order is part of the report: it puts what qualifies the rest of the
// analysis first, and the remarks that only inform last. Callers hand it
// contentChecks; the tests hand it checks of their own.
//
// Findings describing the same defect are merged before anything is charged,
// so that a defect two checks both saw is reported once and paid for once.
func Run[In any](ctx context.Context, checks []Check[In], in In) (issues []model.Issue, penalty int) {
	type observed struct {
		finding Finding
		// source names this observer in another finding's corroborated_by. It
		// is the rspamd symbol when there is one, and the check's name
		// otherwise.
		source string
	}

	var found []observed
	for _, check := range checks {
		reported, err := check.Run(ctx, in)
		if err != nil {
			// The check reached no verdict. Saying nothing about it in the
			// report is the honest answer: a finding would state a defect
			// nobody observed.
			log.Printf("check %q could not complete: %v", check.Name, err)
			continue
		}

		for _, finding := range reported {
			source := check.Name
			if finding.Symbol != nil {
				source = *finding.Symbol
			}
			// A finding that named no category answers the reading its check
			// does. This is settled before the merge below, so that the
			// category travels with the finding that is kept rather than
			// depending on which check happened to report it first.
			if finding.Category == "" {
				finding.Category = check.Category
			}

			found = append(found, observed{finding: finding, source: source})
		}
	}

	// The first finding of a concern is the one kept, which is why the
	// registry lists our own checks before the spam filter's: what happyDeliver
	// read for itself carries a location and advice of its own, and the
	// filter's agreement is worth noting on it rather than repeating beside it.
	keptByConcern := make(map[string]int, len(found))
	kept := make([]observed, 0, len(found))

	for _, o := range found {
		if o.finding.Concern == "" {
			kept = append(kept, o)
			continue
		}

		if at, seen := keptByConcern[o.finding.Concern]; seen {
			// An observer agreeing with itself is a duplicate, not a
			// corroboration: the same URL written twice in a message draws the
			// same suspicion twice, and "also reported by" our own check would
			// be a strange thing to read. Such a finding is simply dropped.
			//
			// It only says the same thing when it reads the same, though: a
			// check that names one concern for a whole class of defect, as the
			// contrast reading does for every unreadable colour pair it finds,
			// reports each of them separately and each is worth keeping.
			if o.source == kept[at].source {
				if saysTheSame(o.finding, kept[at].finding) {
					continue
				}

				kept = append(kept, o)
				continue
			}

			corroborated := []string{}
			if existing := kept[at].finding.CorroboratedBy; existing != nil {
				corroborated = *existing
			}
			if !slices.Contains(corroborated, o.source) {
				corroborated = append(corroborated, o.source)
			}
			kept[at].finding.CorroboratedBy = &corroborated
			continue
		}

		keptByConcern[o.finding.Concern] = len(kept)
		kept = append(kept, o)
	}

	// Each family is totalled before being capped: the cap belongs to the
	// family, not to the defect, so that two defects sharing one may not
	// deduct twice its bound between them.
	perFamily := make(map[*Family]int, len(checks))

	issues = make([]model.Issue, 0, len(kept))
	for _, o := range kept {
		issues = append(issues, o.finding.Issue)

		// What a finding costs is its defect's business: a check reporting a
		// dead link and a dead unsubscribe address answers for them
		// differently, the first being already paid for by a criterion.
		if o.finding.Defect == nil || o.finding.Defect.Family == nil {
			continue
		}

		family := o.finding.Defect.Family
		switch {
		case family.PerSeverity != nil:
			perFamily[family] += family.PerSeverity[o.finding.Severity]
		case family.PerItem > 0:
			perFamily[family] += family.PerItem
		default:
			perFamily[family] += SeverityPenalty(o.finding.Severity)
		}
	}

	for family, total := range perFamily {
		penalty += min(total, family.Cap)
	}

	return issues, penalty
}
