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

// Package reputation converts the checker-blacklist aggregation output into the
// API model and derives a deliverability-style score/grade from it. It keeps
// the checker-blacklist and grading dependencies out of the HTTP layer.
package reputation

import (
	"encoding/json"
	"maps"
	"slices"

	blacklist "git.happydns.org/checker-blacklist/checker"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/grade"
)

// FromObservation turns a checker-blacklist observation payload into a
// DomainBlacklistResult. It returns nil when the payload is missing or of an
// unexpected type, so callers can degrade gracefully.
func FromObservation(raw interface{}) *model.DomainBlacklistResult {
	data := dataOf(raw)
	if data == nil {
		return nil
	}
	return buildResult(data)
}

// dataOf reads a checker-blacklist observation payload, or nil when it is
// missing or of an unexpected type.
func dataOf(raw any) *blacklist.BlacklistData {
	data, _ := raw.(*blacklist.BlacklistData)
	return data
}

func buildResult(data *blacklist.BlacklistData) *model.DomainBlacklistResult {
	// A source the instance does not run has nothing to say about the
	// domain: it is left out of the results altogether.
	results := make([]model.DomainBlacklistSourceResult, 0, len(data.Results))
	for _, r := range data.Results {
		if r.Enabled {
			results = append(results, toSourceResult(r))
		}
	}

	out := &model.DomainBlacklistResult{
		RegisteredDomain: data.RegisteredDomain,
		CollectedAt:      data.CollectedAt,
		Results:          results,
	}

	// Tally the per-source verdicts once: the verdict and the score both
	// derive from it, so they cannot disagree. The score uses the same
	// scale as the rest of the report (pkg/grade) and is omitted when the
	// verdict is inconclusive (no usable source). The per-source counts
	// themselves are not sent over the API: results already carries one
	// entry per source, so the frontend derives any count it needs from it.
	summary := tally(results)
	out.Verdict = verdictOf(summary)
	if out.Verdict != model.DomainBlacklistResultVerdictInconclusive {
		score := max(0, 100-summary.penalty())
		g := model.DomainBlacklistResultGrade(grade.Of(score))
		out.Score = &score
		out.Grade = &g
	}

	return out
}

// blacklistTally holds the per-source counts used internally to derive the
// verdict and score. It is not part of the API response: results already
// carries one entry per source, so the frontend derives any count it needs
// from it instead of trusting a second, possibly diverging, summary.
type blacklistTally struct {
	answered, errored int
	// listed splits by severity into critical, warning and info.
	listed, critical, warning, info int
}

// Weight of a listing on the score, by severity, before it is shared out
// among the sources that answered.
const (
	criticalWeight = 100
	warningWeight  = 50
	infoWeight     = 25
)

// penalty returns the points the listings take off the score. Each
// listing weighs by its severity, divided by the number of sources that
// answered: a critical listing on one source out of five costs 20 points.
// The result is rounded up so no listing ever goes unpenalised.
func (s blacklistTally) penalty() int {
	if s.answered == 0 {
		return 0
	}
	weight := s.critical*criticalWeight + s.warning*warningWeight + s.info*infoWeight
	return (weight + s.answered - 1) / s.answered
}

// tally counts the per-source statuses.
func tally(results []model.DomainBlacklistSourceResult) (summary blacklistTally) {
	for _, r := range results {
		switch r.Status {
		case model.DomainBlacklistSourceResultStatusErrored:
			summary.errored++
		case model.DomainBlacklistSourceResultStatusClean:
			summary.answered++
		case model.DomainBlacklistSourceResultStatusPending:
			// No answer yet: it neither penalises nor vouches for the domain.
		case model.DomainBlacklistSourceResultStatusListed:
			summary.answered++
			summary.listed++
			switch utils.Deref(r.Severity) {
			case "crit":
				summary.critical++
			case "info":
				summary.info++
			default: // "warn" or unspecified severity
				summary.warning++
			}
		}
	}
	return summary
}

// verdictOf derives the overall verdict from the tally. It is inconclusive
// when no enabled source gave a usable answer.
func verdictOf(s blacklistTally) model.DomainBlacklistResultVerdict {
	switch {
	case s.critical > 0:
		return model.DomainBlacklistResultVerdictListedCritical
	case s.listed > 0:
		return model.DomainBlacklistResultVerdictListed
	case s.answered == 0:
		return model.DomainBlacklistResultVerdictInconclusive
	default:
		return model.DomainBlacklistResultVerdictClean
	}
}

// statusOf says how a source counts toward the verdict. A source whose
// resolver was blocked (e.g. a DNSBL refusing public resolvers) counts as
// errored, as in the checker's own rule engine: it did not answer, so it
// must not vouch for the domain. Nor must a feed source whose list is still
// downloading, which reports itself pending rather than in error.
func statusOf(r blacklist.SourceResult, listed bool) model.DomainBlacklistSourceResultStatus {
	switch {
	case r.Error != "" || r.BlockedQuery:
		return model.DomainBlacklistSourceResultStatusErrored
	case r.Pending:
		return model.DomainBlacklistSourceResultStatusPending
	case listed:
		return model.DomainBlacklistSourceResultStatusListed
	default:
		return model.DomainBlacklistSourceResultStatusClean
	}
}

func toSourceResult(r blacklist.SourceResult) model.DomainBlacklistSourceResult {
	// Recompute the verdict via the source's own Evaluate so the response
	// matches the rule engine's view (the SourceResult.Listed/Severity
	// fields are not populated by Collect).
	listed, severity := blacklist.EvaluateResult(r)

	out := model.DomainBlacklistSourceResult{
		SourceId:     r.SourceID,
		SourceName:   r.SourceName,
		Listed:       listed,
		Status:       statusOf(r, listed),
		Subject:      utils.PtrToNonZero(r.Subject),
		BlockedQuery: utils.PtrToNonZero(r.BlockedQuery),
		Severity:     utils.PtrToNonZero(severity),
		LookupUrl:    utils.PtrToNonZero(r.LookupURL),
		RemovalUrl:   utils.PtrToNonZero(r.RemovalURL),
		Reference:    utils.PtrToNonZero(r.Reference),
		Error:        utils.PtrToNonZero(r.Error),
	}
	if len(r.Reasons) > 0 {
		out.Reasons = utils.PtrTo(slices.Clone(r.Reasons))
	}
	if len(r.Evidence) > 0 {
		ev := make([]model.DomainBlacklistEvidence, 0, len(r.Evidence))
		for _, e := range r.Evidence {
			item := model.DomainBlacklistEvidence{
				Label:  e.Label,
				Value:  e.Value,
				Status: utils.PtrToNonZero(e.Status),
			}
			if len(e.Extra) > 0 {
				item.Extra = utils.PtrTo(maps.Clone(e.Extra))
			}
			ev = append(ev, item)
		}
		out.Evidence = &ev
	}
	if len(r.Details) > 0 {
		var details map[string]interface{}
		if err := json.Unmarshal(r.Details, &details); err == nil && details != nil {
			out.Details = &details
		}
	}
	return out
}
