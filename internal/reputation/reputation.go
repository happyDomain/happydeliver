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

	blacklist "git.happydns.org/checker-blacklist/checker"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/analyzer"
)

// FromObservation turns a checker-blacklist observation payload into a
// DomainBlacklistResult. It returns nil when the payload is missing or of an
// unexpected type, so callers can degrade gracefully.
func FromObservation(raw interface{}) *model.DomainBlacklistResult {
	data, ok := raw.(*blacklist.BlacklistData)
	if !ok || data == nil {
		return nil
	}
	return buildResult(data)
}

func buildResult(data *blacklist.BlacklistData) *model.DomainBlacklistResult {
	results := make([]model.DomainBlacklistSourceResult, 0, len(data.Results))
	for _, r := range data.Results {
		results = append(results, toSourceResult(r))
	}

	out := &model.DomainBlacklistResult{
		RegisteredDomain: data.RegisteredDomain,
		CollectedAt:      data.CollectedAt,
		Results:          results,
	}

	// Compute a deliverability-style score/grade from the per-source verdicts,
	// mirroring the RBL grading in pkg/analyzer. The score/grade are omitted
	// when the verdict is inconclusive (no usable source).
	if score, ok := scoreResults(results); ok {
		grade := model.DomainBlacklistResultGrade(analyzer.ScoreToGrade(score))
		out.Score = &score
		out.Grade = &grade
	}

	return out
}

// scoreResults turns the per-source verdicts into a 0-100 reputation score. It
// returns ok=false when the verdict is inconclusive: no enabled source, or
// every enabled source errored. Listings are penalised by severity so a single
// critical listing is enough to fail the domain.
func scoreResults(results []model.DomainBlacklistSourceResult) (int, bool) {
	enabled := 0
	errored := 0
	penalty := 0

	for _, r := range results {
		if !r.Enabled {
			continue
		}
		enabled++
		if r.Error != nil && *r.Error != "" {
			errored++
			continue
		}
		if !r.Listed {
			continue
		}
		switch severityOf(r) {
		case "crit":
			penalty += 100
		case "info":
			penalty += 10
		default: // "warn" or unspecified severity
			penalty += 20
		}
	}

	if enabled == 0 || errored == enabled {
		return 0, false
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score, true
}

func severityOf(r model.DomainBlacklistSourceResult) string {
	if r.Severity == nil {
		return ""
	}
	return *r.Severity
}

func toSourceResult(r blacklist.SourceResult) model.DomainBlacklistSourceResult {
	// Recompute the verdict via the source's own Evaluate so the response
	// matches the rule engine's view (the SourceResult.Listed/Severity
	// fields are not populated by Collect).
	listed, severity := blacklist.EvaluateResult(r)

	out := model.DomainBlacklistSourceResult{
		SourceId:   r.SourceID,
		SourceName: r.SourceName,
		Enabled:    r.Enabled,
		Listed:     listed,
	}
	if r.Subject != "" {
		out.Subject = utils.PtrTo(r.Subject)
	}
	if r.BlockedQuery {
		out.BlockedQuery = utils.PtrTo(r.BlockedQuery)
	}
	if severity != "" {
		out.Severity = utils.PtrTo(severity)
	}
	if len(r.Reasons) > 0 {
		reasons := append([]string(nil), r.Reasons...)
		out.Reasons = &reasons
	}
	if len(r.Evidence) > 0 {
		ev := make([]model.DomainBlacklistEvidence, 0, len(r.Evidence))
		for _, e := range r.Evidence {
			item := model.DomainBlacklistEvidence{Label: e.Label, Value: e.Value}
			if e.Status != "" {
				item.Status = utils.PtrTo(e.Status)
			}
			if len(e.Extra) > 0 {
				extra := make(map[string]string, len(e.Extra))
				for k, v := range e.Extra {
					extra[k] = v
				}
				item.Extra = &extra
			}
			ev = append(ev, item)
		}
		out.Evidence = &ev
	}
	if r.LookupURL != "" {
		out.LookupUrl = utils.PtrTo(r.LookupURL)
	}
	if r.RemovalURL != "" {
		out.RemovalUrl = utils.PtrTo(r.RemovalURL)
	}
	if r.Reference != "" {
		out.Reference = utils.PtrTo(r.Reference)
	}
	if r.Error != "" {
		out.Error = utils.PtrTo(r.Error)
	}
	if len(r.Details) > 0 {
		var details map[string]interface{}
		if err := json.Unmarshal(r.Details, &details); err == nil && details != nil {
			out.Details = &details
		}
	}
	return out
}
