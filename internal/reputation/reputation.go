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
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	blacklist "git.happydns.org/checker-blacklist/checker"
	"golang.org/x/net/idna"

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
			results = append(results, toSourceResult(r, data.Domain))
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
		issues := listingIssues(results, summary.answered, data.RegisteredDomain)
		out.Issues = &model.DomainBlacklistIssues{Sources: &issues}
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

// weightOf is what a listing weighs on the score, by its severity.
func weightOf(severity string) (int, model.IssueSeverity) {
	switch severity {
	case "crit":
		return criticalWeight, model.IssueSeverityCritical
	case "info":
		return infoWeight, model.IssueSeverityMedium
	default: // "warn" or unspecified severity
		return warningWeight, model.IssueSeverityHigh
	}
}

// listingIssues says what each source listing the domain calls for, each
// charged its share of the penalty: the shares round up the way the
// penalty does, and stop where the score does, so they add up to it.
func listingIssues(results []model.DomainBlacklistSourceResult, answered int, domain string) []model.Issue {
	issues := []model.Issue{}
	shared := func(weight int) int {
		return min((weight+answered-1)/answered, 100)
	}

	weight := 0
	for _, r := range results {
		if r.Status != model.DomainBlacklistSourceResultStatusListed {
			continue
		}
		w, severity := weightOf(utils.Deref(r.Severity))
		penalty := shared(weight+w) - shared(weight)
		weight += w

		message := fmt.Sprintf("%s lists %s.", r.SourceName, domain)
		if r.Reasons != nil && len(*r.Reasons) > 0 {
			message = fmt.Sprintf("%s lists %s: %s.", r.SourceName, domain, strings.Join(*r.Reasons, "; "))
		}
		location := r.SourceName
		advice := "Check what each list reports (malware, phishing, spam), clean up the domain or the site it points to, then follow each list's removal procedure."
		issues = append(issues, model.Issue{
			Type:     model.IssueTypeDomainListed,
			Category: model.IssueCategoryDeliverability,
			Severity: severity,
			Message:  message,
			Location: &location,
			Advice:   &advice,
			Penalty:  &penalty,
		})
	}
	return issues
}

// tally counts the per-source statuses.
func tally(results []model.DomainBlacklistSourceResult) (summary blacklistTally) {
	for _, r := range results {
		switch r.Status {
		case model.DomainBlacklistSourceResultStatusErrored:
			summary.errored++
		case model.DomainBlacklistSourceResultStatusClean:
			summary.answered++
		case model.DomainBlacklistSourceResultStatusInformational, model.DomainBlacklistSourceResultStatusPending:
			// Shown only: it neither penalises nor vouches for the domain.
		case model.DomainBlacklistSourceResultStatusListed:
			summary.answered++
			summary.listed++
			switch weight, _ := weightOf(utils.Deref(r.Severity)); weight {
			case criticalWeight:
				summary.critical++
			case infoWeight:
				summary.info++
			default:
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

// webOnlySources block ad and tracker hosts for web browsing. No mail
// filter acts on them, and they list most large senders (google.com,
// microsoft.com, or their ad subdomains), so they are shown for
// information only.
var webOnlySources = map[string]bool{"oisd": true, "disconnect": true}

// urlFeedSources report every feed URL under the registered domain, on
// any of its subdomains: phishing hosted on sites.google.com says
// nothing about mail from google.com.
var urlFeedSources = map[string]bool{"openphish": true, "phishtank": true}

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
	case webOnlySources[r.SourceID]:
		return model.DomainBlacklistSourceResultStatusInformational
	case listed:
		return model.DomainBlacklistSourceResultStatusListed
	default:
		return model.DomainBlacklistSourceResultStatusClean
	}
}

// coveringURLs keeps the evidence URLs hosted on domain or on one of its
// parents: the others are on sibling or child names of the registered
// domain.
func coveringURLs(evidence []blacklist.Evidence, domain string) []blacklist.Evidence {
	return slices.DeleteFunc(slices.Clone(evidence), func(e blacklist.Evidence) bool {
		host := hostOf(e.Value)
		return host == "" || (host != domain && !strings.HasSuffix(domain, "."+host))
	})
}

// hostOf returns the host of rawURL in the form checker-blacklist gives
// the checked domain: ASCII, lower case, without a trailing dot.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if a, err := idna.Lookup.ToASCII(host); err == nil {
		return a
	}
	return strings.ToLower(host)
}

// toSourceResult converts r, checked for domain, to the API model.
func toSourceResult(r blacklist.SourceResult, domain string) model.DomainBlacklistSourceResult {
	// Only the URLs on domain or on one of its parents make a listing;
	// without any left, the reasons describing them go too.
	if urlFeedSources[r.SourceID] && len(r.Evidence) > 0 {
		r.Evidence = coveringURLs(r.Evidence, domain)
		if len(r.Evidence) == 0 {
			r.Reasons = nil
		}
	}

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
