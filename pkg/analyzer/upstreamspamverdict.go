// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package analyzer

import (
	"fmt"

	"git.happydns.org/happyDeliver/internal/model"
)

// An upstream filter is one that stamped its verdict on the message before
// this instance saw it: a provider filtering what its users send, or, on an
// uploaded file, what its users receive. The same filter may sit on either
// side, and its headers do not tell which. Either way, whoever handed the
// message over controls them: a verdict in the message's favour is easily
// forged and proves nothing, while nobody forges one against their own mail.
// Such a verdict can therefore only lower the spam category, see capSpamGrade.
//
// Teaching happyDeliver one of these filters takes a file of its own,
// registering it from init with registerUpstreamSpamVerdictFilter. Attributing its
// headers, grading the spam category and filling the report all go through the
// registry, and the web interface shows the verdict with the card registered
// under the same key, or a generic one.
type upstreamSpamVerdictFilter struct {
	// profile tells which headers are the filter's. Its scanner is the key the
	// verdict is reported under.
	profile spamScannerProfile

	// name is the filter's name, as shown.
	name string

	// analyze reads the filter's verdict out of the headers attributed to it,
	// and returns nil when they carry none.
	analyze func(ScannerHeaders) *UpstreamSpamVerdict
}

// UpstreamSpamVerdict is what an upstream filter made of a message.
type UpstreamSpamVerdict struct {
	// Filter and Name are the filter's, filled in by the registry.
	Filter SpamScanner
	Name   string

	IsSpam bool

	// Verdict says in a few words what the filter made of the message, as
	// "Spam" or "Not spam".
	Verdict string

	// Score and Grade are what the verdict caps the spam category at. Grade is
	// empty when the verdict does not count against the message.
	Score int
	Grade string

	// Details is what the filter reported, serialized as is for the web
	// interface to show: the backend never reads it back.
	Details any
}

// upstreamSpamVerdictFilters lists the registered filters, in the order their
// verdicts are reported.
var upstreamSpamVerdictFilters []upstreamSpamVerdictFilter

// registerUpstreamSpamVerdictFilter teaches happyDeliver an upstream filter. It is
// meant to be called from init, and panics on a key already taken.
func registerUpstreamSpamVerdictFilter(f upstreamSpamVerdictFilter) {
	for _, profile := range spamScannerProfiles {
		if profile.scanner == f.profile.scanner {
			panic(fmt.Sprintf("analyzer: spam scanner %q registered twice", f.profile.scanner))
		}
	}

	upstreamSpamVerdictFilters = append(upstreamSpamVerdictFilters, f)
	// After the profiles spamheaders.go lists itself: those go first, as they
	// contend for the shared headers.
	spamScannerProfiles = append(spamScannerProfiles, f.profile)
}

// analyzeUpstreamSpamVerdicts reads the verdict of every registered filter that left
// one on the message.
func analyzeUpstreamSpamVerdicts(headers SpamHeaderSet) []*UpstreamSpamVerdict {
	var verdicts []*UpstreamSpamVerdict

	for _, f := range upstreamSpamVerdictFilters {
		verdict := f.analyze(headers.For(f.profile.scanner))
		if verdict == nil {
			continue
		}

		verdict.Filter = f.profile.scanner
		verdict.Name = f.name
		verdicts = append(verdicts, verdict)
	}

	return verdicts
}

// capSpamGradeByUpstreamSpamVerdicts holds the spam category to every verdict that
// counts against the message.
func capSpamGradeByUpstreamSpamVerdicts(score int, g string, verdicts []*UpstreamSpamVerdict) (int, string) {
	for _, verdict := range verdicts {
		score, g = capSpamGrade(score, g, verdict.Score, verdict.Grade)
	}

	return score, g
}

// upstreamSpamVerdictsReport turns the verdicts into the report's, nil when there are
// none. Only a verdict counting against the message carries a grade.
func upstreamSpamVerdictsReport(verdicts []*UpstreamSpamVerdict) *[]model.UpstreamSpamVerdict {
	if len(verdicts) == 0 {
		return nil
	}

	report := make([]model.UpstreamSpamVerdict, 0, len(verdicts))
	for _, verdict := range verdicts {
		entry := model.UpstreamSpamVerdict{
			Filter:  string(verdict.Filter),
			Name:    verdict.Name,
			IsSpam:  verdict.IsSpam,
			Verdict: verdict.Verdict,
			Details: verdict.Details,
		}
		if verdict.Grade != "" {
			score := verdict.Score
			grade := model.UpstreamSpamVerdictDeliverabilityGrade(verdict.Grade)
			entry.DeliverabilityScore = &score
			entry.DeliverabilityGrade = &grade
		}
		report = append(report, entry)
	}

	return &report
}
