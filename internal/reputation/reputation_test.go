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

package reputation

import (
	"testing"
	"time"

	blacklist "git.happydns.org/checker-blacklist/checker"

	"git.happydns.org/happyDeliver/internal/model"
)

func TestFromObservationNilOrWrongType(t *testing.T) {
	if got := FromObservation(nil); got != nil {
		t.Fatalf("FromObservation(nil) = %v, want nil", got)
	}
	if got := FromObservation("not-a-blacklist-data"); got != nil {
		t.Fatalf("FromObservation(wrong type) = %v, want nil", got)
	}
}

func TestFromObservationCriticalListing(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	data := &blacklist.BlacklistData{
		Domain:           "example.com",
		RegisteredDomain: "example.com",
		CollectedAt:      now,
		Results: []blacklist.SourceResult{
			{
				// dnsbl.Evaluate reports crit+listed when enabled, no error/blocked
				// query, and at least one piece of evidence.
				SourceID:   "dnsbl",
				SourceName: "DNS blocklists",
				Subject:    "zen.spamhaus.org",
				Enabled:    true,
				Reasons:    []string{"listed on zen.spamhaus.org"},
				Evidence:   []blacklist.Evidence{{Label: "Return code", Value: "127.0.0.2"}},
				LookupURL:  "https://check.spamhaus.org/",
				RemovalURL: "https://www.spamhaus.org/lookup/",
			},
			{
				// Same source ID, clean subject: enabled, no evidence -> not listed.
				SourceID:   "dnsbl",
				SourceName: "DNS blocklists",
				Subject:    "multi.surbl.org",
				Enabled:    true,
			},
			{
				// Disabled source: left out of the results.
				SourceID:   "dnsbl",
				SourceName: "DNS blocklists",
				Subject:    "uribl.com",
				Enabled:    false,
			},
		},
	}

	result := FromObservation(data)
	if result == nil {
		t.Fatal("FromObservation returned nil for populated data")
	}
	if result.RegisteredDomain != "example.com" {
		t.Errorf("RegisteredDomain = %q, want %q", result.RegisteredDomain, "example.com")
	}
	if !result.CollectedAt.Equal(now) {
		t.Errorf("CollectedAt = %v, want %v", result.CollectedAt, now)
	}
	if len(result.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2: the disabled source must be left out", len(result.Results))
	}

	listed := result.Results[0]
	if !listed.Listed {
		t.Error("expected first result to be Listed")
	}
	if listed.Severity == nil || *listed.Severity != blacklist.SeverityCrit {
		t.Errorf("Severity = %v, want %q", listed.Severity, blacklist.SeverityCrit)
	}
	if listed.LookupUrl == nil || *listed.LookupUrl != "https://check.spamhaus.org/" {
		t.Errorf("LookupUrl = %v, want the lookup URL", listed.LookupUrl)
	}
	if listed.Evidence == nil || len(*listed.Evidence) != 1 {
		t.Errorf("Evidence = %v, want one entry", listed.Evidence)
	}

	clean := result.Results[1]
	if clean.Listed {
		t.Error("expected second result not to be Listed")
	}
	if clean.LookupUrl != nil {
		t.Errorf("LookupUrl = %v, want nil for an unset field", clean.LookupUrl)
	}

	// The critical listing weighs 100, shared between the two sources
	// that answered.
	if result.Score == nil || *result.Score != 50 {
		t.Errorf("Score = %v, want 50", result.Score)
	}
	if result.Grade == nil {
		t.Fatal("Grade is nil, want a grade to be set")
	}
	if result.Verdict != model.DomainBlacklistResultVerdictListedCritical {
		t.Errorf("Verdict = %q, want %q", result.Verdict, model.DomainBlacklistResultVerdictListedCritical)
	}
	want := blacklistTally{answered: 2, listed: 1, critical: 1}
	if got := tally(result.Results); got != want {
		t.Errorf("tally(Results) = %+v, want %+v", got, want)
	}
}

func TestFromObservationCleanIsHighScore(t *testing.T) {
	data := &blacklist.BlacklistData{
		Domain:      "example.net",
		CollectedAt: time.Now(),
		Results: []blacklist.SourceResult{
			{SourceID: "dnsbl", SourceName: "DNS blocklists", Subject: "zen.spamhaus.org", Enabled: true},
			{SourceID: "dnsbl", SourceName: "DNS blocklists", Subject: "multi.surbl.org", Enabled: true},
		},
	}

	result := FromObservation(data)
	if result == nil {
		t.Fatal("FromObservation returned nil for populated data")
	}
	if result.Score == nil || *result.Score != 100 {
		t.Errorf("Score = %v, want 100", result.Score)
	}
	for _, r := range result.Results {
		if r.Listed {
			t.Errorf("unexpected listed result: %+v", r)
		}
	}
}

func TestFromObservationInconclusiveOmitsScore(t *testing.T) {
	cases := []struct {
		name    string
		results []blacklist.SourceResult
	}{
		{
			name:    "all disabled",
			results: []blacklist.SourceResult{{SourceID: "dnsbl", Enabled: false}},
		},
		{
			name: "all errored",
			results: []blacklist.SourceResult{
				{SourceID: "dnsbl", Enabled: true, Error: "timeout"},
			},
		},
		{
			name: "all blocked by the resolver",
			results: []blacklist.SourceResult{
				{SourceID: "dnsbl", Subject: "zen.spamhaus.org", Enabled: true, BlockedQuery: true},
				{SourceID: "dnsbl", Subject: "dbl.spamhaus.org", Enabled: true, BlockedQuery: true},
			},
		},
		{
			name: "blocked and errored",
			results: []blacklist.SourceResult{
				{SourceID: "dnsbl", Subject: "zen.spamhaus.org", Enabled: true, BlockedQuery: true},
				{SourceID: "dnsbl", Subject: "multi.surbl.org", Enabled: true, Error: "timeout"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &blacklist.BlacklistData{
				Domain:      "example.org",
				CollectedAt: time.Now(),
				Results:     tc.results,
			}
			result := FromObservation(data)
			if result == nil {
				t.Fatal("FromObservation returned nil for populated data")
			}
			if result.Score != nil {
				t.Errorf("Score = %v, want nil (inconclusive)", *result.Score)
			}
			if result.Grade != nil {
				t.Errorf("Grade = %v, want nil (inconclusive)", *result.Grade)
			}
			if result.Verdict != model.DomainBlacklistResultVerdictInconclusive {
				t.Errorf("Verdict = %q, want %q", result.Verdict, model.DomainBlacklistResultVerdictInconclusive)
			}
			if got := tally(result.Results); got.answered != 0 {
				t.Errorf("tally(Results).answered = %d, want 0", got.answered)
			}
		})
	}
}

func TestFromObservationBlockedQueryIsIgnored(t *testing.T) {
	data := &blacklist.BlacklistData{
		Domain:      "example.com",
		CollectedAt: time.Now(),
		Results: []blacklist.SourceResult{
			{SourceID: "dnsbl", SourceName: "DNS blocklists", Subject: "zen.spamhaus.org", Enabled: true, BlockedQuery: true},
			{SourceID: "dnsbl", SourceName: "DNS blocklists", Subject: "multi.surbl.org", Enabled: true},
			{
				SourceID:   "disconnect",
				SourceName: "Disconnect",
				Enabled:    true,
				Evidence:   []blacklist.Evidence{{Label: "Category", Value: "Advertising"}},
			},
		},
	}

	result := FromObservation(data)
	if result == nil {
		t.Fatal("FromObservation returned nil for populated data")
	}
	// Only the warn listing weighs on the score; the blocked source neither
	// penalises nor vouches for the domain: the listing weighs 50, shared
	// between the two sources that answered.
	if result.Score == nil || *result.Score != 75 {
		t.Errorf("Score = %v, want 75", result.Score)
	}
	if result.Verdict != model.DomainBlacklistResultVerdictListed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, model.DomainBlacklistResultVerdictListed)
	}
	want := blacklistTally{answered: 2, errored: 1, listed: 1, warning: 1}
	if got := tally(result.Results); got != want {
		t.Errorf("tally(Results) = %+v, want %+v", got, want)
	}
	blocked := result.Results[0]
	if blocked.Listed {
		t.Error("blocked result must not be Listed")
	}
	if blocked.BlockedQuery == nil || !*blocked.BlockedQuery {
		t.Errorf("BlockedQuery = %v, want true", blocked.BlockedQuery)
	}
}

func TestFromObservationCleanDespiteSomeErrors(t *testing.T) {
	data := &blacklist.BlacklistData{
		Domain:      "example.com",
		CollectedAt: time.Now(),
		Results: []blacklist.SourceResult{
			{SourceID: "dnsbl", Subject: "zen.spamhaus.org", Enabled: true, BlockedQuery: true},
			{SourceID: "dnsbl", Subject: "multi.surbl.org", Enabled: true, Error: "timeout"},
			{SourceID: "dnsbl", Subject: "uribl.com", Enabled: true},
			{SourceID: "dnsbl", Subject: "dbl.example.net", Enabled: true},
		},
	}

	result := FromObservation(data)
	if result == nil {
		t.Fatal("FromObservation returned nil for populated data")
	}
	// The sources that answered found nothing: the domain is clean, but the
	// summary must not pretend the failed ones answered too.
	if result.Verdict != model.DomainBlacklistResultVerdictClean {
		t.Errorf("Verdict = %q, want %q", result.Verdict, model.DomainBlacklistResultVerdictClean)
	}
	want := blacklistTally{answered: 2, errored: 2}
	if got := tally(result.Results); got != want {
		t.Errorf("tally(Results) = %+v, want %+v", got, want)
	}
	if result.Score == nil || *result.Score != 100 {
		t.Errorf("Score = %v, want 100", result.Score)
	}
}

func TestFromObservationStatus(t *testing.T) {
	data := &blacklist.BlacklistData{
		Results: []blacklist.SourceResult{
			{SourceID: "otx", Enabled: false},
			{SourceID: "quad9", Enabled: false},
			{SourceID: "dnsbl", Subject: "zen.spamhaus.org", Enabled: true, BlockedQuery: true},
			{SourceID: "quad9", Enabled: true, Error: "timeout"},
			{SourceID: "quad9", Enabled: true},
		},
	}
	// The disabled otx and quad9 are left out.
	want := []model.DomainBlacklistSourceResultStatus{
		model.DomainBlacklistSourceResultStatusErrored,
		model.DomainBlacklistSourceResultStatusErrored,
		model.DomainBlacklistSourceResultStatusClean,
	}

	out := FromObservation(data)
	if len(out.Results) != len(want) {
		t.Fatalf("len(Results) = %d, want %d", len(out.Results), len(want))
	}
	for i, r := range out.Results {
		if r.Status != want[i] {
			t.Errorf("Results[%d] (%s) status = %q, want %q", i, r.SourceId, r.Status, want[i])
		}
	}
	got := tally(out.Results)
	if got.errored != 2 || got.answered != 1 {
		t.Errorf("tally(Results) = %+v, want 2 errored, 1 answered", got)
	}
}

// A feed still downloading has no error and no evidence, which reads as
// clean unless Pending is looked at: the first checks after a start must
// not call the domain clean on the strength of empty lists.
func TestFromObservationPendingFeedsDoNotVouch(t *testing.T) {
	data := &blacklist.BlacklistData{
		Results: []blacklist.SourceResult{
			{SourceID: "openphish", Enabled: true, Pending: true},
			{SourceID: "phishtank", Enabled: true, Pending: true},
			{SourceID: "oisd", Enabled: true, Pending: true},
		},
	}

	out := FromObservation(data)
	for _, r := range out.Results {
		if r.Status != model.DomainBlacklistSourceResultStatusPending {
			t.Errorf("%s status = %q, want %q", r.SourceId, r.Status, model.DomainBlacklistSourceResultStatusPending)
		}
	}
	if out.Verdict != model.DomainBlacklistResultVerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", out.Verdict, model.DomainBlacklistResultVerdictInconclusive)
	}
	if out.Score != nil {
		t.Errorf("Score = %d, want none for an inconclusive verdict", *out.Score)
	}
}

func TestTallyPenaltyIsShared(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tally blacklistTally
		want  int
	}{
		{"nothing answered", blacklistTally{}, 0},
		{"clean", blacklistTally{answered: 5}, 0},
		{"one critical out of five", blacklistTally{answered: 5, listed: 1, critical: 1}, 20},
		{"one critical alone", blacklistTally{answered: 1, listed: 1, critical: 1}, 100},
		{"one warning out of five", blacklistTally{answered: 5, listed: 1, warning: 1}, 10},
		{"one info out of thirty rounds up", blacklistTally{answered: 30, listed: 1, info: 1}, 1},
		{"mixed", blacklistTally{answered: 4, listed: 3, critical: 1, warning: 1, info: 1}, 44},
	} {
		if got := tc.tally.penalty(); got != tc.want {
			t.Errorf("%s: penalty() = %d, want %d", tc.name, got, tc.want)
		}
	}
}
