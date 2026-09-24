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
				// Disabled source: not counted as enabled at all.
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
	if len(result.Results) != 3 {
		t.Fatalf("len(Results) = %d, want 3", len(result.Results))
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

	// A critical listing should drive the score to 0 with the worst grade.
	if result.Score == nil || *result.Score != 0 {
		t.Errorf("Score = %v, want 0", result.Score)
	}
	if result.Grade == nil {
		t.Fatal("Grade is nil, want a grade to be set")
	}
}

func TestFromObservationCleanIsHighScore(t *testing.T) {
	data := &blacklist.BlacklistData{
		Domain:       "example.net",
		CollectedAt:  time.Now(),
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
		})
	}
}
