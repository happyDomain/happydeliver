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
	"testing"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// withUpstreamSpamVerdictFilter registers a filter for the duration of a test.
func withUpstreamSpamVerdictFilter(t *testing.T, f upstreamSpamVerdictFilter) {
	t.Helper()

	filters, profiles := upstreamSpamVerdictFilters, spamScannerProfiles
	t.Cleanup(func() {
		upstreamSpamVerdictFilters, spamScannerProfiles = filters, profiles
	})

	registerUpstreamSpamVerdictFilter(f)
}

// exampleUpstreamFilter flags as spam a message whose X-Example-Verdict says so.
var exampleUpstreamFilter = upstreamSpamVerdictFilter{
	profile: spamScannerProfile{
		scanner:    "example",
		ownHeaders: []string{"X-Example-Verdict"},
	},
	name: "Example",
	analyze: func(headers ScannerHeaders) *UpstreamSpamVerdict {
		switch headers["X-Example-Verdict"] {
		case "":
			return nil
		case "spam":
			score, grade := spamBandE.top()
			return &UpstreamSpamVerdict{IsSpam: true, Verdict: "Spam", Score: score, Grade: grade, Details: map[string]string{"raw": "spam"}}
		default:
			return &UpstreamSpamVerdict{Verdict: "Not spam", Score: 100}
		}
	},
}

func TestUpstreamSpamVerdicts(t *testing.T) {
	withUpstreamSpamVerdictFilter(t, exampleUpstreamFilter)

	tests := []struct {
		name       string
		raw        string
		wantCount  int
		wantSpam   bool
		wantGraded bool
	}{
		{"no header, no verdict", "Subject: hello\r\n\r\nbody\r\n", 0, false, false},
		{"a clean verdict is reported ungraded", "X-Example-Verdict: ok\r\nSubject: hello\r\n\r\nbody\r\n", 1, false, false},
		{"a verdict against the message is graded", "X-Example-Verdict: spam\r\nSubject: hello\r\n\r\nbody\r\n", 1, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := mailmsg.Parse([]byte(tt.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			verdicts := analyzeUpstreamSpamVerdicts(spamScannerHeaders(email))
			if len(verdicts) != tt.wantCount {
				t.Fatalf("got %d verdicts, want %d", len(verdicts), tt.wantCount)
			}

			report := upstreamSpamVerdictsReport(verdicts)
			if tt.wantCount == 0 {
				if report != nil {
					t.Errorf("report = %v, want nil", *report)
				}
				return
			}

			got := (*report)[0]
			if got.Filter != "example" || got.Name != "Example" {
				t.Errorf("filter = %q %q, want example Example", got.Filter, got.Name)
			}
			if got.IsSpam != tt.wantSpam {
				t.Errorf("is_spam = %v, want %v", got.IsSpam, tt.wantSpam)
			}
			if (got.DeliverabilityGrade != nil) != tt.wantGraded {
				t.Errorf("deliverability_grade = %v, graded: %v", got.DeliverabilityGrade, tt.wantGraded)
			}
		})
	}
}

func TestCapSpamGradeByUpstreamSpamVerdicts(t *testing.T) {
	verdicts := []*UpstreamSpamVerdict{
		{Score: 100},
		{Score: 64, Grade: "E"},
		{Score: 30, Grade: "F"},
	}

	score, grade := capSpamGradeByUpstreamSpamVerdicts(92, "B", verdicts)
	if score != 30 || grade != "F" {
		t.Errorf("got %d %q, want 30 \"F\"", score, grade)
	}

	score, grade = capSpamGradeByUpstreamSpamVerdicts(92, "B", verdicts[:1])
	if score != 92 || grade != "B" {
		t.Errorf("a clean verdict changed the category: got %d %q", score, grade)
	}
}

func TestRegisterUpstreamSpamVerdictFilterTwice(t *testing.T) {
	withUpstreamSpamVerdictFilter(t, exampleUpstreamFilter)

	defer func() {
		if recover() == nil {
			t.Error("registering a key twice did not panic")
		}
	}()
	registerUpstreamSpamVerdictFilter(exampleUpstreamFilter)
}
