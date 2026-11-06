// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// updateContentGolden rewrites the reference files instead of comparing to
// them. Run it when a change is *meant* to alter the content report, and read
// the resulting diff as the list of what it changed:
//
//	GOWORK=off go test ./pkg/analyzer/ -run TestContentGolden -update-golden
var updateContentGolden = flag.Bool("update-golden", false, "rewrite the content golden files instead of comparing to them")

// contentGoldenDir holds one reference file per fixture of ../../../test_email.
const contentGoldenDir = "testdata/content_golden"

// contentGolden is what a caller of the content analysis observes: the report
// block and the score it yields. It deliberately holds none of the analyzer's
// internal structures, so that a refactoring free to reshape them is still
// held to producing the very same report.
type contentGolden struct {
	Analysis *model.ContentAnalysis `json:"content_analysis"`
	Score    int                    `json:"score"`
	Grade    string                 `json:"grade"`
}

// TestContentGolden pins the content report of every fixture message.
//
// It exists to guard a refactoring, not to state what a good message looks
// like: the reference files record today's behaviour, warts included. A
// refactoring that claims to change nothing must leave every one of them
// untouched, which is a far stronger statement than the per-check unit tests
// can make on their own.
//
// URLs are left unfetched: the fixtures point at domains nobody here controls,
// so probing them would make the reference depend on the network. What the
// probe reveals is covered by link_http_test.go against a local server.
func TestContentGolden(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "..", "test_email", "*.eml"))
	if err != nil {
		t.Fatalf("listing fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixture found under ../../../test_email")
	}

	if *updateContentGolden {
		if err := os.MkdirAll(contentGoldenDir, 0o755); err != nil {
			t.Fatalf("creating %s: %v", contentGoldenDir, err)
		}
	}

	for _, fixture := range fixtures {
		name := strings.TrimSuffix(filepath.Base(fixture), ".eml")

		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatalf("reading %s: %v", fixture, err)
			}

			email, err := mailmsg.Parse(raw)
			if err != nil {
				t.Fatalf("parsing %s: %v", fixture, err)
			}

			analyzer := NewAnalyzer(5 * time.Second)
			analyzer.SkipProbes = true

			results := analyzer.Analyze(email)
			score, grade := analyzer.scoreOf(results)
			analysis := analyzer.analysisOf(results)

			// What the issues say they cost is what the score lost, so that
			// fixing them all brings it back to a hundred. A score held at
			// zero lost more than it shows.
			charged := 0
			for _, issue := range Issues(analysis) {
				if issue.Penalty != nil {
					charged += *issue.Penalty
				}
			}
			if score > 0 && grade != "" && charged != 100-score {
				t.Errorf("the issues are charged %d points, the score lost %d", charged, 100-score)
			}

			got, err := json.MarshalIndent(contentGolden{
				Analysis: analysis,
				Score:    score,
				Grade:    grade,
			}, "", "  ")
			if err != nil {
				t.Fatalf("serialising the report: %v", err)
			}
			got = append(got, '\n')

			golden := filepath.Join(contentGoldenDir, name+".json")

			if *updateContentGolden {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatalf("writing %s: %v", golden, err)
				}
				return
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("reading %s: %v (run with -update-golden to create it)", golden, err)
			}

			if string(got) != string(want) {
				t.Errorf("content report changed for %s.\n--- want\n%s\n--- got\n%s", name, want, got)
			}
		})
	}
}
