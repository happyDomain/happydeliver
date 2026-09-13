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
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// TestContentAnalyzerIsSharedSafely analyses several messages at once through
// one analyzer, which is how the server uses it: NewReportGenerator builds a
// single Analyzer at startup and every delivery and upload goes through
// that one.
//
// Run it under -race to see what it guards. Beyond the race itself, it checks
// that each report keeps its own message's unsubscribe address: state held on
// the analyzer rather than on the results was not merely racy, it attributed
// one message's List-Unsubscribe to another message's report, and sent the
// probe after the wrong URL.
func TestContentAnalyzerIsSharedSafely(t *testing.T) {
	const messages = 8

	shared := NewAnalyzer(5 * time.Second)
	shared.SkipProbes = true

	type outcome struct {
		want     string
		analysis *model.ContentAnalysis
		results  *Results
	}
	outcomes := make([]outcome, messages)

	var wg sync.WaitGroup
	for i := range messages {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each message advertises an unsubscribe address of its own, and
			// one-click on the even ones only.
			unsubscribe := fmt.Sprintf("https://example.com/unsubscribe/%d", i)
			raw := fmt.Appendf(nil,
				"From: sender@example.com\r\n"+
					"Subject: message %d\r\n"+
					"List-Unsubscribe: <%s>\r\n"+
					oneClickHeader(i%2 == 0)+
					"Content-Type: text/html\r\n"+
					"\r\n"+
					"<html><body><p>Message %d</p></body></html>",
				i, unsubscribe, i)

			email, err := mailmsg.Parse(raw)
			if err != nil {
				t.Errorf("parsing message %d: %v", i, err)
				return
			}

			results := shared.Analyze(email)
			outcomes[i] = outcome{
				want:     unsubscribe,
				analysis: shared.analysisOf(results),
				results:  results,
			}
		}()
	}
	wg.Wait()

	for i, got := range outcomes {
		if got.results == nil {
			continue // the goroutine already failed the test
		}

		if !slices.Equal(got.results.ListUnsubscribeURLs, []string{got.want}) {
			t.Errorf("message %d kept %v as its unsubscribe address, want [%s]", i, got.results.ListUnsubscribeURLs, got.want)
		}

		wantOneClick := i%2 == 0
		if got.results.HasOneClickUnsubscribe != wantOneClick {
			t.Errorf("message %d reports one-click %v, want %v", i, got.results.HasOneClickUnsubscribe, wantOneClick)
		}

		if got.analysis == nil || got.analysis.UnsubscribeMethods == nil {
			t.Errorf("message %d produced no unsubscribe method", i)
			continue
		}
		methods := *got.analysis.UnsubscribeMethods
		if !slices.Contains(methods, model.ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader) {
			t.Errorf("message %d does not report its List-Unsubscribe header: %v", i, methods)
		}
		if slices.Contains(methods, model.ContentAnalysisUnsubscribeMethodsOneClick) != wantOneClick {
			t.Errorf("message %d reports one-click as %v, want %v: %v", i, !wantOneClick, wantOneClick, methods)
		}
	}
}

func oneClickHeader(enabled bool) string {
	if !enabled {
		return ""
	}
	return "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
}
