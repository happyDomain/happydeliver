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

package analyzer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// scannedMessage is the message handed to the scanner by the tests below. What
// it says does not matter: the controller's reply is what is under test.
const scannedMessage = "From: sender@example.com\r\n" +
	"Subject: HELLO THERE\r\n" +
	"\r\n" +
	"Hello.\r\n"

// replyWith answers every request with one canned rspamd reply.
func replyWith(t *testing.T, body string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("writing the reply: %v", err)
		}
	}
}

// TestRspamdScanReachesTheContentFindings walks the whole path: an uploaded
// message, a controller that answers, and the advice that comes out of it.
func TestRspamdScanReachesTheContentFindings(t *testing.T) {
	server := httptest.NewServer(replyWith(t,
		`{"score":3.0,"symbols":{
		  "ZERO_FONT": {"name":"ZERO_FONT","score":1.0},
		  "R_SPF_ALLOW": {"name":"R_SPF_ALLOW","score":-0.2}
		}}`))
	t.Cleanup(server.Close)

	generator := NewReportGenerator(GeneratorOptions{
		DNSTimeout:    time.Second,
		HTTPTimeout:   time.Second,
		RspamdScanURL: server.URL,
	})
	generator.contentAnalyzer.SkipProbes = true

	email, err := mailmsg.Parse([]byte(scannedMessage))
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	results := generator.AnalyzeEmail(email, AnalysisOptions{Source: model.ReportSourceUploaded})

	if results.Content == nil || results.Content.Rspamd == nil {
		t.Fatal("the content analysis was given no filter result")
	}
	if _, ok := results.Content.Rspamd.Symbols["ZERO_FONT"]; !ok {
		t.Error("the scan's symbols did not reach the content analysis")
	}

	// The spam category is untouched: the scan had no SMTP connection behind
	// it, so it says nothing worth scoring about the sender.
	if results.Rspamd != nil {
		t.Errorf("the scan was published as the message's spam verdict: %+v", results.Rspamd)
	}

	analysis := generator.contentAnalyzer.Analysis(results.Content, results.ContentReading)
	if analysis == nil || analysis.HtmlIssues == nil {
		t.Fatal("no content issue came out of the scan")
	}

	var found bool
	for _, issue := range *analysis.HtmlIssues {
		if issue.Symbol != nil && *issue.Symbol == "ZERO_FONT" {
			found = true
			if issue.Advice == nil || *issue.Advice == "" {
				t.Error("the finding carries no advice")
			}
		}
		if issue.Symbol != nil && *issue.Symbol == "R_SPF_ALLOW" {
			t.Error("an authentication symbol of the scan reached the content report")
		}
	}
	if !found {
		t.Error("ZERO_FONT was raised by the scan but is missing from the report")
	}
}

// TestRspamdScanLeavesReceivedMessagesAlone pins the condition: a message this
// instance received is annotated by its own milter on the way in, and asking a
// filter again would be both wasteful and a second opinion nobody asked for.
func TestRspamdScanLeavesReceivedMessagesAlone(t *testing.T) {
	var asked bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked = true
		io.WriteString(w, `{"symbols":{"ZERO_FONT":{"name":"ZERO_FONT","score":1.0}}}`)
	}))
	t.Cleanup(server.Close)

	generator := NewReportGenerator(GeneratorOptions{
		DNSTimeout:    time.Second,
		HTTPTimeout:   time.Second,
		RspamdScanURL: server.URL,
	})
	generator.contentAnalyzer.SkipProbes = true

	email, err := mailmsg.Parse([]byte(scannedMessage))
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	generator.AnalyzeEmail(email, AnalysisOptions{Source: model.ReportSourceReceived})

	if asked {
		t.Error("a message received over SMTP was submitted for a scan")
	}
}

// TestRspamdScanDoesNotDisplaceAThirdPartyVerdict covers an uploaded .eml that
// already carries someone else's X-Spamd-Result: their verdict stays the
// message's spam block, while the content findings come from the scan we can
// vouch for.
func TestRspamdScanDoesNotDisplaceAThirdPartyVerdict(t *testing.T) {
	server := httptest.NewServer(replyWith(t,
		`{"score":3.0,"symbols":{"ZERO_FONT":{"name":"ZERO_FONT","score":1.0}}}`))
	t.Cleanup(server.Close)

	generator := NewReportGenerator(GeneratorOptions{
		DNSTimeout:    time.Second,
		HTTPTimeout:   time.Second,
		RspamdScanURL: server.URL,
	})
	generator.contentAnalyzer.SkipProbes = true

	email, err := mailmsg.Parse([]byte(
		"From: sender@example.com\r\n" +
			"Subject: HELLO THERE\r\n" +
			"X-Spamd-Result: default: False [1.20 / 15.00];\tMIME_HTML_ONLY(0.20)[];\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<html><body><p>Hello</p></body></html>"))
	if err != nil {
		t.Fatalf("parsing the message: %v", err)
	}

	results := generator.AnalyzeEmail(email, AnalysisOptions{Source: model.ReportSourceUploaded})

	if results.Rspamd == nil {
		t.Fatal("the third party's verdict was dropped")
	}
	if _, ok := results.Rspamd.Symbols["MIME_HTML_ONLY"]; !ok {
		t.Error("the spam block is not the one the message carried")
	}
	if _, ok := results.Rspamd.Symbols["ZERO_FONT"]; ok {
		t.Error("the scan overwrote the third party's verdict")
	}

	// While the content findings come from our own scan.
	if results.Content == nil || results.Content.Rspamd == nil {
		t.Fatal("the content analysis was given no filter result")
	}
	if _, ok := results.Content.Rspamd.Symbols["ZERO_FONT"]; !ok {
		t.Error("the content findings do not come from the scan")
	}
}
