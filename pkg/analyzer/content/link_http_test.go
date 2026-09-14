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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
	"git.happydns.org/happyDeliver/pkg/urlprobe"
)

// The URL of an httptest server is "http://127.0.0.1:PORT", which
// analyzeURLSuspicions reports three times over: ip_host, non_standard_port and
// insecure_scheme. Tests that reach the network therefore never assert on
// IsSafe or on Suspicions, only on what the probe brought back. The mapping
// and scoring tests below run on hand-built results instead, with no server at
// all.

// probeLink runs on a single URL exactly what a message carrying it would get:
// the offline reading, then the fetch pass. The tests go through
// probeContentURLs rather than a shortcut of their own, so that what they
// assert is what production does.
func probeLink(t *testing.T, analyzer *Analyzer, rawURL string) LinkCheck {
	t.Helper()

	results := &Results{Links: []LinkCheck{analyzeLinkOffline(rawURL)}}
	analyzer.probeContentURLs(results)

	return results.Links[0]
}

// newProbingTestAnalyzer returns an analyzer allowed to fetch the loopback
// address the test servers listen on. Outside the tests the probe refuses any
// address that is not on the public internet; see TestProbeRefusesPrivateTargets.
func newProbingTestAnalyzer(timeout time.Duration) *Analyzer {
	analyzer := NewAnalyzer(timeout)
	analyzer.prober.AllowPrivateTargets = true
	return analyzer
}

// findingKinds lists the kinds of the findings, to compare against an expected
// set without depending on their order or on their wording.
func findingKinds(findings []LinkHTTPFinding) []LinkHTTPFindingKind {
	kinds := make([]LinkHTTPFindingKind, 0, len(findings))
	for _, finding := range findings {
		kinds = append(kinds, finding.Kind)
	}
	return kinds
}

// hopServer answers "/hop/N" with a redirection to "/hop/N-1", and "/hop/0"
// with a 200, so that a request to "/hop/N" walks exactly N redirections.
func hopServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		remaining, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if remaining == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s/hop/%d", server.URL, remaining-1), http.StatusFound)
	})

	return server
}

func TestProbeRecordsRedirectChain(t *testing.T) {
	server := hopServer(t)
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	check := probeLink(t, analyzer, server.URL+"/hop/2")

	if check.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", check.Status)
	}
	if len(check.RedirectChain) != 2 {
		t.Errorf("RedirectChain = %v, want 2 hops", check.RedirectChain)
	}
	if !strings.HasSuffix(check.FinalURL, "/hop/0") {
		t.Errorf("FinalURL = %q, want it to end at /hop/0", check.FinalURL)
	}
	// Two hops are ordinary: a redirection that is merely followed is not a
	// finding.
	if len(check.HTTPFindings) != 0 {
		t.Errorf("HTTPFindings = %v, want none for a two-hop chain", findingKinds(check.HTTPFindings))
	}
}

func TestProbeReportsExcessiveRedirects(t *testing.T) {
	server := hopServer(t)
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	tests := []struct {
		name     string
		hops     int
		severity model.ContentIssueSeverity
	}{
		{name: "three hops are a detour", hops: 3, severity: model.ContentIssueSeverityMedium},
		{name: "five hops are a chain out of hand", hops: 5, severity: model.ContentIssueSeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := probeLink(t, analyzer, fmt.Sprintf("%s/hop/%d", server.URL, tt.hops))

			if len(check.HTTPFindings) != 1 {
				t.Fatalf("HTTPFindings = %v, want exactly one", findingKinds(check.HTTPFindings))
			}
			finding := check.HTTPFindings[0]
			if finding.Kind != LinkHTTPExcessiveRedirects {
				t.Errorf("Kind = %q, want %q", finding.Kind, LinkHTTPExcessiveRedirects)
			}
			if finding.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", finding.Severity, tt.severity)
			}
			// The message must name the destination the chain ends at: that is
			// what the sender has to look at.
			if !strings.Contains(finding.Message, "/hop/0") {
				t.Errorf("Message = %q, want it to name the final URL", finding.Message)
			}
		})
	}
}

func TestProbeReportsRedirectLoop(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/loop", http.StatusFound)
	})
	// A chain that never repeats a URL still has to stop somewhere.
	mux.HandleFunc("/endless/", func(w http.ResponseWriter, r *http.Request) {
		step, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/endless/"))
		http.Redirect(w, r, fmt.Sprintf("%s/endless/%d", server.URL, step+1), http.StatusFound)
	})

	analyzer := newProbingTestAnalyzer(5 * time.Second)

	for _, path := range []string{"/loop", "/endless/0"} {
		t.Run(path, func(t *testing.T) {
			check := probeLink(t, analyzer, server.URL+path)

			if !check.hasFinding(LinkHTTPRedirectLoop) {
				t.Fatalf("HTTPFindings = %v, want a redirect loop", findingKinds(check.HTTPFindings))
			}
			if check.Status != 0 {
				t.Errorf("Status = %d, want 0: no response ever came back", check.Status)
			}
			// The link is its own reason for failing, so it must not be filed
			// under "could not verify", which would map it to a timeout.
			if check.Warning != "" {
				t.Errorf("Warning = %q, want empty: the loop is the link's doing", check.Warning)
			}
		})
	}
}

func TestProbeClassifiesStatusCodes(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	for _, status := range []int{404, 410, 401, 403, 429, 500, 503} {
		mux.HandleFunc(fmt.Sprintf("/%d", status), func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})
	}

	analyzer := newProbingTestAnalyzer(5 * time.Second)

	tests := []struct {
		status   int
		kind     LinkHTTPFindingKind
		severity model.ContentIssueSeverity
	}{
		{status: 404, kind: LinkHTTPNotFound, severity: model.ContentIssueSeverityHigh},
		{status: 410, kind: LinkHTTPNotFound, severity: model.ContentIssueSeverityHigh},
		{status: 401, kind: LinkHTTPProtected, severity: model.ContentIssueSeverityHigh},
		{status: 403, kind: LinkHTTPProtected, severity: model.ContentIssueSeverityHigh},
		{status: 429, kind: LinkHTTPServerFailure, severity: model.ContentIssueSeverityMedium},
		{status: 500, kind: LinkHTTPServerFailure, severity: model.ContentIssueSeverityMedium},
		{status: 503, kind: LinkHTTPServerFailure, severity: model.ContentIssueSeverityMedium},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			check := probeLink(t, analyzer, fmt.Sprintf("%s/%d", server.URL, tt.status))

			if check.Status != tt.status {
				t.Errorf("Status = %d, want %d", check.Status, tt.status)
			}
			if len(check.HTTPFindings) != 1 {
				t.Fatalf("HTTPFindings = %v, want exactly one", findingKinds(check.HTTPFindings))
			}
			if got := check.HTTPFindings[0].Kind; got != tt.kind {
				t.Errorf("Kind = %q, want %q", got, tt.kind)
			}
			if got := check.HTTPFindings[0].Severity; got != tt.severity {
				t.Errorf("Severity = %q, want %q", got, tt.severity)
			}
		})
	}
}

func TestProbeFallsBackToGETWhenHEADIsRefused(t *testing.T) {
	for _, refusal := range []int{http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(strconv.Itoa(refusal), func(t *testing.T) {
			var methods []string
			var ranges []string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				if r.Method == http.MethodHead {
					w.WriteHeader(refusal)
					return
				}
				ranges = append(ranges, r.Header.Get("Range"))
				w.WriteHeader(http.StatusPartialContent)
				fmt.Fprint(w, "x")
			}))
			defer server.Close()

			check := probeLink(t, newProbingTestAnalyzer(5*time.Second), server.URL)

			if check.Status != http.StatusPartialContent {
				t.Errorf("Status = %d, want 206 from the GET", check.Status)
			}
			if len(check.HTTPFindings) != 0 {
				t.Errorf("HTTPFindings = %v, want none: the page answers, it merely refuses HEAD", findingKinds(check.HTTPFindings))
			}
			if want := []string{http.MethodHead, http.MethodGet}; !slices.Equal(methods, want) {
				t.Errorf("methods = %v, want %v", methods, want)
			}
			// The probe wants the status line, not the document.
			if want := []string{"bytes=0-0"}; !slices.Equal(ranges, want) {
				t.Errorf("Range headers = %v, want %v", ranges, want)
			}
		})
	}
}

func TestProbeKeepsProtectedWhenGETIsRefusedToo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	check := probeLink(t, newProbingTestAnalyzer(5*time.Second), server.URL)

	if !check.hasFinding(LinkHTTPProtected) {
		t.Errorf("HTTPFindings = %v, want the link reported as protected", findingKinds(check.HTTPFindings))
	}
}

func TestProbeLeavesTransportFailuresAsWarnings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := server.URL
	server.Close()

	check := probeLink(t, newProbingTestAnalyzer(2*time.Second), closedURL)

	// Not reaching a server from here says nothing about the message: the
	// sender must not be charged for it.
	if !check.Valid {
		t.Error("Valid = false, want true: an unreachable server is not the sender's doing")
	}
	if check.Status != 0 {
		t.Errorf("Status = %d, want 0", check.Status)
	}
	if check.Warning == "" {
		t.Error("Warning is empty, want the failure reported as unverifiable")
	}
	if len(check.HTTPFindings) != 0 {
		t.Errorf("HTTPFindings = %v, want none", findingKinds(check.HTTPFindings))
	}
}

func TestAnalyzeContentFetchesEachURLOnce(t *testing.T) {
	var hits atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	body := strings.Repeat(fmt.Sprintf(`<a href="%s">Same link</a>`, server.URL), 5) +
		fmt.Sprintf(`<img src="%s" alt="Same URL again">`, server.URL)

	results := newProbingTestAnalyzer(5 * time.Second).Analyze(&mailmsg.Message{
		Header: make(mail.Header),
		Parts: []mailmsg.Part{{
			ContentType: "text/html",
			IsHTML:      true,
			Content:     "<html><body>" + body + "</body></html>",
		}},
	})

	if got := hits.Load(); got != 1 {
		t.Errorf("server was hit %d times, want 1: one URL is one request", got)
	}
	// Deduplication happens on the wire, not in the report: every occurrence is
	// still reported.
	if len(results.Links) != 5 {
		t.Errorf("len(Links) = %d, want 5", len(results.Links))
	}
	for i, link := range results.Links {
		if link.Status != http.StatusOK {
			t.Errorf("Links[%d].Status = %d, want 200 on every occurrence", i, link.Status)
		}
	}
}

func TestAnalyzeContentReportsBrokenImages(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/missing.png", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	analyzer := newProbingTestAnalyzer(5 * time.Second)
	results := analyzer.Analyze(&mailmsg.Message{
		Header: make(mail.Header),
		Parts: []mailmsg.Part{{
			ContentType: "text/html",
			IsHTML:      true,
			Content: fmt.Sprintf(`<html><body>
				<img src="%s/missing.png" alt="Gone">
				<img src="%s/logo.png" alt="Fine">
				<img src="cid:inline@example.org" alt="Attached">
				<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="Inline">
			</body></html>`, server.URL, server.URL),
		}},
	})

	if len(results.Images) != 4 {
		t.Fatalf("len(Images) = %d, want 4", len(results.Images))
	}

	broken, fine, attached, inline := results.Images[0], results.Images[1], results.Images[2], results.Images[3]

	if !broken.IsBroken {
		t.Error("the 404 image is not marked broken")
	}
	if !slices.Contains(findingKinds(broken.HTTPFindings), LinkHTTPNotFound) {
		t.Errorf("HTTPFindings = %v, want not_found", findingKinds(broken.HTTPFindings))
	}
	if !strings.HasPrefix(broken.HTTPFindings[0].Message, "Image") {
		t.Errorf("Message = %q, want it to open on what the URL was found as", broken.HTTPFindings[0].Message)
	}
	if fine.IsBroken || len(fine.HTTPFindings) != 0 {
		t.Errorf("the 200 image is reported as broken: %v", findingKinds(fine.HTTPFindings))
	}
	// An attached or inlined image designates no destination to fetch.
	if attached.Status != 0 || inline.Status != 0 {
		t.Errorf("cid:/data: images were fetched (status %d and %d)", attached.Status, inline.Status)
	}

	analysis := analyzer.analysisOf(results)
	if !slices.ContainsFunc(*analysis.HtmlIssues, func(i model.ContentIssue) bool {
		return i.Type == model.ContentIssueTypeUnreachableLink && i.Location != nil && strings.HasSuffix(*i.Location, "/missing.png")
	}) {
		t.Error("no unreachable_link issue was raised for the broken image")
	}

	// The verdict has to reach the report, not just the analysis: an image that
	// does not load is what the recipient sees first.
	apiImages := *analysis.Images
	if apiImages[0].IsBroken == nil || !*apiImages[0].IsBroken {
		t.Errorf("the 404 image is reported as is_broken = %v", apiImages[0].IsBroken)
	}
	if apiImages[0].HttpCode == nil || *apiImages[0].HttpCode != http.StatusNotFound {
		t.Errorf("http_code = %v, want 404", apiImages[0].HttpCode)
	}
	if apiImages[1].IsBroken == nil || *apiImages[1].IsBroken {
		t.Errorf("the 200 image is reported as is_broken = %v", apiImages[1].IsBroken)
	}
	// Nothing was ever fetched for an attached or inlined image, so the report
	// must not claim it is fine any more than that it is broken.
	if apiImages[2].IsBroken != nil || apiImages[3].IsBroken != nil {
		t.Error("cid:/data: images carry an is_broken verdict, though they were never fetched")
	}
}

func TestAnalyzeContentChecksListUnsubscribeURLs(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantFinding bool
	}{
		{name: "a gone endpoint is reported", status: http.StatusNotFound, wantFinding: true},
		// RFC 8058 has the endpoint accept a POST; refusing the HEAD this probe
		// sends says nothing about whether a recipient can unsubscribe.
		{name: "a POST-only endpoint is left alone", status: http.StatusMethodNotAllowed, wantFinding: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var methods []string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			header := make(mail.Header)
			header["List-Unsubscribe"] = []string{"<" + server.URL + "/unsub>"}

			analyzer := newProbingTestAnalyzer(5 * time.Second)
			results := analyzer.Analyze(&mailmsg.Message{
				Header: header,
				Parts: []mailmsg.Part{{
					ContentType: "text/html",
					IsHTML:      true,
					Content:     "<html><body><p>Newsletter</p></body></html>",
				}},
			})

			if len(results.UnsubscribeChecks) != 1 {
				t.Fatalf("len(UnsubscribeChecks) = %d, want 1", len(results.UnsubscribeChecks))
			}

			// Probing an unsubscribe endpoint must never carry out the
			// unsubscription: no GET fallback, and no POST, ever.
			for _, method := range methods {
				if method != http.MethodHead {
					t.Errorf("the endpoint received a %s; only HEAD is safe here", method)
				}
			}

			findings := results.UnsubscribeChecks[0].HTTPFindings
			if tt.wantFinding {
				if !slices.Contains(findingKinds(findings), LinkHTTPNotFound) {
					t.Fatalf("HTTPFindings = %v, want not_found", findingKinds(findings))
				}
				if findings[0].Severity != model.ContentIssueSeverityHigh {
					t.Errorf("Severity = %q, want high", findings[0].Severity)
				}
				analysis := analyzer.analysisOf(results)
				if !slices.ContainsFunc(*analysis.HtmlIssues, func(i model.ContentIssue) bool {
					return i.Type == model.ContentIssueTypeUnreachableLink
				}) {
					t.Error("the dead unsubscribe endpoint raised no issue")
				}
			} else if len(findings) != 0 {
				t.Errorf("HTTPFindings = %v, want none", findingKinds(findings))
			}
		})
	}
}

func TestRedirectDowngradeSuspicion(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		chain []string
		want  bool
	}{
		{
			name:  "an https link handed over to http is reported",
			url:   "https://example.com/offer",
			chain: []string{"https://tracker.example.net/r/1", "http://example.org/landing"},
			want:  true,
		},
		{
			name:  "a chain that stays on https is not",
			url:   "https://example.com/offer",
			chain: []string{"https://www.example.com/offer"},
			want:  false,
		},
		{
			// The static suspicion already reports it; saying it twice would
			// charge the sender twice for one mistake.
			name:  "a link already written in http is not reported again",
			url:   "http://example.com/offer",
			chain: []string{"http://www.example.com/offer"},
			want:  false,
		},
		{
			name:  "a link with no redirection has nothing to downgrade",
			url:   "https://example.com/offer",
			chain: nil,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suspicion := redirectDowngradeSuspicion(tt.url, tt.chain)

			if (suspicion != nil) != tt.want {
				t.Fatalf("redirectDowngradeSuspicion() = %v, want reported: %t", suspicion, tt.want)
			}
			if suspicion == nil {
				return
			}
			if suspicion.Kind != URLSuspicionInsecureScheme {
				t.Errorf("Kind = %q, want %q", suspicion.Kind, URLSuspicionInsecureScheme)
			}
			if !strings.HasPrefix(suspicion.Message, "Redirect target") {
				t.Errorf("Message = %q, want it to name the redirection", suspicion.Message)
			}
		})
	}
}

func TestGenerateContentAnalysisReportsHTTPFindings(t *testing.T) {
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	deadURL := "https://example.com/gone"
	notFound, _ := httpStatusFinding("Link", http.StatusNotFound)

	results := &Results{
		HTMLContent: "<html><body></body></html>",
		Links: []LinkCheck{
			{
				URL: deadURL, Valid: true, IsSafe: true,
				probedURL: probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
			},
			{
				URL: "https://example.com/moved", Valid: true, IsSafe: true,
				probedURL: probedURL{
					Status: 200,
					RedirectChain: []string{
						"https://t.example.net/1", "https://t.example.net/2", "https://www.example.com/moved",
					},
					FinalURL: "https://www.example.com/moved",
				},
			},
			{
				URL: "https://example.com/www", Valid: true, IsSafe: true,
				probedURL: probedURL{
					Status:        200,
					RedirectChain: []string{"https://www.example.com/www"},
					FinalURL:      "https://www.example.com/www",
				},
			},
		},
	}

	analysis := analyzer.analysisOf(results)

	issues := *analysis.HtmlIssues
	if len(issues) != 1 {
		t.Fatalf("HtmlIssues = %+v, want exactly one", issues)
	}
	if issues[0].Type != model.ContentIssueTypeUnreachableLink {
		t.Errorf("Type = %q, want %q", issues[0].Type, model.ContentIssueTypeUnreachableLink)
	}
	if issues[0].Location == nil || *issues[0].Location != deadURL {
		t.Errorf("Location = %v, want %q", issues[0].Location, deadURL)
	}

	links := *analysis.Links
	if links[0].Status != model.LinkCheckStatusBroken {
		t.Errorf("the 404 link is %q, want %q", links[0].Status, model.LinkCheckStatusBroken)
	}
	// A link that answers, but only after a detour, is neither broken nor
	// suspicious: the chain is what the report has to show.
	if links[1].Status != model.LinkCheckStatusRedirected {
		t.Errorf("the redirected link is %q, want %q", links[1].Status, model.LinkCheckStatusRedirected)
	}
	if links[1].RedirectChain == nil || len(*links[1].RedirectChain) != 3 {
		t.Errorf("RedirectChain = %v, want the three hops it walked", links[1].RedirectChain)
	}
	// Where the chain ends is the one thing about it worth reading first.
	if links[1].FinalUrl == nil || *links[1].FinalUrl != "https://www.example.com/moved" {
		t.Errorf("FinalUrl = %v, want the end of the chain", links[1].FinalUrl)
	}
	// A single hop is how the ordinary web works: the chain is still reported,
	// but the status stays valid, or the label would be on half the links of
	// every message and mean nothing.
	if links[2].Status != model.LinkCheckStatusValid {
		t.Errorf("the one-hop link is %q, want %q", links[2].Status, model.LinkCheckStatusValid)
	}
	if links[2].RedirectChain == nil {
		t.Error("RedirectChain is empty on the one-hop link, want it reported all the same")
	}
}

// TestHTTPFindingsAnswerTheirRole covers the one place the probe check departs
// from its own category: what a URL that does not answer costs a reader
// depends on what the URL was found as.
//
// A dead image leaves a hole the recipient sees the moment the message opens,
// which is a matter of rendering. A dead link and a dead unsubscribe address
// cost a destination, not a rendering, and stay with the deliverability
// findings. A chain that merely ends late is reached after all, so the image
// does render and it stays there too.
func TestHTTPFindingsAnswerTheirRole(t *testing.T) {
	dead, _ := httpStatusFinding("Image", http.StatusNotFound)
	late, _ := redirectChainFinding("Image", []string{"a", "b", "c"}, "https://example.com/end")

	for _, tc := range []struct {
		name    string
		finding LinkHTTPFinding
		role    urlRole
		want    reading.Category
	}{
		{"a dead image", dead, urlRoleImage, reading.CategoryRendering},
		{"a dead link", dead, urlRoleLink, ""},
		{"a dead unsubscribe address", dead, urlRoleUnsubscribe, ""},
		{"an image reached late", late, urlRoleImage, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issue := httpFindingIssue("https://example.com/thing", tc.role, tc.finding)
			if issue.Category != tc.want {
				t.Errorf("Category = %q, want %q", issue.Category, tc.want)
			}
		})
	}
}

// And the whole way through: a dead image source reaches the report filed
// under rendering, the check's own deliverability notwithstanding.
func TestGenerateContentAnalysisFilesADeadImageUnderRendering(t *testing.T) {
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	notFound, _ := httpStatusFinding("Image", http.StatusNotFound)

	analysis := analyzer.analysisOf(&Results{
		HTMLContent: "<html><body></body></html>",
		Images: []ImageCheck{{
			Src: "https://example.com/logo.png", HasAlt: true,
			probedURL: probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
		}},
	})

	issues := *analysis.HtmlIssues
	if len(issues) != 1 {
		t.Fatalf("HtmlIssues = %+v, want exactly one", issues)
	}
	if issues[0].Category != reading.CategoryRendering {
		t.Errorf("Category = %q, want %q", issues[0].Category, reading.CategoryRendering)
	}
}

func TestGenerateContentAnalysisFilesRedirectFindingsApart(t *testing.T) {
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	excessive, _ := redirectChainFinding("Link", []string{"a", "b", "c"}, "https://example.com/end")

	analysis := analyzer.analysisOf(&Results{
		HTMLContent: "<html><body></body></html>",
		Links: []LinkCheck{{
			URL: "https://example.com/start", Valid: true, IsSafe: true,
			probedURL: probedURL{
				Status:        200,
				RedirectChain: []string{"a", "b", "c"},
				HTTPFindings:  []LinkHTTPFinding{excessive},
			},
		}},
	})

	issues := *analysis.HtmlIssues
	if len(issues) != 1 || issues[0].Type != model.ContentIssueTypeExcessiveRedirects {
		t.Errorf("HtmlIssues = %+v, want a single excessive_redirects issue", issues)
	}
}

func TestCalculateContentScorePenalizesHTTPFindings(t *testing.T) {
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	base := func(findings []LinkHTTPFinding, status int) *Results {
		return &Results{
			HTMLValid:       true,
			HTMLContent:     "<html><body><p>Newsletter</p></body></html>",
			TextContent:     "Newsletter",
			TextAlternative: textAltOK,
			Links: []LinkCheck{
				{URL: "https://example.com/a", Valid: true, IsSafe: true, probedURL: probedURL{Status: 200}},
				{
					URL: "https://example.com/b", Valid: true, IsSafe: true,
					probedURL: probedURL{Status: status, HTTPFindings: findings},
				},
			},
		}
	}

	notFound, _ := httpStatusFinding("Link", http.StatusNotFound)

	clean, _ := analyzer.scoreOf(base(nil, 200))
	dead, _ := analyzer.scoreOf(base([]LinkHTTPFinding{notFound}, 404))

	// Ten points for the link that no longer counts among the working ones,
	// and nothing else: the links criterion is the one that grades a dead body
	// link, so the finding that names it deducts nothing on top. One defect,
	// one payer.
	if want := clean - 10; dead != want {
		t.Errorf("score with a dead link = %d, want %d (clean score is %d)", dead, want, clean)
	}

	loop := LinkHTTPFinding{Kind: LinkHTTPRedirectLoop, Severity: model.ContentIssueSeverityHigh}
	looping, _ := analyzer.scoreOf(base([]LinkHTTPFinding{loop}, 0))

	// A link that never arrives carries no status code, and must still count as
	// broken rather than as one of the working links.
	if want := clean - 10; looping != want {
		t.Errorf("score with a looping link = %d, want %d (clean score is %d)", looping, want, clean)
	}

	// A chain that does end is the one no criterion grades: the link answers,
	// so it counts among the working ones, and the detour answers under the
	// probe cap instead.
	excessive, _ := redirectChainFinding("Link", []string{"a", "b", "c"}, "https://example.com/end")
	detoured, _ := analyzer.scoreOf(base([]LinkHTTPFinding{excessive}, 200))

	if want := clean - reading.SeverityPenalty(excessive.Severity); detoured != want {
		t.Errorf("score with a detoured link = %d, want %d (clean score is %d)", detoured, want, clean)
	}
}

func TestCalculateContentScoreKeepsPenaltyBudgetsApart(t *testing.T) {
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	// Enough of each to blow through both caps on its own.
	var suspicions []URLSuspicion
	var findings []LinkHTTPFinding
	for range 10 {
		suspicions = append(suspicions, URLSuspicion{Severity: model.ContentIssueSeverityHigh})
		// Redirect chains, being the probe findings no criterion grades: what
		// this test weighs is the probe cap, so it must be a defect that
		// actually answers under it.
		findings = append(findings, LinkHTTPFinding{Kind: LinkHTTPExcessiveRedirects, Severity: model.ContentIssueSeverityHigh})
	}

	// One message per score: results are the finished record of one analysis,
	// read as often as needed but never rewritten between two readings.
	message := func(suspicions []URLSuspicion) *Results {
		return &Results{
			HTMLValid:       true,
			HTMLContent:     "<html><body><p>Newsletter</p></body></html>",
			TextContent:     "Newsletter",
			TextAlternative: textAltOK,
			Links: []LinkCheck{{
				URL: "https://example.com/a", Valid: true, Suspicions: suspicions,
				probedURL: probedURL{Status: 200, HTTPFindings: findings},
			}},
		}
	}

	both, _ := analyzer.scoreOf(message(suspicions))
	onlyHTTP, _ := analyzer.scoreOf(message(nil))

	if both >= onlyHTTP {
		t.Errorf("score with both defects = %d, want it below the score with findings alone (%d): the two caps are independent", both, onlyHTTP)
	}
}

func TestProbeRefusesPrivateTargets(t *testing.T) {
	// The analyzer fetches URLs a stranger chose, from inside whatever network
	// it runs in, and hands the status code back in the report. Without this
	// refusal it is a port scanner operated by whoever sends the message.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a loopback address was reached: the guard let a private target through")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	targets := []struct {
		name string
		url  string
	}{
		{name: "loopback", url: server.URL},
		{name: "link-local cloud metadata", url: "http://169.254.169.254/latest/meta-data/"},
		{name: "private range", url: "http://10.0.0.1/"},
		{name: "unique-local IPv6", url: "http://[fd00::1]/"},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			check := probeLink(t, NewAnalyzer(2*time.Second), target.url)

			if check.Status != 0 {
				t.Errorf("Status = %d, want 0: the address must never be dialed", check.Status)
			}
			// The refusal is ours, not the sender's: it is reported as a link
			// that could not be verified, never as a dead one.
			if check.Warning == "" {
				t.Error("Warning is empty, want the refusal reported")
			}
			if len(check.HTTPFindings) != 0 {
				t.Errorf("HTTPFindings = %v, want none", findingKinds(check.HTTPFindings))
			}
		})
	}
}

func TestProbeRefusesPrivateTargetsBehindAName(t *testing.T) {
	// A hostname is not a promise about what it resolves to, so the check has
	// to sit on the address dialed rather than on the URL. localhost is the one
	// name every machine resolves to a loopback address.
	check := probeLink(t, NewAnalyzer(2*time.Second), "http://localhost:6379/")

	if check.Status != 0 {
		t.Errorf("Status = %d, want 0: a name resolving to a loopback address must be refused too", check.Status)
	}
}

func TestProbeRefusesPrivateTargetsAcrossARedirect(t *testing.T) {
	// A public URL that redirects inward is the same attack with one more hop,
	// which is why the check is on the dial: every hop opens its own connection.
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirection reached a loopback address")
	}))
	defer private.Close()

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, private.URL+"/internal", http.StatusFound)
	}))
	defer public.Close()

	// The first hop is itself a loopback address, so the analyzer is allowed
	// the one it is told to reach and refuses the next on its own.
	analyzer := NewAnalyzer(2 * time.Second)
	analyzer.prober.UseTransport(onlyAllowHost(t, public.Listener.Addr().String()))

	check := probeLink(t, analyzer, public.URL)

	if check.Status != 0 {
		t.Errorf("Status = %d, want 0: the redirection must not be followed inward", check.Status)
	}
}

// onlyAllowHost builds a transport that refuses every address but one, standing
// in for "the first hop is public, the next is not".
func onlyAllowHost(t *testing.T, allowed string) *http.Transport {
	t.Helper()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != allowed {
			return nil, urlprobe.ErrPrivateTarget
		}
		return dialer.DialContext(ctx, network, address)
	}

	return transport
}

func TestProbeRetriesWithoutRangeWhenRefused(t *testing.T) {
	// A server may refuse the byte range rather than the document. The page is
	// alive, and must not be reported as a dead link.
	var ranges []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ranges = append(ranges, r.Header.Get("Range"))
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "the whole page")
	}))
	defer server.Close()

	check := probeLink(t, newProbingTestAnalyzer(5*time.Second), server.URL)

	if check.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200: the range was refused, not the page", check.Status)
	}
	if len(check.HTTPFindings) != 0 {
		t.Errorf("HTTPFindings = %v, want none", findingKinds(check.HTTPFindings))
	}
	if want := []string{"bytes=0-0", ""}; !slices.Equal(ranges, want) {
		t.Errorf("Range headers = %v, want %v", ranges, want)
	}
}

func TestAnalyzeContentCapsTheURLsItFetches(t *testing.T) {
	var hits atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var body strings.Builder
	for i := range urlprobe.MaxURLs + 20 {
		fmt.Fprintf(&body, `<a href="%s/%d">Link %d</a>`, server.URL, i, i)
	}

	analyzer := newProbingTestAnalyzer(5 * time.Second)
	results := analyzer.Analyze(&mailmsg.Message{
		Header: make(mail.Header),
		Parts: []mailmsg.Part{{
			ContentType: "text/html",
			IsHTML:      true,
			Content:     "<html><body>" + body.String() + "</body></html>",
		}},
	})

	if got := hits.Load(); got != urlprobe.MaxURLs {
		t.Errorf("server was hit %d times, want %d", got, urlprobe.MaxURLs)
	}
	if results.UnprobedURLs != 20 {
		t.Errorf("UnprobedURLs = %d, want 20", results.UnprobedURLs)
	}

	// What was left out has to be said, not passed off as checked.
	analysis := analyzer.analysisOf(results)
	if !slices.ContainsFunc(*analysis.HtmlIssues, func(i model.ContentIssue) bool {
		return i.Severity == model.ContentIssueSeverityInfo && strings.Contains(i.Message, "left unchecked")
	}) {
		t.Error("the URLs left unfetched were not reported")
	}
}

func TestRepeatedURLIsReportedOnce(t *testing.T) {
	// One URL is one fetch, hence one verdict: a footer link repeated across a
	// newsletter must not fill the report with the same issue five times, nor
	// be charged five times against the score.
	analyzer := newProbingTestAnalyzer(5 * time.Second)

	deadURL := "https://example.com/gone"
	notFound, _ := httpStatusFinding("Link", http.StatusNotFound)
	dead := LinkCheck{
		URL: deadURL, Valid: true, IsSafe: true,
		probedURL: probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
	}

	results := &Results{
		HTMLValid:       true,
		HTMLContent:     "<html><body><p>Newsletter</p></body></html>",
		TextContent:     "Newsletter",
		TextAlternative: textAltOK,
		Links:           []LinkCheck{dead, dead, dead, dead, dead},
		// The same URL used as an image source is still the same URL.
		Images: []ImageCheck{{
			Src: deadURL, HasAlt: true, AltText: "Gone", Valid: true,
			probedURL: probedURL{Status: 404, HTTPFindings: []LinkHTTPFinding{notFound}},
		}},
	}

	issues := *analyzer.analysisOf(results).HtmlIssues
	unreachable := 0
	for _, issue := range issues {
		if issue.Type == model.ContentIssueTypeUnreachableLink {
			unreachable++
		}
	}
	if unreachable != 1 {
		t.Errorf("the same dead URL raised %d issues, want 1", unreachable)
	}

	single := *results
	single.Links = []LinkCheck{dead}
	single.Images = nil

	repeated, _ := analyzer.scoreOf(results)
	once, _ := analyzer.scoreOf(&single)

	// The links block still counts every occurrence: five dead links out of
	// five is a worse message than one, but the finding is charged once.
	if repeated > once {
		t.Errorf("score with the URL repeated = %d, want no better than %d", repeated, once)
	}
}
