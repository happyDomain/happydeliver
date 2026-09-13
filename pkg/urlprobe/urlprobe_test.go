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

package urlprobe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// probe fetches one URL and returns what came back.
func probe(t *testing.T, prober *Prober, url string) Answer {
	t.Helper()

	answers := prober.Probe(context.Background(), []Request{{URL: url}})
	answer, ok := answers[url]
	if !ok {
		t.Fatalf("nothing came back for %q", url)
	}

	return answer
}

// TestProbeable says which URLs are worth a request at all: it answers on the
// scheme, an address on the web being the only thing there is to fetch.
func TestProbeable(t *testing.T) {
	tests := map[string]bool{
		"https://example.com/page":  true,
		"http://example.com/page":   true,
		"mailto:sender@example.com": false,
		"tel:+33123456789":          false,
		"data:text/plain,hello":     false,
		"/relative/path":            false,
		"http://exa mple.com/":      false,
		"":                          false,
	}

	for rawURL, want := range tests {
		if got := Probeable(rawURL); got != want {
			t.Errorf("Probeable(%q) = %v, want %v", rawURL, got, want)
		}
	}
}

// TestProbeRefusesPrivateTargets is what this package exists for: the messages
// analysed are supplied by whoever asks for the analysis, so a URL naming an
// address inside the network happyDeliver runs in must not be fetched.
//
// The refusal sits on the dial, so it holds whatever the URL looked like.
func TestProbeRefusesPrivateTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	answer := probe(t, New(2*time.Second), server.URL)

	if answer.Status != 0 {
		t.Errorf("the loopback server answered %d, want the probe to have refused to dial it", answer.Status)
	}
	if !errors.Is(answer.Err, ErrPrivateTarget) {
		t.Errorf("the probe failed with %v, want it to name the refusal", answer.Err)
	}
}

// TestProbeAllowsPrivateTargetsWhenTold covers the seam the tests of the
// analysis rely on, without which none of them could serve a fixture.
func TestProbeAllowsPrivateTargetsWhenTold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL)

	if answer.Err != nil {
		t.Fatalf("the probe failed: %v", answer.Err)
	}
	if answer.Status != http.StatusOK {
		t.Errorf("the server answered %d, want %d", answer.Status, http.StatusOK)
	}
}

// TestProbeRecordsWhereTheChainWent pins what a caller reads a redirection off:
// the hops in the order they were walked, and the URL the chain ended at.
func TestProbeRecordsWhereTheChainWent(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, server.URL+"/middle", http.StatusFound)
		case "/middle":
			http.Redirect(w, r, server.URL+"/end", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL+"/start")

	if answer.Status != http.StatusOK {
		t.Fatalf("the chain ended on %d, want %d", answer.Status, http.StatusOK)
	}
	if len(answer.RedirectChain) != 2 {
		t.Fatalf("the chain reads %v, want the two hops it walked", answer.RedirectChain)
	}
	if answer.FinalURL != server.URL+"/end" {
		t.Errorf("the chain ended at %q, want %q", answer.FinalURL, server.URL+"/end")
	}
}

// TestProbeStopsALoop: a destination sending the request back where it came
// from never ends, so the probe gives up and says why.
func TestProbeStopsALoop(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/loop", http.StatusFound)
	}))
	defer server.Close()

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL+"/loop")

	if answer.Err == nil {
		t.Fatal("the probe followed a loop to its end, which it has none of")
	}
	if !RedirectExhausted(answer.Err) {
		t.Errorf("the probe failed with %v, want an exhausted chain", answer.Err)
	}
}

// TestProbeStopsAChainThatRunsTooLong: a chain that never loops but never
// ends either is given up on past MaxRedirects, and the hops walked are kept.
func TestProbeStopsAChainThatRunsTooLong(t *testing.T) {
	var server *httptest.Server
	hop := 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hop++
		http.Redirect(w, r, fmt.Sprintf("%s/hop/%d", server.URL, hop), http.StatusFound)
	}))
	defer server.Close()

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL+"/start")

	if !RedirectExhausted(answer.Err) {
		t.Fatalf("the probe failed with %v, want an exhausted chain", answer.Err)
	}
	if len(answer.RedirectChain) != MaxRedirects {
		t.Errorf("the chain reads %d hop(s), want the %d it walked before giving up", len(answer.RedirectChain), MaxRedirects)
	}
}

// methodsServer answers each request by what it was asked, and records the
// methods in the order they were tried.
func methodsServer(t *testing.T, answer func(r *http.Request) int) (*httptest.Server, *[]string) {
	t.Helper()

	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(answer(r))
	}))
	t.Cleanup(server.Close)

	return server, &methods
}

// TestProbeFallsBackToGET: a server refusing the HEAD itself has not said
// anything about the page, so the question is asked again the way a browser
// would.
func TestProbeFallsBackToGET(t *testing.T) {
	for _, refusal := range []int{http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(http.StatusText(refusal), func(t *testing.T) {
			server, methods := methodsServer(t, func(r *http.Request) int {
				if r.Method == http.MethodHead {
					return refusal
				}
				if r.Header.Get("Range") != "bytes=0-0" {
					t.Errorf("the GET asked for %q, want the first byte alone", r.Header.Get("Range"))
				}
				return http.StatusOK
			})

			prober := New(2 * time.Second)
			prober.AllowPrivateTargets = true

			answer := probe(t, prober, server.URL)

			if answer.Status != http.StatusOK || answer.Method != http.MethodGet {
				t.Errorf("the probe answered %d by %s, want %d by GET", answer.Status, answer.Method, http.StatusOK)
			}
			if len(*methods) != 2 {
				t.Errorf("the server was asked %v, want a HEAD then a GET", *methods)
			}
		})
	}
}

// TestProbeAsksAgainWithoutTheRange: a server refusing the byte range has the
// document, and is asked for it whole.
func TestProbeAsksAgainWithoutTheRange(t *testing.T) {
	server, methods := methodsServer(t, func(r *http.Request) int {
		switch {
		case r.Method == http.MethodHead:
			return http.StatusMethodNotAllowed
		case r.Header.Get("Range") != "":
			return http.StatusRequestedRangeNotSatisfiable
		default:
			return http.StatusOK
		}
	})

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL)

	if answer.Status != http.StatusOK {
		t.Errorf("the probe answered %d, want %d once asked without the range", answer.Status, http.StatusOK)
	}
	if len(*methods) != 3 {
		t.Errorf("the server was asked %v, want a HEAD then two GETs", *methods)
	}
}

// TestProbeKeepsTheHEADWhenTold: a GET on an unsubscribe endpoint may
// unsubscribe the recipient for real, so the refusal of the HEAD is what is
// reported.
func TestProbeKeepsTheHEADWhenTold(t *testing.T) {
	server, methods := methodsServer(t, func(*http.Request) int { return http.StatusMethodNotAllowed })

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answers := prober.Probe(context.Background(), []Request{{URL: server.URL, Opts: Options{NoGETFallback: true}}})

	answer := answers[server.URL]
	if answer.Status != http.StatusMethodNotAllowed || answer.Method != http.MethodHead {
		t.Errorf("the probe answered %d by %s, want the HEAD's refusal", answer.Status, answer.Method)
	}
	if len(*methods) != 1 {
		t.Errorf("the server was asked %v, want the HEAD alone", *methods)
	}
}

// TestProbeKeepsTheHEADWhenTheGETFailsToo: a refusal is a better answer than
// a connection that dropped.
func TestProbeKeepsTheHEADWhenTheGETFailsToo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Hang up on the GET without answering.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}))
	defer server.Close()

	prober := New(2 * time.Second)
	prober.AllowPrivateTargets = true

	answer := probe(t, prober, server.URL)

	if answer.Err != nil || answer.Status != http.StatusForbidden || answer.Method != http.MethodHead {
		t.Errorf("the probe answered %+v, want the HEAD's refusal", answer)
	}
}

// TestProbeOfAURLThatDoesNotParse: a URL naming no destination fails before
// anything is dialled.
func TestProbeOfAURLThatDoesNotParse(t *testing.T) {
	answer := probe(t, New(2*time.Second), "http://exa mple.com/")

	if answer.Err == nil || answer.Status != 0 {
		t.Errorf("the probe answered %+v, want a failure to build the request", answer)
	}
}

// TestUseTransport is the seam the analysis tests confine a probe through.
func TestUseTransport(t *testing.T) {
	prober := New(2 * time.Second)
	replaced := http.NewFileTransport(http.Dir(t.TempDir()))

	prober.UseTransport(replaced)

	if prober.client.Transport != replaced {
		t.Error("the prober still dials through its own transport")
	}
}
