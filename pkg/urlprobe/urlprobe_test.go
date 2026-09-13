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
