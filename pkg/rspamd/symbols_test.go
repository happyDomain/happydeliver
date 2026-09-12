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

package rspamd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleSymbols = `[
  {"group": "subject", "rules": [
    {"symbol": "SUBJ_ALL_CAPS", "description": "Subject contains mostly capital letters", "weight": 3.0},
    {"symbol": "UNDESCRIBED", "description": "", "weight": 1.0}
  ]},
  {"group": "empty", "rules": []}
]`

// TestParseSymbols reads the catalogue the way rspamd publishes it: grouped,
// and only the symbols that come with a description are worth keeping.
func TestParseSymbols(t *testing.T) {
	symbols := parseSymbols([]byte(sampleSymbols))

	if len(symbols) != 1 {
		t.Fatalf("read %d symbol(s), want the one described", len(symbols))
	}
	if symbols["SUBJ_ALL_CAPS"] != "Subject contains mostly capital letters" {
		t.Errorf("SUBJ_ALL_CAPS reads %q, want its description", symbols["SUBJ_ALL_CAPS"])
	}
	if _, kept := symbols["UNDESCRIBED"]; kept {
		t.Error("a symbol without a description was kept")
	}
}

func TestParseSymbolsOfSomethingElse(t *testing.T) {
	if symbols := parseSymbols([]byte("<html>not json</html>")); symbols != nil {
		t.Errorf("read %v out of a reply that is not a catalogue, want nothing", symbols)
	}
}

// TestEmbeddedSymbols holds the shipped catalogue to being readable: an
// instance without an rspamd of its own reads its descriptions from here.
func TestEmbeddedSymbols(t *testing.T) {
	symbols := Symbols("")

	if len(symbols) == 0 {
		t.Fatal("the embedded catalogue is empty")
	}
	for name, description := range symbols {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(description) == "" {
			t.Errorf("the catalogue carries the symbol %q described as %q", name, description)
		}
	}
	if License == "" || Attribution == "" {
		t.Error("the catalogue ships without its licence or attribution")
	}
}

// TestSymbolsPreferTheInstance: an rspamd that answers describes its symbols
// the way it is configured, and the embedded catalogue is for when it does
// not.
func TestSymbolsPreferTheInstance(t *testing.T) {
	asked := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Write([]byte(sampleSymbols))
	}))
	t.Cleanup(server.Close)

	symbols := Symbols(server.URL + "/")

	if asked != "/symbols" {
		t.Errorf("asked %q, want /symbols", asked)
	}
	if len(symbols) != 1 || symbols["SUBJ_ALL_CAPS"] == "" {
		t.Errorf("read %v, want the instance's own catalogue", symbols)
	}
}

func TestSymbolsFallBackOnTheEmbeddedCatalogue(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(refusing.Close)

	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(garbled.Close)

	embedded := parseSymbols(embedded)

	for name, url := range map[string]string{
		"refusing":  refusing.URL,
		"garbled":   garbled.URL,
		"not there": "http://127.0.0.1:1",
	} {
		t.Run(name, func(t *testing.T) {
			if symbols := Symbols(url); len(symbols) != len(embedded) {
				t.Errorf("read %d symbol(s), want the %d embedded ones", len(symbols), len(embedded))
			}
		})
	}
}
