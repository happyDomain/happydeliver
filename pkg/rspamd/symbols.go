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

package rspamd

import (
	_ "embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed data/rspamd-symbols.json
var embedded []byte

// License is the Apache-2.0 text rspamd publishes, shipped alongside the
// descriptions so that binary-only recipients of happyDeliver (a release
// artifact, a container image) get the copy section 4(a) asks to be given.
//
//go:embed data/rspamd.LICENSE
var License string

// Attribution is the credit Apache-2.0 section 4(c) asks to be retained.
const Attribution = `rspamd symbol descriptions
--------------------------

Copyright (c) Vsevolod Stakhov <vsevolod@rspamd.com> and the rspamd
         contributors
Source:  https://github.com/rspamd/rspamd, read from the /symbols endpoint of
         a running instance
License: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0
Changes: none, each description is embedded exactly as rspamd publishes it.
         How much a symbol weighs on a report, and what happyDeliver advises a
         sender to do about it, live in its own source code, not in these
         descriptions.`

// symbolGroup represents a group of rspamd symbols from the API/embedded JSON.
type symbolGroup struct {
	Group string        `json:"group"`
	Rules []symbolEntry `json:"rules"`
}

// symbolEntry represents a single rspamd symbol entry.
type symbolEntry struct {
	Symbol      string  `json:"symbol"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
}

// parseSymbols parses the rspamd symbols JSON into a name->description map.
func parseSymbols(data []byte) map[string]string {
	var groups []symbolGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		log.Printf("Failed to parse rspamd symbols JSON: %v", err)
		return nil
	}

	symbols := make(map[string]string, len(groups)*10)
	for _, g := range groups {
		for _, r := range g.Rules {
			if r.Description != "" {
				symbols[r.Symbol] = r.Description
			}
		}
	}
	return symbols
}

// Symbols reads the descriptions rspamd gives its symbols, keyed by symbol
// name.
// If apiURL is non-empty, it fetches from the rspamd API first, falling back to the embedded list on error.
func Symbols(apiURL string) map[string]string {
	if apiURL != "" {
		if symbols := fetch(apiURL); symbols != nil {
			return symbols
		}
		log.Printf("Failed to fetch rspamd symbols from %s, using embedded list", apiURL)
	}
	return parseSymbols(embedded)
}

// fetch fetches symbol descriptions from the rspamd API.
func fetch(apiURL string) map[string]string {
	url := strings.TrimRight(apiURL, "/") + "/symbols"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error fetching rspamd symbols: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("rspamd API returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading rspamd symbols response: %v", err)
		return nil
	}

	return parseSymbols(body)
}
