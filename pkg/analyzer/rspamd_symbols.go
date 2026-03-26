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
	_ "embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed rspamd-symbols.json
var embeddedRspamdSymbols []byte

// rspamdSymbolGroup represents a group of rspamd symbols from the API/embedded JSON.
type rspamdSymbolGroup struct {
	Group string              `json:"group"`
	Rules []rspamdSymbolEntry `json:"rules"`
}

// rspamdSymbolEntry represents a single rspamd symbol entry.
type rspamdSymbolEntry struct {
	Symbol      string  `json:"symbol"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
}

// parseRspamdSymbolsJSON parses the rspamd symbols JSON into a name->description map.
func parseRspamdSymbolsJSON(data []byte) map[string]string {
	var groups []rspamdSymbolGroup
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

// LoadRspamdSymbols loads rspamd symbol descriptions.
// If apiURL is non-empty, it fetches from the rspamd API first, falling back to the embedded list on error.
func LoadRspamdSymbols(apiURL string) map[string]string {
	if apiURL != "" {
		if symbols := fetchRspamdSymbols(apiURL); symbols != nil {
			return symbols
		}
		log.Printf("Failed to fetch rspamd symbols from %s, using embedded list", apiURL)
	}
	return parseRspamdSymbolsJSON(embeddedRspamdSymbols)
}

// fetchRspamdSymbols fetches symbol descriptions from the rspamd API.
func fetchRspamdSymbols(apiURL string) map[string]string {
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

	return parseRspamdSymbolsJSON(body)
}
