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
	"math"
	"regexp"
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
)

// Default rspamd action thresholds (rspamd built-in defaults)
const (
	rspamdDefaultRejectThreshold    float32 = 15
	rspamdDefaultAddHeaderThreshold float32 = 6
)

// RspamdAnalyzer analyzes rspamd results from email headers
type RspamdAnalyzer struct {
	symbols map[string]string
}

// NewRspamdAnalyzer creates a new rspamd analyzer with optional symbol descriptions
func NewRspamdAnalyzer(symbols map[string]string) *RspamdAnalyzer {
	return &RspamdAnalyzer{symbols: symbols}
}

// AnalyzeRspamd extracts and analyzes rspamd results from email headers
func (a *RspamdAnalyzer) AnalyzeRspamd(email *EmailMessage) *model.RspamdResult {
	headers := email.GetRspamdHeaders()
	if len(headers) == 0 {
		return nil
	}

	// Require at least X-Spamd-Result or X-Rspamd-Score to produce a meaningful report
	_, hasSpamdResult := headers["X-Spamd-Result"]
	_, hasRspamdScore := headers["X-Rspamd-Score"]
	if !hasSpamdResult && !hasRspamdScore {
		return nil
	}

	result := &model.RspamdResult{
		Symbols: make(map[string]model.SpamTestDetail),
	}

	// Parse X-Spamd-Result header (primary source for score, threshold, and symbols)
	// Format: "default: False [-3.91 / 15.00];\n\tSYMBOL(score)[params]; ..."
	if spamdResult, ok := headers["X-Spamd-Result"]; ok {
		report := strings.ReplaceAll(spamdResult, "; ", ";\n")
		result.Report = &report
		a.parseSpamdResult(spamdResult, result)
	}

	// Parse X-Rspamd-Score as override/fallback for score
	if scoreHeader, ok := headers["X-Rspamd-Score"]; ok {
		if score, err := strconv.ParseFloat(strings.TrimSpace(scoreHeader), 64); err == nil {
			result.Score = float32(score)
		}
	}

	// Parse X-Rspamd-Server
	if serverHeader, ok := headers["X-Rspamd-Server"]; ok {
		server := strings.TrimSpace(serverHeader)
		result.Server = &server
	}

	// Populate symbol descriptions from the lookup map
	if a.symbols != nil {
		for name, sym := range result.Symbols {
			if desc, ok := a.symbols[name]; ok {
				sym.Description = &desc
				result.Symbols[name] = sym
			}
		}
	}

	// Derive IsSpam from score vs reject threshold.
	if result.Threshold > 0 {
		result.IsSpam = result.Score >= result.Threshold
	} else {
		result.IsSpam = result.Score >= rspamdDefaultAddHeaderThreshold
	}

	return result
}

// parseSpamdResult parses the X-Spamd-Result header
// Format: "default: False [-3.91 / 15.00];\n\tSYMBOL(score)[params]; ..."
func (a *RspamdAnalyzer) parseSpamdResult(header string, result *model.RspamdResult) {
	// Extract score and threshold from the first line
	// e.g. "default: False [-3.91 / 15.00]"
	scoreRe := regexp.MustCompile(`\[\s*(-?\d+\.?\d*)\s*/\s*(-?\d+\.?\d*)\s*\]`)
	if matches := scoreRe.FindStringSubmatch(header); len(matches) > 2 {
		if score, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.Score = float32(score)
		}
		if threshold, err := strconv.ParseFloat(matches[2], 64); err == nil {
			result.Threshold = float32(threshold)

			// No threshold? use default AddHeaderThreshold
			if result.Threshold <= 0 {
				result.Threshold = rspamdDefaultAddHeaderThreshold
			}
		}
	}

	// Parse is_spam from header (before we may get action from X-Rspamd-Action)
	firstLine := strings.SplitN(header, ";", 2)[0]
	if strings.Contains(firstLine, ": True") || strings.Contains(firstLine, ": true") {
		result.IsSpam = true
	}

	// Parse symbols: SYMBOL(score)[params]
	// Each symbol entry is separated by ";", so within each part we use a
	// greedy match to capture params that may contain nested brackets.
	symbolRe := regexp.MustCompile(`(\w+)\((-?\d+\.?\d*)\)(?:\[(.*)\])?`)
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		matches := symbolRe.FindStringSubmatch(part)
		if len(matches) > 2 {
			name := matches[1]
			score, _ := strconv.ParseFloat(matches[2], 64)
			sym := model.SpamTestDetail{
				Name:  name,
				Score: float32(score),
			}
			if len(matches) > 3 && matches[3] != "" {
				params := matches[3]
				sym.Params = &params
			}
			result.Symbols[name] = sym
		}
	}
}

// CalculateRspamdScore calculates the rspamd contribution to deliverability (0-100 scale)
func (a *RspamdAnalyzer) CalculateRspamdScore(result *model.RspamdResult) (int, string) {
	if result == nil {
		return 100, "" // rspamd not installed
	}

	threshold := result.Threshold
	percentage := 100 - int(math.Round(float64(result.Score*100/(2*threshold))))

	if percentage > 100 {
		return 100, "A+"
	} else if percentage < 0 {
		return 0, "F"
	}

	// Linear scale between 0 and threshold
	return percentage, ScoreToGrade(percentage)
}
