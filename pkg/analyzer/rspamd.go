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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// Default rspamd action thresholds (rspamd built-in defaults)
const (
	rspamdDefaultRejectThreshold    float32 = 15
	rspamdDefaultAddHeaderThreshold float32 = 6
)

// rspamd's SpamAssassin-shaped status header, e.g.
// "No, rspamdscore=-4.78, required=10.00".
var rspamdStatusScoreRe = regexp.MustCompile(`(?i)rspamdscore=(-?\d+\.?\d*)`)

// X-Spamd-Result: the "[score / threshold]" verdict of its first line, and the
// "SYMBOL(score)[params]" entries that follow.
var (
	rspamdResultScoreRe  = regexp.MustCompile(`\[\s*(-?\d+\.?\d*)\s*/\s*(-?\d+\.?\d*)\s*\]`)
	rspamdResultSymbolRe = regexp.MustCompile(`(\w+)\((-?\d+\.?\d*)\)(?:\[(.*)\])?`)
)

// RspamdAnalyzer analyzes rspamd results from email headers
type RspamdAnalyzer struct {
	symbols map[string]string
}

// NewRspamdAnalyzer creates a new rspamd analyzer with optional symbol descriptions
func NewRspamdAnalyzer(symbols map[string]string) *RspamdAnalyzer {
	return &RspamdAnalyzer{symbols: symbols}
}

// effectiveThreshold returns the threshold to score a message against: the one
// rspamd reported, or its add-header default when it reported none. Only the
// reported one is published, so that a client can tell a threshold this
// instance actually uses from a default stood in for it.
func effectiveThreshold(result *model.RspamdResult) float32 {
	if result.Threshold != nil {
		return *result.Threshold
	}
	return rspamdDefaultAddHeaderThreshold
}

// AnalyzeRspamd analyzes the headers SpamScannerHeaders attributed to rspamd
func (a *RspamdAnalyzer) AnalyzeRspamd(headers ScannerHeaders) *model.RspamdResult {
	// A bare X-Spam or a server stamp identifies rspamd but says nothing about
	// the message: require a header carrying a verdict to produce a report.
	if !headers.Has("X-Spamd-Result", "X-Rspamd-Score", "X-Spam-Status", "X-Spam-Score", "X-Spam-Flag") {
		return nil
	}

	result := &model.RspamdResult{
		Symbols: make(map[string]model.SpamTestDetail),
	}

	var hasScore bool

	// Parse X-Spamd-Result header (primary source for score, threshold, and symbols)
	// Format: "default: False [-3.91 / 15.00];\n\tSYMBOL(score)[params]; ..."
	if spamdResult, ok := headers["X-Spamd-Result"]; ok {
		report := strings.ReplaceAll(spamdResult, "; ", ";\n")
		result.Report = &report
		hasScore = a.parseSpamdResult(spamdResult, result)
	}

	// rspamd's X-Spam-Status variant carries no symbols, only the score and the
	// threshold: fall back to it only for what X-Spamd-Result didn't supply.
	if statusHeader, ok := headers["X-Spam-Status"]; ok && (!hasScore || result.Threshold == nil) {
		hasScore = a.parseSpamStatus(statusHeader, result) || hasScore
	}

	// Parse X-Rspamd-Score as override/fallback for score
	if scoreHeader, ok := headers["X-Rspamd-Score"]; ok {
		if score, ok := parseFloat32(scoreHeader); ok {
			result.Score = score
			hasScore = true
		}
	}

	// rspamd's milter_headers also writes SpamAssassin's names, sometimes as the
	// only verdict on the message: fill in what its own headers left out.
	shared := readSharedSpamVerdict(headers)
	if !hasScore && shared.hasScore {
		result.Score = shared.score
		hasScore = true
	}

	// Parse X-Rspamd-Action: what rspamd did with the message
	if actionHeader, ok := headers["X-Rspamd-Action"]; ok {
		if action := strings.TrimSpace(actionHeader); action != "" {
			result.Action = &action
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

	// Derive IsSpam from score vs threshold. Without a score anywhere, the
	// X-Spam-Flag verdict is all there is to go on.
	switch {
	case hasScore:
		result.IsSpam = result.Score >= effectiveThreshold(result)
	case shared.hasVerdict:
		result.IsSpam = shared.isSpam
	}

	return result
}

// parseSpamStatus parses rspamd's X-Spam-Status header
// Format: "No, rspamdscore=-4.78, required=10.00"
// It reports whether the header carried a score.
func (a *RspamdAnalyzer) parseSpamStatus(header string, result *model.RspamdResult) (hasScore bool) {
	if score, ok := extractFloatField(header, rspamdStatusScoreRe); ok {
		result.Score = score
		hasScore = true
	}

	// A non-positive threshold says nothing (rspamd writes "required=0.00" when
	// it has no reject action configured): leave it unreported.
	if threshold, ok := extractFloatField(header, spamStatusRequiredRe); ok && threshold > 0 {
		result.Threshold = utils.PtrTo(threshold)
	}

	return hasScore
}

// parseSpamdResult parses the X-Spamd-Result header
// Format: "default: False [-3.91 / 15.00];\n\tSYMBOL(score)[params]; ..."
// It reports whether the header carried a score.
func (a *RspamdAnalyzer) parseSpamdResult(header string, result *model.RspamdResult) (hasScore bool) {
	// Extract score and threshold from the first line
	// e.g. "default: False [-3.91 / 15.00]"
	if matches := rspamdResultScoreRe.FindStringSubmatch(header); len(matches) > 2 {
		if score, ok := parseFloat32(matches[1]); ok {
			result.Score = score
			hasScore = true
		}
		// Same as in parseSpamStatus: a non-positive threshold is not one.
		if threshold, ok := parseFloat32(matches[2]); ok && threshold > 0 {
			result.Threshold = utils.PtrTo(threshold)
		}
	}

	// Parse is_spam from header (before we may get action from X-Rspamd-Action)
	firstLine, _, _ := strings.Cut(header, ";")
	if strings.Contains(firstLine, ": True") || strings.Contains(firstLine, ": true") {
		result.IsSpam = true
	}

	// Parse symbols: SYMBOL(score)[params]
	// Each symbol entry is separated by ";", so within each part we use a
	// greedy match to capture params that may contain nested brackets.
	for part := range strings.SplitSeq(header, ";") {
		part = strings.TrimSpace(part)
		matches := rspamdResultSymbolRe.FindStringSubmatch(part)
		if len(matches) > 2 {
			name := matches[1]
			score, _ := parseFloat32(matches[2])
			sym := model.SpamTestDetail{
				Name:  name,
				Score: score,
			}
			if len(matches) > 3 && matches[3] != "" {
				params := matches[3]
				sym.Params = &params
			}
			result.Symbols[name] = sym
		}
	}

	return hasScore
}

// CalculateRspamdScore calculates the rspamd contribution to deliverability
// (0-100 scale). The action rspamd took decides the band, the score where in
// it the message stands: see spamBand.
func (a *RspamdAnalyzer) CalculateRspamdScore(result *model.RspamdResult) (int, string) {
	if result == nil {
		return 100, "" // rspamd not installed
	}

	score := float64(result.Score)
	reject, addHeader := rspamdGradingThresholds(result)

	switch rspamdEffectiveAction(result, reject, addHeader) {
	case "reject", "soft reject", "discard", "quarantine":
		return spamBandF.at(score, reject, spamAbusiveFactor*reject)
	case "add header", "rewrite subject":
		return spamBandE.at(score, addHeader, reject)
	case "greylist":
		return spamBandD.at(score/addHeader, spamNearFraction, 1)
	default:
		return gradeAcceptedSpamScore(score, addHeader)
	}
}

// rspamdGradingThresholds returns the scores at which rspamd rejects a message
// and marks it as spam. The threshold rspamd reports is its reject one; the
// add-header one is never reported, so its default stands in, capped by the
// reported reject threshold.
func rspamdGradingThresholds(result *model.RspamdResult) (reject, addHeader float64) {
	reject = float64(rspamdDefaultRejectThreshold)
	if result.Threshold != nil {
		reject = float64(*result.Threshold)
	}
	addHeader = math.Min(float64(rspamdDefaultAddHeaderThreshold), reject)
	return
}

// rspamdEffectiveAction returns the action rspamd announced in X-Rspamd-Action,
// or, when it announced none, the one its score calls for.
func rspamdEffectiveAction(result *model.RspamdResult, reject, addHeader float64) string {
	if result.Action != nil {
		switch action := strings.ToLower(strings.TrimSpace(*result.Action)); action {
		case "no action", "greylist", "add header", "rewrite subject", "soft reject", "reject", "discard", "quarantine":
			return action
		}
	}

	switch score := float64(result.Score); {
	case score >= reject:
		return "reject"
	case score >= addHeader:
		return "add header"
	default:
		return "no action"
	}
}
