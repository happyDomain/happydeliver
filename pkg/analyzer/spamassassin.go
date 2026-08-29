// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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

// SpamAssassin's X-Spam-Status header, e.g.
// "Yes, score=5.5 required=5.0 tests=TEST1,TEST2,TEST3 autolearn=no". The
// leading boundary keeps another scanner's prefixed score, such as rspamd's
// "rspamdscore=", from being read as SpamAssassin's.
var (
	spamAssassinStatusScoreRe = regexp.MustCompile(`(?:^|[^\w-])score=(-?\d+\.?\d*)`)
	spamAssassinStatusTestsRe = regexp.MustCompile(`tests=([^=]+)(?:\s|$)`)
)

// What SpamAssassin, and only it, writes in an X-Spam-Status: its own score,
// the rules it ran, or the outcome of its Bayes training.
var spamAssassinStatusSignatureRe = regexp.MustCompile(`(?i)(?:^|[^\w-])score=|tests=|autolearn=`)

// An X-Spam-Report test line: "score TEST_NAME Description", e.g.
// "  0.0 TEST_NAME Description" or " -0.1 TEST_NAME Description".
var spamAssassinReportTestRe = regexp.MustCompile(`^\s*(-?\d+\.?\d*)\s+(\S+)\s+(.*)$`)

// SpamAssassinAnalyzer analyzes SpamAssassin results from email headers
type SpamAssassinAnalyzer struct{}

// NewSpamAssassinAnalyzer creates a new SpamAssassin analyzer
func NewSpamAssassinAnalyzer() *SpamAssassinAnalyzer {
	return &SpamAssassinAnalyzer{}
}

// AnalyzeSpamAssassin analyzes the headers SpamScannerHeaders attributed to
// SpamAssassin
func (a *SpamAssassinAnalyzer) AnalyzeSpamAssassin(headers ScannerHeaders) *model.SpamAssassinResult {
	// Require at least X-Spam-Status, X-Spam-Score, or X-Spam-Flag to produce a meaningful report
	if !headers.Has("X-Spam-Status", "X-Spam-Score", "X-Spam-Flag") {
		return nil
	}

	result := &model.SpamAssassinResult{
		TestDetails: make(map[string]model.SpamTestDetail),
	}

	// X-Spam-Status is the authoritative source: X-Spam-Score and X-Spam-Flag
	// carry no marker identifying their author, so on a host running several
	// milters they may well be another scanner's.
	var statusHasScore, statusHasVerdict bool
	// SpamScannerHeaders never routes a blank value, so ok alone is enough here.
	if statusHeader, ok := headers["X-Spam-Status"]; ok {
		statusHasScore, statusHasVerdict = a.parseSpamStatus(statusHeader, result)
	}

	// Fall back to X-Spam-Score and X-Spam-Flag for what X-Spam-Status left out.
	shared := readSharedSpamVerdict(headers)
	if !statusHasScore && shared.hasScore {
		result.Score = shared.score
	}
	if !statusHasVerdict && shared.hasVerdict {
		result.IsSpam = shared.isSpam
	}

	// Parse X-Spam-Report header for detailed test results
	if reportHeader, ok := headers["X-Spam-Report"]; ok {
		result.Report = utils.PtrTo(strings.Replace(reportHeader, " * ", "\n* ", -1))
		a.parseSpamReport(reportHeader, result)
	}

	// Parse X-Spam-Checker-Version
	if versionHeader, ok := headers["X-Spam-Checker-Version"]; ok {
		result.Version = utils.PtrTo(strings.TrimSpace(versionHeader))
	}

	return result
}

// parseSpamStatus parses the X-Spam-Status header
// Format: Yes/No, score=5.5 required=5.0 tests=TEST1,TEST2,TEST3 autolearn=no
// It reports whether the header carried a score and a Yes/No verdict, so the
// caller only falls back to X-Spam-Score and X-Spam-Flag for what is missing.
func (a *SpamAssassinAnalyzer) parseSpamStatus(header string, result *model.SpamAssassinResult) (hasScore, hasVerdict bool) {
	// Check if spam (first word)
	verdict, _, _ := strings.Cut(header, ",")
	verdict = strings.TrimSpace(verdict)
	if strings.EqualFold(verdict, "yes") || strings.EqualFold(verdict, "no") {
		result.IsSpam = strings.EqualFold(verdict, "yes")
		hasVerdict = true
	}

	// Extract score and required score
	if score, ok := extractFloatField(header, spamAssassinStatusScoreRe); ok {
		result.Score = score
		hasScore = true
	}
	if required, ok := extractFloatField(header, spamStatusRequiredRe); ok {
		result.RequiredScore = required
	}

	// Extract tests
	if matches := spamAssassinStatusTestsRe.FindStringSubmatch(header); len(matches) > 1 {
		testsStr := matches[1]
		// Tests can be comma or space separated
		tests := strings.FieldsFunc(testsStr, func(r rune) bool {
			return r == ',' || r == ' '
		})
		result.Tests = &tests
	}

	return hasScore, hasVerdict
}

// parseSpamReport parses the X-Spam-Report header to extract test details
// Format varies, but typically:
// * 1.5 TEST_NAME Description of test
// * 0.0 TEST_NAME2 Description
// Multiline descriptions continue on lines starting with * but without score:
// *  0.0 TEST_NAME Description line 1
// *      continuation line 2
// *      continuation line 3
func (a *SpamAssassinAnalyzer) parseSpamReport(report string, result *model.SpamAssassinResult) {
	segments := strings.Split(report, "*")

	var currentTestName string
	var currentDescription strings.Builder

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		// Try to match as a test line
		matches := spamAssassinReportTestRe.FindStringSubmatch(segment)
		if len(matches) > 3 {
			// Save previous test if exists
			if currentTestName != "" {
				description := strings.TrimSpace(currentDescription.String())
				detail := model.SpamTestDetail{
					Name:        currentTestName,
					Score:       result.TestDetails[currentTestName].Score,
					Description: &description,
				}
				result.TestDetails[currentTestName] = detail
			}

			// Start new test
			testName := matches[2]
			score, _ := parseFloat32(matches[1])
			description := strings.TrimSpace(matches[3])

			currentTestName = testName
			currentDescription.Reset()
			currentDescription.WriteString(description)

			// Initialize with score
			result.TestDetails[testName] = model.SpamTestDetail{
				Name:  testName,
				Score: score,
			}
		} else if currentTestName != "" {
			// This is a continuation line for the current test
			// Add a space before appending to ensure proper word separation
			if currentDescription.Len() > 0 {
				currentDescription.WriteString(" ")
			}
			currentDescription.WriteString(segment)
		}
	}

	// Save the last test if exists
	if currentTestName != "" {
		description := strings.TrimSpace(currentDescription.String())
		detail := model.SpamTestDetail{
			Name:        currentTestName,
			Score:       result.TestDetails[currentTestName].Score,
			Description: &description,
		}
		result.TestDetails[currentTestName] = detail
	}
}

// CalculateSpamAssassinScore calculates the SpamAssassin contribution to deliverability
func (a *SpamAssassinAnalyzer) CalculateSpamAssassinScore(result *model.SpamAssassinResult) (int, string) {
	if result == nil {
		return 100, "" // No spam scan results, assume good
	}

	// SpamAssassin score typically ranges from -10 to +20
	// Score < 0 is very likely ham (good)
	// Score 0-5 is threshold range (configurable, usually 5.0)
	// Score > 5 is likely spam

	score := result.Score

	// Convert SpamAssassin score to 0-100 scale (inverted - lower SA score is better)
	if score < 0 {
		return 100, "A+" // Perfect score for ham
	} else if score == 0 {
		return 100, "A" // Perfect score for ham
	} else if score >= result.RequiredScore {
		return 0, "F" // Failed spam test
	} else {
		// Linear scale between 0 and required threshold
		percentage := 100 - int(math.Round(float64(score*100/(2*result.RequiredScore))))
		return percentage, ScoreToGrade(percentage - 5)
	}
}
