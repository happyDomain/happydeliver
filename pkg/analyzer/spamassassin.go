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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// SpamAssassinAnalyzer analyzes SpamAssassin results from email headers
type SpamAssassinAnalyzer struct{}

// NewSpamAssassinAnalyzer creates a new SpamAssassin analyzer
func NewSpamAssassinAnalyzer() *SpamAssassinAnalyzer {
	return &SpamAssassinAnalyzer{}
}

// SpamAssassinResult represents parsed SpamAssassin results
type SpamAssassinResult struct {
	IsSpam        bool
	Score         float64
	RequiredScore float64
	Tests         []string
	TestDetails   map[string]SpamTestDetail
	Version       string
	RawReport     string
}

// SpamTestDetail contains details about a specific spam test
type SpamTestDetail struct {
	Name        string
	Score       float64
	Description string
}

// AnalyzeSpamAssassin extracts and analyzes SpamAssassin results from email headers
func (a *SpamAssassinAnalyzer) AnalyzeSpamAssassin(email *EmailMessage) *SpamAssassinResult {
	headers := email.GetSpamAssassinHeaders()
	if len(headers) == 0 {
		return nil
	}

	result := &SpamAssassinResult{
		TestDetails: make(map[string]SpamTestDetail),
	}

	// Parse X-Spam-Status header
	if statusHeader, ok := headers["X-Spam-Status"]; ok {
		a.parseSpamStatus(statusHeader, result)
	}

	// Parse X-Spam-Score header (as fallback if not in X-Spam-Status)
	if scoreHeader, ok := headers["X-Spam-Score"]; ok && result.Score == 0 {
		if score, err := strconv.ParseFloat(strings.TrimSpace(scoreHeader), 64); err == nil {
			result.Score = score
		}
	}

	// Parse X-Spam-Flag header (as fallback)
	if flagHeader, ok := headers["X-Spam-Flag"]; ok {
		result.IsSpam = strings.TrimSpace(strings.ToUpper(flagHeader)) == "YES"
	}

	// Parse X-Spam-Report header for detailed test results
	if reportHeader, ok := headers["X-Spam-Report"]; ok {
		result.RawReport = strings.Replace(reportHeader, " *  ", "\n *  ", -1)
		a.parseSpamReport(reportHeader, result)
	}

	// Parse X-Spam-Checker-Version
	if versionHeader, ok := headers["X-Spam-Checker-Version"]; ok {
		result.Version = strings.TrimSpace(versionHeader)
	}

	return result
}

// parseSpamStatus parses the X-Spam-Status header
// Format: Yes/No, score=5.5 required=5.0 tests=TEST1,TEST2,TEST3 autolearn=no
func (a *SpamAssassinAnalyzer) parseSpamStatus(header string, result *SpamAssassinResult) {
	// Check if spam (first word)
	parts := strings.SplitN(header, ",", 2)
	if len(parts) > 0 {
		firstPart := strings.TrimSpace(parts[0])
		result.IsSpam = strings.EqualFold(firstPart, "yes")
	}

	// Extract score
	scoreRe := regexp.MustCompile(`score=(-?\d+\.?\d*)`)
	if matches := scoreRe.FindStringSubmatch(header); len(matches) > 1 {
		if score, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.Score = score
		}
	}

	// Extract required score
	requiredRe := regexp.MustCompile(`required=(-?\d+\.?\d*)`)
	if matches := requiredRe.FindStringSubmatch(header); len(matches) > 1 {
		if required, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.RequiredScore = required
		}
	}

	// Extract tests
	testsRe := regexp.MustCompile(`tests=([^\s]+)`)
	if matches := testsRe.FindStringSubmatch(header); len(matches) > 1 {
		testsStr := matches[1]
		// Tests can be comma or space separated
		tests := strings.FieldsFunc(testsStr, func(r rune) bool {
			return r == ',' || r == ' '
		})
		result.Tests = tests
	}
}

// parseSpamReport parses the X-Spam-Report header to extract test details
// Format varies, but typically:
// * 1.5 TEST_NAME Description of test
// * 0.0 TEST_NAME2 Description
// Note: mail.Header.Get() joins continuation lines, so newlines are removed.
// We split on '*' to separate individual tests.
func (a *SpamAssassinAnalyzer) parseSpamReport(report string, result *SpamAssassinResult) {
	// The report header has been joined by mail.Header.Get(), so we split on '*'
	// Each segment starting with '*' is either a test line or continuation
	segments := strings.Split(report, "*")

	// Regex to match test lines: score TEST_NAME Description
	// Format: "  0.0 TEST_NAME Description" or " -0.1 TEST_NAME Description"
	testRe := regexp.MustCompile(`^\s*(-?\d+\.?\d*)\s+(\S+)\s+(.*)$`)

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		// Try to match as a test line
		matches := testRe.FindStringSubmatch(segment)
		if len(matches) > 3 {
			testName := matches[2]
			score, _ := strconv.ParseFloat(matches[1], 64)
			description := strings.TrimSpace(matches[3])

			detail := SpamTestDetail{
				Name:        testName,
				Score:       score,
				Description: description,
			}
			result.TestDetails[testName] = detail
		}
	}
}

// GetSpamAssassinScore calculates the SpamAssassin contribution to deliverability (0-20 points)
// Scoring:
// - Score <= 0: 20 points (excellent)
// - Score < required: 15 points (good)
// - Score slightly above required (< 2x): 10 points (borderline)
// - Score moderately high (< 3x required): 5 points (poor)
// - Score very high: 0 points (spam)
func (a *SpamAssassinAnalyzer) GetSpamAssassinScore(result *SpamAssassinResult) float32 {
	if result == nil {
		return 0.0
	}

	score := result.Score
	required := result.RequiredScore
	if required == 0 {
		required = 5.0 // Default SpamAssassin threshold
	}

	// Calculate deliverability score
	if score <= 0 {
		return 20.0
	} else if score < required {
		// Linear scaling from 15 to 20 based on how negative/low the score is
		ratio := score / required
		return 15.0 + (5.0 * (1.0 - float32(ratio)))
	} else if score < required*2 {
		// Slightly above threshold
		return 10.0
	} else if score < required*3 {
		// Moderately high
		return 5.0
	}

	// Very high spam score
	return 0.0
}

// GenerateSpamAssassinChecks generates check results for SpamAssassin analysis
func (a *SpamAssassinAnalyzer) GenerateSpamAssassinChecks(result *SpamAssassinResult) []api.Check {
	var checks []api.Check

	if result == nil {
		checks = append(checks, api.Check{
			Category: api.Spam,
			Name:     "SpamAssassin Analysis",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Grade:    ScoreToCheckGrade(0.0),
			Message:  "No SpamAssassin headers found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Ensure your MTA is configured to run SpamAssassin checks"),
		})
		return checks
	}

	// Main spam score check
	mainCheck := a.generateMainSpamCheck(result)
	checks = append(checks, mainCheck)

	// Add checks for significant spam tests (score > 1.0 or < -1.0)
	for _, test := range result.Tests {
		if detail, ok := result.TestDetails[test]; ok {
			if detail.Score > 1.0 || detail.Score < -1.0 {
				check := a.generateTestCheck(detail)
				checks = append(checks, check)
			}
		}
	}

	return checks
}

// generateMainSpamCheck creates the main spam score check
func (a *SpamAssassinAnalyzer) generateMainSpamCheck(result *SpamAssassinResult) api.Check {
	check := api.Check{
		Category: api.Spam,
		Name:     "SpamAssassin Score",
	}

	score := result.Score
	required := result.RequiredScore
	if required == 0 {
		required = 5.0
	}

	delivScore := a.GetSpamAssassinScore(result)
	check.Score = delivScore
	check.Grade = ScoreToCheckGrade((delivScore / 20.0) * 100)

	// Determine status and message based on score
	if score <= 0 {
		check.Status = api.CheckStatusPass
		check.Message = fmt.Sprintf("Excellent spam score: %.1f (threshold: %.1f)", score, required)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your email has a negative spam score, indicating good email practices")
	} else if score < required {
		check.Status = api.CheckStatusPass
		check.Message = fmt.Sprintf("Good spam score: %.1f (threshold: %.1f)", score, required)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your email passes spam filters")
	} else if score < required*1.5 {
		check.Status = api.CheckStatusWarn
		check.Message = fmt.Sprintf("Borderline spam score: %.1f (threshold: %.1f)", score, required)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Your email is close to being marked as spam. Review the triggered spam tests below")
	} else if score < required*2 {
		check.Status = api.CheckStatusWarn
		check.Message = fmt.Sprintf("High spam score: %.1f (threshold: %.1f)", score, required)
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Your email is likely to be marked as spam. Address the issues identified in spam tests")
	} else {
		check.Status = api.CheckStatusFail
		check.Message = fmt.Sprintf("Very high spam score: %.1f (threshold: %.1f)", score, required)
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		check.Advice = api.PtrTo("Your email will almost certainly be marked as spam. Urgently address the spam test failures")
	}

	// Add details
	if len(result.Tests) > 0 {
		details := fmt.Sprintf("Triggered %d tests: %s", len(result.Tests), strings.Join(result.Tests[:min(5, len(result.Tests))], ", "))
		if len(result.Tests) > 5 {
			details += fmt.Sprintf(" and %d more", len(result.Tests)-5)
		}
		check.Details = &details
	}

	return check
}

// generateTestCheck creates a check for a specific spam test
func (a *SpamAssassinAnalyzer) generateTestCheck(detail SpamTestDetail) api.Check {
	check := api.Check{
		Category: api.Spam,
		Name:     fmt.Sprintf("Spam Test: %s", detail.Name),
	}

	if detail.Score > 0 {
		// Negative indicator (increases spam score)
		if detail.Score > 2.0 {
			check.Status = api.CheckStatusFail
			check.Severity = api.PtrTo(api.CheckSeverityHigh)
		} else {
			check.Status = api.CheckStatusWarn
			check.Severity = api.PtrTo(api.CheckSeverityMedium)
		}
		check.Score = 0.0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Message = fmt.Sprintf("Test failed with score +%.1f", detail.Score)
		advice := fmt.Sprintf("%s. This test adds %.1f to your spam score", detail.Description, detail.Score)
		check.Advice = &advice
	} else {
		// Positive indicator (decreases spam score)
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Grade = ScoreToCheckGrade((1.0 / 20.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = fmt.Sprintf("Test passed with score %.1f", detail.Score)
		advice := fmt.Sprintf("%s. This test reduces your spam score by %.1f", detail.Description, -detail.Score)
		check.Advice = &advice
	}

	check.Details = &detail.Description

	return check
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
