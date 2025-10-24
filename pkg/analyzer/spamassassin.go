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

// AnalyzeSpamAssassin extracts and analyzes SpamAssassin results from email headers
func (a *SpamAssassinAnalyzer) AnalyzeSpamAssassin(email *EmailMessage) *api.SpamAssassinResult {
	headers := email.GetSpamAssassinHeaders()
	if len(headers) == 0 {
		return nil
	}

	result := &api.SpamAssassinResult{
		TestDetails: make(map[string]api.SpamTestDetail),
	}

	// Parse X-Spam-Status header
	if statusHeader, ok := headers["X-Spam-Status"]; ok {
		a.parseSpamStatus(statusHeader, result)
	}

	// Parse X-Spam-Score header (as fallback if not in X-Spam-Status)
	if scoreHeader, ok := headers["X-Spam-Score"]; ok && result.Score == 0 {
		if score, err := strconv.ParseFloat(strings.TrimSpace(scoreHeader), 64); err == nil {
			result.Score = float32(score)
		}
	}

	// Parse X-Spam-Flag header (as fallback)
	if flagHeader, ok := headers["X-Spam-Flag"]; ok {
		result.IsSpam = strings.TrimSpace(strings.ToUpper(flagHeader)) == "YES"
	}

	// Parse X-Spam-Report header for detailed test results
	if reportHeader, ok := headers["X-Spam-Report"]; ok {
		result.Report = api.PtrTo(strings.Replace(reportHeader, " * ", "\n* ", -1))
		a.parseSpamReport(reportHeader, result)
	}

	// Parse X-Spam-Checker-Version
	if versionHeader, ok := headers["X-Spam-Checker-Version"]; ok {
		result.Version = api.PtrTo(strings.TrimSpace(versionHeader))
	}

	return result
}

// parseSpamStatus parses the X-Spam-Status header
// Format: Yes/No, score=5.5 required=5.0 tests=TEST1,TEST2,TEST3 autolearn=no
func (a *SpamAssassinAnalyzer) parseSpamStatus(header string, result *api.SpamAssassinResult) {
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
			result.Score = float32(score)
		}
	}

	// Extract required score
	requiredRe := regexp.MustCompile(`required=(-?\d+\.?\d*)`)
	if matches := requiredRe.FindStringSubmatch(header); len(matches) > 1 {
		if required, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.RequiredScore = float32(required)
		}
	}

	// Extract tests
	testsRe := regexp.MustCompile(`tests=([^=]+)(?:\s|$)`)
	if matches := testsRe.FindStringSubmatch(header); len(matches) > 1 {
		testsStr := matches[1]
		// Tests can be comma or space separated
		tests := strings.FieldsFunc(testsStr, func(r rune) bool {
			return r == ',' || r == ' '
		})
		result.Tests = &tests
	}
}

// parseSpamReport parses the X-Spam-Report header to extract test details
// Format varies, but typically:
// * 1.5 TEST_NAME Description of test
// * 0.0 TEST_NAME2 Description
// Multiline descriptions continue on lines starting with * but without score:
// *  0.0 TEST_NAME Description line 1
// *      continuation line 2
// *      continuation line 3
func (a *SpamAssassinAnalyzer) parseSpamReport(report string, result *api.SpamAssassinResult) {
	segments := strings.Split(report, "*")

	// Regex to match test lines: score TEST_NAME Description
	// Format: "  0.0 TEST_NAME Description" or " -0.1 TEST_NAME Description"
	testRe := regexp.MustCompile(`^\s*(-?\d+\.?\d*)\s+(\S+)\s+(.*)$`)

	var currentTestName string
	var currentDescription strings.Builder

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		// Try to match as a test line
		matches := testRe.FindStringSubmatch(segment)
		if len(matches) > 3 {
			// Save previous test if exists
			if currentTestName != "" {
				description := strings.TrimSpace(currentDescription.String())
				detail := api.SpamTestDetail{
					Name:        currentTestName,
					Score:       result.TestDetails[currentTestName].Score,
					Description: &description,
				}
				result.TestDetails[currentTestName] = detail
			}

			// Start new test
			testName := matches[2]
			score, _ := strconv.ParseFloat(matches[1], 64)
			description := strings.TrimSpace(matches[3])

			currentTestName = testName
			currentDescription.Reset()
			currentDescription.WriteString(description)

			// Initialize with score
			result.TestDetails[testName] = api.SpamTestDetail{
				Name:  testName,
				Score: float32(score),
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
		detail := api.SpamTestDetail{
			Name:        currentTestName,
			Score:       result.TestDetails[currentTestName].Score,
			Description: &description,
		}
		result.TestDetails[currentTestName] = detail
	}
}

// CalculateSpamAssassinScore calculates the SpamAssassin contribution to deliverability
func (a *SpamAssassinAnalyzer) CalculateSpamAssassinScore(result *api.SpamAssassinResult) (int, string) {
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
