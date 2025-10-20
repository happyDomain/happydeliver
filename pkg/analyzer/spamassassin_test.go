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
	"net/mail"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/api"
)

func TestParseSpamStatus(t *testing.T) {
	tests := []struct {
		name           string
		header         string
		expectedIsSpam bool
		expectedScore  float64
		expectedReq    float64
		expectedTests  []string
	}{
		{
			name:           "Clean email",
			header:         "No, score=-0.1 required=5.0 tests=ALL_TRUSTED autolearn=ham",
			expectedIsSpam: false,
			expectedScore:  -0.1,
			expectedReq:    5.0,
			expectedTests:  []string{"ALL_TRUSTED"},
		},
		{
			name:           "Spam email",
			header:         "Yes, score=15.5 required=5.0 tests=BAYES_99,SPOOFED_SENDER,MISSING_HEADERS autolearn=spam",
			expectedIsSpam: true,
			expectedScore:  15.5,
			expectedReq:    5.0,
			expectedTests:  []string{"BAYES_99", "SPOOFED_SENDER", "MISSING_HEADERS"},
		},
		{
			name:           "Borderline email",
			header:         "No, score=4.8 required=5.0 tests=HTML_MESSAGE,MIME_HTML_ONLY",
			expectedIsSpam: false,
			expectedScore:  4.8,
			expectedReq:    5.0,
			expectedTests:  []string{"HTML_MESSAGE", "MIME_HTML_ONLY"},
		},
		{
			name:           "No tests listed",
			header:         "No, score=0.5 required=5.0",
			expectedIsSpam: false,
			expectedScore:  0.5,
			expectedReq:    5.0,
			expectedTests:  nil,
		},
	}

	analyzer := NewSpamAssassinAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SpamAssassinResult{
				TestDetails: make(map[string]SpamTestDetail),
			}
			analyzer.parseSpamStatus(tt.header, result)

			if result.IsSpam != tt.expectedIsSpam {
				t.Errorf("IsSpam = %v, want %v", result.IsSpam, tt.expectedIsSpam)
			}
			if result.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", result.Score, tt.expectedScore)
			}
			if result.RequiredScore != tt.expectedReq {
				t.Errorf("RequiredScore = %v, want %v", result.RequiredScore, tt.expectedReq)
			}
			if len(tt.expectedTests) > 0 && !stringSliceEqual(result.Tests, tt.expectedTests) {
				t.Errorf("Tests = %v, want %v", result.Tests, tt.expectedTests)
			}
		})
	}
}

func TestParseSpamReport(t *testing.T) {
	report := `Content analysis details:   (15.5 points, 5.0 required)

 * 5.0 BAYES_99 Bayes spam probability is 99 to 100%
 * 3.5 SPOOFED_SENDER From address doesn't match envelope sender
 * 2.0 MISSING_HEADERS Missing important headers
 * 1.5 HTML_MESSAGE Contains HTML
 * 0.5 MIME_HTML_ONLY Message only has HTML parts
 * -1.0 ALL_TRUSTED All mail servers are trusted
 * 4.0 SUSPICIOUS_URLS Contains suspicious URLs
`

	analyzer := NewSpamAssassinAnalyzer()
	result := &SpamAssassinResult{
		TestDetails: make(map[string]SpamTestDetail),
	}

	analyzer.parseSpamReport(report, result)

	expectedTests := map[string]SpamTestDetail{
		"BAYES_99": {
			Name:        "BAYES_99",
			Score:       5.0,
			Description: "Bayes spam probability is 99 to 100%",
		},
		"SPOOFED_SENDER": {
			Name:        "SPOOFED_SENDER",
			Score:       3.5,
			Description: "From address doesn't match envelope sender",
		},
		"ALL_TRUSTED": {
			Name:        "ALL_TRUSTED",
			Score:       -1.0,
			Description: "All mail servers are trusted",
		},
	}

	for testName, expected := range expectedTests {
		detail, ok := result.TestDetails[testName]
		if !ok {
			t.Errorf("Test %s not found in results", testName)
			continue
		}
		if detail.Score != expected.Score {
			t.Errorf("Test %s score = %v, want %v", testName, detail.Score, expected.Score)
		}
		if detail.Description != expected.Description {
			t.Errorf("Test %s description = %q, want %q", testName, detail.Description, expected.Description)
		}
	}
}

func TestGetSpamAssassinScore(t *testing.T) {
	tests := []struct {
		name          string
		result        *SpamAssassinResult
		expectedScore float32
		minScore      float32
		maxScore      float32
	}{
		{
			name:          "Nil result",
			result:        nil,
			expectedScore: 0.0,
		},
		{
			name: "Excellent score (negative)",
			result: &SpamAssassinResult{
				Score:         -2.5,
				RequiredScore: 5.0,
			},
			expectedScore: 2.0,
		},
		{
			name: "Good score (below threshold)",
			result: &SpamAssassinResult{
				Score:         2.0,
				RequiredScore: 5.0,
			},
			minScore: 1.5,
			maxScore: 2.0,
		},
		{
			name: "Borderline (just above threshold)",
			result: &SpamAssassinResult{
				Score:         6.0,
				RequiredScore: 5.0,
			},
			expectedScore: 1.0,
		},
		{
			name: "High spam score",
			result: &SpamAssassinResult{
				Score:         12.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0.5,
		},
		{
			name: "Very high spam score",
			result: &SpamAssassinResult{
				Score:         20.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0.0,
		},
	}

	analyzer := NewSpamAssassinAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.GetSpamAssassinScore(tt.result)

			if tt.minScore > 0 || tt.maxScore > 0 {
				if score < tt.minScore || score > tt.maxScore {
					t.Errorf("Score = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
				}
			} else {
				if score != tt.expectedScore {
					t.Errorf("Score = %v, want %v", score, tt.expectedScore)
				}
			}
		})
	}
}

func TestAnalyzeSpamAssassin(t *testing.T) {
	tests := []struct {
		name               string
		headers            map[string]string
		expectedIsSpam     bool
		expectedScore      float64
		expectedHasDetails bool
	}{
		{
			name: "Clean email with full headers",
			headers: map[string]string{
				"X-Spam-Status":          "No, score=-0.5 required=5.0 tests=ALL_TRUSTED autolearn=ham",
				"X-Spam-Score":           "-0.5",
				"X-Spam-Flag":            "NO",
				"X-Spam-Report":          "* -0.5 ALL_TRUSTED All mail servers are trusted",
				"X-Spam-Checker-Version": "SpamAssassin 3.4.2",
			},
			expectedIsSpam:     false,
			expectedScore:      -0.5,
			expectedHasDetails: true,
		},
		{
			name: "Spam email",
			headers: map[string]string{
				"X-Spam-Status": "Yes, score=15.0 required=5.0 tests=BAYES_99,SPOOFED_SENDER",
				"X-Spam-Flag":   "YES",
			},
			expectedIsSpam: true,
			expectedScore:  15.0,
		},
		{
			name: "Only X-Spam-Score header",
			headers: map[string]string{
				"X-Spam-Score": "3.2",
			},
			expectedIsSpam: false,
			expectedScore:  3.2,
		},
	}

	analyzer := NewSpamAssassinAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create email message with headers
			email := &EmailMessage{
				Header: make(mail.Header),
			}
			for key, value := range tt.headers {
				email.Header[key] = []string{value}
			}

			result := analyzer.AnalyzeSpamAssassin(email)

			if result == nil {
				t.Fatal("Expected result, got nil")
			}

			if result.IsSpam != tt.expectedIsSpam {
				t.Errorf("IsSpam = %v, want %v", result.IsSpam, tt.expectedIsSpam)
			}
			if result.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", result.Score, tt.expectedScore)
			}
			if tt.expectedHasDetails && len(result.TestDetails) == 0 {
				t.Error("Expected test details, got none")
			}
		})
	}
}

func TestGenerateSpamAssassinChecks(t *testing.T) {
	tests := []struct {
		name           string
		result         *SpamAssassinResult
		expectedStatus api.CheckStatus
		minChecks      int
	}{
		{
			name:           "Nil result",
			result:         nil,
			expectedStatus: api.CheckStatusWarn,
			minChecks:      1,
		},
		{
			name: "Clean email",
			result: &SpamAssassinResult{
				IsSpam:        false,
				Score:         -0.5,
				RequiredScore: 5.0,
				Tests:         []string{"ALL_TRUSTED"},
				TestDetails: map[string]SpamTestDetail{
					"ALL_TRUSTED": {
						Name:        "ALL_TRUSTED",
						Score:       -1.5,
						Description: "All mail servers are trusted",
					},
				},
			},
			expectedStatus: api.CheckStatusPass,
			minChecks:      2, // Main check + one test detail
		},
		{
			name: "Spam email",
			result: &SpamAssassinResult{
				IsSpam:        true,
				Score:         15.0,
				RequiredScore: 5.0,
				Tests:         []string{"BAYES_99", "SPOOFED_SENDER"},
				TestDetails: map[string]SpamTestDetail{
					"BAYES_99": {
						Name:        "BAYES_99",
						Score:       5.0,
						Description: "Bayes spam probability is 99 to 100%",
					},
					"SPOOFED_SENDER": {
						Name:        "SPOOFED_SENDER",
						Score:       3.5,
						Description: "From address doesn't match envelope sender",
					},
				},
			},
			expectedStatus: api.CheckStatusFail,
			minChecks:      3, // Main check + two significant tests
		},
	}

	analyzer := NewSpamAssassinAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.GenerateSpamAssassinChecks(tt.result)

			if len(checks) < tt.minChecks {
				t.Errorf("Got %d checks, want at least %d", len(checks), tt.minChecks)
			}

			// Check main check (first one)
			if len(checks) > 0 {
				mainCheck := checks[0]
				if mainCheck.Status != tt.expectedStatus {
					t.Errorf("Main check status = %v, want %v", mainCheck.Status, tt.expectedStatus)
				}
				if mainCheck.Category != api.Spam {
					t.Errorf("Main check category = %v, want %v", mainCheck.Category, api.Spam)
				}
			}
		})
	}
}

func TestAnalyzeSpamAssassinNoHeaders(t *testing.T) {
	analyzer := NewSpamAssassinAnalyzer()
	email := &EmailMessage{
		Header: make(mail.Header),
	}

	result := analyzer.AnalyzeSpamAssassin(email)

	if result != nil {
		t.Errorf("Expected nil result for email without SpamAssassin headers, got %+v", result)
	}
}

func TestGenerateMainSpamCheck(t *testing.T) {
	analyzer := NewSpamAssassinAnalyzer()

	tests := []struct {
		name           string
		score          float64
		required       float64
		expectedStatus api.CheckStatus
	}{
		{"Excellent", -1.0, 5.0, api.CheckStatusPass},
		{"Good", 2.0, 5.0, api.CheckStatusPass},
		{"Borderline", 6.0, 5.0, api.CheckStatusWarn},
		{"High", 8.0, 5.0, api.CheckStatusWarn},
		{"Very High", 15.0, 5.0, api.CheckStatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &SpamAssassinResult{
				Score:         tt.score,
				RequiredScore: tt.required,
			}

			check := analyzer.generateMainSpamCheck(result)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Category != api.Spam {
				t.Errorf("Category = %v, want %v", check.Category, api.Spam)
			}
			if !strings.Contains(check.Message, "spam score") {
				t.Error("Message should contain 'spam score'")
			}
		})
	}
}

func TestGenerateTestCheck(t *testing.T) {
	analyzer := NewSpamAssassinAnalyzer()

	tests := []struct {
		name           string
		detail         SpamTestDetail
		expectedStatus api.CheckStatus
	}{
		{
			name: "High penalty test",
			detail: SpamTestDetail{
				Name:        "BAYES_99",
				Score:       5.0,
				Description: "Bayes spam probability is 99 to 100%",
			},
			expectedStatus: api.CheckStatusFail,
		},
		{
			name: "Medium penalty test",
			detail: SpamTestDetail{
				Name:        "HTML_MESSAGE",
				Score:       1.5,
				Description: "Contains HTML",
			},
			expectedStatus: api.CheckStatusWarn,
		},
		{
			name: "Positive test",
			detail: SpamTestDetail{
				Name:        "ALL_TRUSTED",
				Score:       -2.0,
				Description: "All mail servers are trusted",
			},
			expectedStatus: api.CheckStatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateTestCheck(tt.detail)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Category != api.Spam {
				t.Errorf("Category = %v, want %v", check.Category, api.Spam)
			}
			if !strings.Contains(check.Name, tt.detail.Name) {
				t.Errorf("Check name should contain test name %s", tt.detail.Name)
			}
		})
	}
}

// Helper function to compare string slices
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
