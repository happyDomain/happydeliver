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
	"bytes"
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

const sampleEmailWithSpamassassinHeader = `X-Spam-Checker-Version: SpamAssassin 4.0.1 (2024-03-26) on e4a8b8eb87ec
X-Spam-Status: No, score=-0.1 required=5.0 tests=DKIM_SIGNED,DKIM_VALID,
	DKIM_VALID_AU,RCVD_IN_VALIDITY_CERTIFIED_BLOCKED,
	RCVD_IN_VALIDITY_RPBL_BLOCKED,RCVD_IN_VALIDITY_SAFE_BLOCKED,
	SPF_HELO_NONE,SPF_PASS autolearn=disabled version=4.0.1
X-Spam-Level:
X-Spam-Report:
	*  0.0 RCVD_IN_VALIDITY_SAFE_BLOCKED RBL: ADMINISTRATOR NOTICE: The query
	*      to Validity was blocked.  See
	*      https://knowledge.validity.com/hc/en-us/articles/20961730681243 for
	*      more information.
	*      [80.67.179.207 listed in sa-accredit.habeas.com]
	*  0.0 RCVD_IN_VALIDITY_RPBL_BLOCKED RBL: ADMINISTRATOR NOTICE: The query
	*      to Validity was blocked.  See
	*      https://knowledge.validity.com/hc/en-us/articles/20961730681243 for
	*      more information.
	*      [80.67.179.207 listed in bl.score.senderscore.com]
	*  0.0 RCVD_IN_VALIDITY_CERTIFIED_BLOCKED RBL: ADMINISTRATOR NOTICE: The
	*      query to Validity was blocked.  See
	*      https://knowledge.validity.com/hc/en-us/articles/20961730681243 for
	*      more information.
	*      [80.67.179.207 listed in sa-trusted.bondedsender.org]
	* -0.0 SPF_PASS SPF: sender matches SPF record
	*  0.0 SPF_HELO_NONE SPF: HELO does not publish an SPF Record
	* -0.1 DKIM_VALID Message has at least one valid DKIM or DK signature
	*  0.1 DKIM_SIGNED Message has a DKIM or DK signature, not necessarily
	*      valid
	* -0.1 DKIM_VALID_AU Message has a valid DKIM or DK signature from author's
	*       domain
Date: Sun, 19 Oct 2025 08:37:30 +0000
Message-ID: <aPSjR57mUnCAt7sp@happydomain.org>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit

BODY`

// TestAnalyzeRealEmailExample tests the analyzer with the real example email file
func TestAnalyzeRealEmailExample(t *testing.T) {
	// Parse the email using the standard net/mail package
	email, err := ParseEmail(bytes.NewBufferString(sampleEmailWithSpamassassinHeader))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	// Create analyzer and analyze SpamAssassin headers
	analyzer := NewSpamAssassinAnalyzer()
	result := analyzer.AnalyzeSpamAssassin(email)

	// Validate that we got a result
	if result == nil {
		t.Fatal("Expected SpamAssassin result, got nil")
	}

	// Validate IsSpam flag (should be false for this email)
	if result.IsSpam {
		t.Error("IsSpam should be false for real_example.eml")
	}

	// Validate score (should be -0.1)
	expectedScore := -0.1
	if result.Score != expectedScore {
		t.Errorf("Score = %v, want %v", result.Score, expectedScore)
	}

	// Validate required score (should be 5.0)
	expectedRequired := 5.0
	if result.RequiredScore != expectedRequired {
		t.Errorf("RequiredScore = %v, want %v", result.RequiredScore, expectedRequired)
	}

	// Validate version
	if !strings.Contains(result.Version, "SpamAssassin") {
		t.Errorf("Version should contain 'SpamAssassin', got: %s", result.Version)
	}

	// Validate that tests were extracted
	if len(result.Tests) == 0 {
		t.Error("Expected tests to be extracted, got none")
	}

	// Check for expected tests from the real email
	expectedTests := map[string]bool{
		"DKIM_SIGNED":   true,
		"DKIM_VALID":    true,
		"DKIM_VALID_AU": true,
		"SPF_PASS":      true,
		"SPF_HELO_NONE": true,
	}

	for _, testName := range result.Tests {
		if expectedTests[testName] {
			t.Logf("Found expected test: %s", testName)
		}
	}

	// Validate that test details were parsed from X-Spam-Report
	if len(result.TestDetails) == 0 {
		t.Error("Expected test details to be parsed from X-Spam-Report, got none")
	}

	// Log what we actually got for debugging
	t.Logf("Parsed %d test details from X-Spam-Report", len(result.TestDetails))
	for name, detail := range result.TestDetails {
		t.Logf("  %s: score=%v, description=%s", name, detail.Score, detail.Description)
	}

	// Define expected test details with their scores
	expectedTestDetails := map[string]float64{
		"SPF_PASS":                           -0.0,
		"SPF_HELO_NONE":                      0.0,
		"DKIM_VALID":                         -0.1,
		"DKIM_SIGNED":                        0.1,
		"DKIM_VALID_AU":                      -0.1,
		"RCVD_IN_VALIDITY_SAFE_BLOCKED":      0.0,
		"RCVD_IN_VALIDITY_RPBL_BLOCKED":      0.0,
		"RCVD_IN_VALIDITY_CERTIFIED_BLOCKED": 0.0,
	}

	// Iterate over expected tests and verify they exist in TestDetails
	for testName, expectedScore := range expectedTestDetails {
		detail, ok := result.TestDetails[testName]
		if !ok {
			t.Errorf("Expected test %s not found in TestDetails", testName)
			continue
		}
		if detail.Score != expectedScore {
			t.Errorf("Test %s score = %v, want %v", testName, detail.Score, expectedScore)
		}
		if detail.Description == "" {
			t.Errorf("Test %s should have a description", testName)
		}
	}

	// Test GetSpamAssassinScore
	score := analyzer.GetSpamAssassinScore(result)
	if score != 2.0 {
		t.Errorf("GetSpamAssassinScore() = %v, want 2.0 (excellent score for negative spam score)", score)
	}

	// Test GenerateSpamAssassinChecks
	checks := analyzer.GenerateSpamAssassinChecks(result)
	if len(checks) < 1 {
		t.Fatal("Expected at least 1 check, got none")
	}

	// Main check should be PASS with excellent score
	mainCheck := checks[0]
	if mainCheck.Status != api.CheckStatusPass {
		t.Errorf("Main check status = %v, want %v", mainCheck.Status, api.CheckStatusPass)
	}
	if mainCheck.Category != api.Spam {
		t.Errorf("Main check category = %v, want %v", mainCheck.Category, api.Spam)
	}
	if !strings.Contains(mainCheck.Message, "spam score") {
		t.Errorf("Main check message should contain 'spam score', got: %s", mainCheck.Message)
	}
	if mainCheck.Score != 2.0 {
		t.Errorf("Main check score = %v, want 2.0", mainCheck.Score)
	}

	// Log all checks for debugging
	t.Logf("Generated %d checks:", len(checks))
	for i, check := range checks {
		t.Logf("  Check %d: %s - %s (score: %.1f, status: %s)",
			i+1, check.Name, check.Message, check.Score, check.Status)
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
