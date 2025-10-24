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
		expectedScore  float32
		expectedReq    float32
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
			result := &api.SpamAssassinResult{
				TestDetails: make(map[string]api.SpamTestDetail),
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
			if len(tt.expectedTests) > 0 {
				if result.Tests == nil {
					t.Errorf("Tests = nil, want %v", tt.expectedTests)
				} else if !stringSliceEqual(*result.Tests, tt.expectedTests) {
					t.Errorf("Tests = %v, want %v", *result.Tests, tt.expectedTests)
				}
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
	result := &api.SpamAssassinResult{
		TestDetails: make(map[string]api.SpamTestDetail),
	}

	analyzer.parseSpamReport(report, result)

	expectedTests := map[string]api.SpamTestDetail{
		"BAYES_99": {
			Name:        "BAYES_99",
			Score:       5.0,
			Description: api.PtrTo("Bayes spam probability is 99 to 100%"),
		},
		"SPOOFED_SENDER": {
			Name:        "SPOOFED_SENDER",
			Score:       3.5,
			Description: api.PtrTo("From address doesn't match envelope sender"),
		},
		"ALL_TRUSTED": {
			Name:        "ALL_TRUSTED",
			Score:       -1.0,
			Description: api.PtrTo("All mail servers are trusted"),
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
		if *detail.Description != *expected.Description {
			t.Errorf("Test %s description = %q, want %q", testName, *detail.Description, *expected.Description)
		}
	}
}

func TestGetSpamAssassinScore(t *testing.T) {
	tests := []struct {
		name          string
		result        *api.SpamAssassinResult
		expectedScore int
		minScore      int
		maxScore      int
	}{
		{
			name:          "Nil result",
			result:        nil,
			expectedScore: 100,
		},
		{
			name: "Excellent score (negative)",
			result: &api.SpamAssassinResult{
				Score:         -2.5,
				RequiredScore: 5.0,
			},
			expectedScore: 100,
		},
		{
			name: "Good score (below threshold)",
			result: &api.SpamAssassinResult{
				Score:         2.0,
				RequiredScore: 5.0,
			},
			expectedScore: 80, // 100 - round(2*100/5) = 100 - 40 = 60
		},
		{
			name: "Score at threshold",
			result: &api.SpamAssassinResult{
				Score:         5.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0, // >= threshold = 0
		},
		{
			name: "Above threshold (spam)",
			result: &api.SpamAssassinResult{
				Score:         6.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0, // >= threshold = 0
		},
		{
			name: "High spam score",
			result: &api.SpamAssassinResult{
				Score:         12.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0, // >= threshold = 0
		},
		{
			name: "Very high spam score",
			result: &api.SpamAssassinResult{
				Score:         20.0,
				RequiredScore: 5.0,
			},
			expectedScore: 0, // >= threshold = 0
		},
	}

	analyzer := NewSpamAssassinAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _ := analyzer.CalculateSpamAssassinScore(tt.result)

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
		expectedScore      float32
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
	var expectedScore float32 = -0.1
	if result.Score != expectedScore {
		t.Errorf("Score = %v, want %v", result.Score, expectedScore)
	}

	// Validate required score (should be 5.0)
	var expectedRequired float32 = 5.0
	if result.RequiredScore != expectedRequired {
		t.Errorf("RequiredScore = %v, want %v", result.RequiredScore, expectedRequired)
	}

	// Validate version
	if result.Version == nil {
		t.Errorf("Version should contain 'SpamAssassin', got: nil")
	} else if !strings.Contains(*result.Version, "SpamAssassin") {
		t.Errorf("Version should contain 'SpamAssassin', got: %s", *result.Version)
	}

	// Validate that tests were extracted
	if len(*result.Tests) == 0 {
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

	for _, testName := range *result.Tests {
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
		t.Logf("  %s: score=%v, description=%s", name, detail.Score, *detail.Description)
	}

	// Define expected test details with their scores
	expectedTestDetails := map[string]float32{
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
		if detail.Description == nil || *detail.Description == "" {
			t.Errorf("Test %s should have a description", testName)
		}
	}

	// Test GetSpamAssassinScore
	score, _ := analyzer.CalculateSpamAssassinScore(result)
	if score != 100 {
		t.Errorf("GetSpamAssassinScore() = %v, want 100 (excellent score for negative spam score)", score)
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
