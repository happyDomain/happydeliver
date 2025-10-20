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
	"net/textproto"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/api"
)

func TestNewDeliverabilityScorer(t *testing.T) {
	scorer := NewDeliverabilityScorer()
	if scorer == nil {
		t.Fatal("Expected scorer, got nil")
	}
}

func TestIsValidMessageID(t *testing.T) {
	tests := []struct {
		name      string
		messageID string
		expected  bool
	}{
		{
			name:      "Valid Message-ID",
			messageID: "<abc123@example.com>",
			expected:  true,
		},
		{
			name:      "Valid with UUID",
			messageID: "<550e8400-e29b-41d4-a716-446655440000@example.com>",
			expected:  true,
		},
		{
			name:      "Missing angle brackets",
			messageID: "abc123@example.com",
			expected:  false,
		},
		{
			name:      "Missing @ symbol",
			messageID: "<abc123example.com>",
			expected:  false,
		},
		{
			name:      "Multiple @ symbols",
			messageID: "<abc@123@example.com>",
			expected:  false,
		},
		{
			name:      "Empty local part",
			messageID: "<@example.com>",
			expected:  false,
		},
		{
			name:      "Empty domain part",
			messageID: "<abc123@>",
			expected:  false,
		},
		{
			name:      "Empty",
			messageID: "",
			expected:  false,
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.isValidMessageID(tt.messageID)
			if result != tt.expected {
				t.Errorf("isValidMessageID(%q) = %v, want %v", tt.messageID, result, tt.expected)
			}
		})
	}
}

func TestCalculateHeaderScore(t *testing.T) {
	tests := []struct {
		name     string
		email    *EmailMessage
		minScore float32
		maxScore float32
	}{
		{
			name:     "Nil email",
			email:    nil,
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name: "Perfect headers",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"To":         "recipient@example.com",
					"Subject":    "Test",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
					"Reply-To":   "reply@example.com",
				}),
				MessageID: "<abc123@example.com>",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
				Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 7.0,
			maxScore: 10.0,
		},
		{
			name: "Missing required headers",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"Subject": "Test",
				}),
			},
			minScore: 0.0,
			maxScore: 4.0,
		},
		{
			name: "Required only, no recommended",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
				}),
				MessageID: "<abc123@example.com>",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
				Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 4.0,
			maxScore: 8.0,
		},
		{
			name: "Invalid Message-ID format",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "invalid-message-id",
					"Subject":    "Test",
					"To":         "recipient@example.com",
					"Reply-To":   "reply@example.com",
				}),
				MessageID: "invalid-message-id",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
				Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 7.0,
			maxScore: 10.0,
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scorer.calculateHeaderScore(tt.email)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("calculateHeaderScore() = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestDetermineRating(t *testing.T) {
	tests := []struct {
		name     string
		score    float32
		expected string
	}{
		{name: "Excellent - 10.0", score: 100.0, expected: "Excellent"},
		{name: "Excellent - 9.5", score: 95.0, expected: "Excellent"},
		{name: "Excellent - 9.0", score: 90.0, expected: "Excellent"},
		{name: "Good - 8.5", score: 85.0, expected: "Good"},
		{name: "Good - 7.0", score: 70.0, expected: "Good"},
		{name: "Fair - 6.5", score: 65.0, expected: "Fair"},
		{name: "Fair - 5.0", score: 50.0, expected: "Fair"},
		{name: "Poor - 4.5", score: 45.0, expected: "Poor"},
		{name: "Poor - 3.0", score: 30.0, expected: "Poor"},
		{name: "Critical - 2.5", score: 25.0, expected: "Critical"},
		{name: "Critical - 0.0", score: 0.0, expected: "Critical"},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.determineRating(tt.score)
			if result != tt.expected {
				t.Errorf("determineRating(%v) = %q, want %q", tt.score, result, tt.expected)
			}
		})
	}
}

func TestGetCategoryStatus(t *testing.T) {
	tests := []struct {
		name     string
		score    float32
		maxScore float32
		expected string
	}{
		{name: "Pass - 100%", score: 3.0, maxScore: 3.0, expected: "Pass"},
		{name: "Pass - 90%", score: 2.7, maxScore: 3.0, expected: "Pass"},
		{name: "Pass - 80%", score: 2.4, maxScore: 3.0, expected: "Pass"},
		{name: "Warn - 75%", score: 2.25, maxScore: 3.0, expected: "Warn"},
		{name: "Warn - 50%", score: 1.5, maxScore: 3.0, expected: "Warn"},
		{name: "Fail - 40%", score: 1.2, maxScore: 3.0, expected: "Fail"},
		{name: "Fail - 0%", score: 0.0, maxScore: 3.0, expected: "Fail"},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.getCategoryStatus(tt.score, tt.maxScore)
			if result != tt.expected {
				t.Errorf("getCategoryStatus(%v, %v) = %q, want %q", tt.score, tt.maxScore, result, tt.expected)
			}
		})
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name           string
		authResults    *api.AuthenticationResults
		spamResult     *SpamAssassinResult
		rblResults     *RBLResults
		contentResults *ContentResults
		email          *EmailMessage
		minScore       float32
		maxScore       float32
		expectedRating string
	}{
		{
			name: "Perfect email",
			authResults: &api.AuthenticationResults{
				Spf: &api.AuthResult{Result: api.AuthResultResultPass},
				Dkim: &[]api.AuthResult{
					{Result: api.AuthResultResultPass},
				},
				Dmarc: &api.AuthResult{Result: api.AuthResultResultPass},
			},
			spamResult: &SpamAssassinResult{
				Score:         -1.0,
				RequiredScore: 5.0,
			},
			rblResults: &RBLResults{
				Checks: []RBLCheck{
					{IP: "192.0.2.1", Listed: false},
				},
			},
			contentResults: &ContentResults{
				HTMLValid:      true,
				Links:          []LinkCheck{{Valid: true, Status: 200}},
				Images:         []ImageCheck{{HasAlt: true}},
				HasUnsubscribe: true,
				TextPlainRatio: 0.8,
				ImageTextRatio: 3.0,
			},
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"To":         "recipient@example.com",
					"Subject":    "Test",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
					"Reply-To":   "reply@example.com",
				}),
				MessageID: "<abc123@example.com>",
				Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minScore:       90.0,
			maxScore:       100.0,
			expectedRating: "Excellent",
		},
		{
			name: "Poor email - auth issues",
			authResults: &api.AuthenticationResults{
				Spf:   &api.AuthResult{Result: api.AuthResultResultFail},
				Dkim:  &[]api.AuthResult{},
				Dmarc: nil,
			},
			spamResult: &SpamAssassinResult{
				Score:         8.0,
				RequiredScore: 5.0,
			},
			rblResults: &RBLResults{
				Checks: []RBLCheck{
					{
						IP:     "192.0.2.1",
						RBL:    "zen.spamhaus.org",
						Listed: true,
					},
				},
				ListedCount: 1,
			},
			contentResults: &ContentResults{
				HTMLValid:      false,
				Links:          []LinkCheck{{Valid: true, Status: 404}},
				HasUnsubscribe: false,
			},
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From": "sender@example.com",
				}),
			},
			minScore:       0.0,
			maxScore:       50.0,
			expectedRating: "Poor",
		},
		{
			name: "Average email",
			authResults: &api.AuthenticationResults{
				Spf: &api.AuthResult{Result: api.AuthResultResultPass},
				Dkim: &[]api.AuthResult{
					{Result: api.AuthResultResultPass},
				},
				Dmarc: nil,
			},
			spamResult: &SpamAssassinResult{
				Score:         4.0,
				RequiredScore: 5.0,
			},
			rblResults: &RBLResults{
				Checks: []RBLCheck{
					{IP: "192.0.2.1", Listed: false},
				},
			},
			contentResults: &ContentResults{
				HTMLValid:      true,
				Links:          []LinkCheck{{Valid: true, Status: 200}},
				HasUnsubscribe: false,
			},
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
				}),
				MessageID: "<abc123@example.com>",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
				Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minScore:       60.0,
			maxScore:       90.0,
			expectedRating: "Good",
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scorer.CalculateScore(
				tt.authResults,
				tt.spamResult,
				tt.rblResults,
				tt.contentResults,
				tt.email,
			)

			if result == nil {
				t.Fatal("Expected result, got nil")
			}

			// Check overall score
			if result.OverallScore < tt.minScore || result.OverallScore > tt.maxScore {
				t.Errorf("OverallScore = %v, want between %v and %v", result.OverallScore, tt.minScore, tt.maxScore)
			}

			// Check rating
			if result.Rating != tt.expectedRating {
				t.Errorf("Rating = %q, want %q", result.Rating, tt.expectedRating)
			}

			// Verify score is within bounds
			if result.OverallScore < 0.0 || result.OverallScore > 100.0 {
				t.Errorf("OverallScore %v is out of bounds [0.0, 100.0]", result.OverallScore)
			}

			// Verify category breakdown exists
			if len(result.CategoryBreakdown) != 5 {
				t.Errorf("Expected 5 categories, got %d", len(result.CategoryBreakdown))
			}

			// Verify recommendations exist
			if len(result.Recommendations) == 0 && result.Rating != "Excellent" {
				t.Error("Expected recommendations for non-excellent rating")
			}

			// Verify category scores add up to overall score
			totalCategoryScore := result.AuthScore + result.SpamScore + result.BlacklistScore + result.ContentScore + result.HeaderScore
			if totalCategoryScore < result.OverallScore-0.01 || totalCategoryScore > result.OverallScore+0.01 {
				t.Errorf("Category scores sum (%.2f) doesn't match overall score (%.2f)",
					totalCategoryScore, result.OverallScore)
			}
		})
	}
}

func TestGenerateRecommendations(t *testing.T) {
	tests := []struct {
		name                 string
		result               *ScoringResult
		expectedMinCount     int
		shouldContainKeyword string
	}{
		{
			name: "Excellent - minimal recommendations",
			result: &ScoringResult{
				OverallScore:   9.5,
				Rating:         "Excellent",
				AuthScore:      3.0,
				SpamScore:      2.0,
				BlacklistScore: 2.0,
				ContentScore:   2.0,
				HeaderScore:    1.0,
			},
			expectedMinCount:     1,
			shouldContainKeyword: "Excellent",
		},
		{
			name: "Critical - many recommendations",
			result: &ScoringResult{
				OverallScore:   1.0,
				Rating:         "Critical",
				AuthScore:      0.5,
				SpamScore:      0.0,
				BlacklistScore: 0.0,
				ContentScore:   0.3,
				HeaderScore:    0.2,
			},
			expectedMinCount:     5,
			shouldContainKeyword: "Critical",
		},
		{
			name: "Poor authentication",
			result: &ScoringResult{
				OverallScore:   5.0,
				Rating:         "Fair",
				AuthScore:      1.5,
				SpamScore:      2.0,
				BlacklistScore: 2.0,
				ContentScore:   1.5,
				HeaderScore:    1.0,
			},
			expectedMinCount:     1,
			shouldContainKeyword: "authentication",
		},
		{
			name: "Blacklist issues",
			result: &ScoringResult{
				OverallScore:   4.0,
				Rating:         "Poor",
				AuthScore:      3.0,
				SpamScore:      2.0,
				BlacklistScore: 0.5,
				ContentScore:   1.5,
				HeaderScore:    1.0,
			},
			expectedMinCount:     1,
			shouldContainKeyword: "blacklist",
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := scorer.generateRecommendations(tt.result)

			if len(recommendations) < tt.expectedMinCount {
				t.Errorf("Got %d recommendations, want at least %d", len(recommendations), tt.expectedMinCount)
			}

			// Check if expected keyword appears in any recommendation
			found := false
			for _, rec := range recommendations {
				if strings.Contains(strings.ToLower(rec), strings.ToLower(tt.shouldContainKeyword)) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("No recommendation contains keyword %q. Recommendations: %v",
					tt.shouldContainKeyword, recommendations)
			}
		})
	}
}

func TestGenerateRequiredHeadersCheck(t *testing.T) {
	tests := []struct {
		name           string
		email          *EmailMessage
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "All required headers present",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
				}),
				From:      &mail.Address{Address: "sender@example.com"},
				MessageID: "<abc123@example.com>",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  4.0,
		},
		{
			name: "Missing all required headers",
			email: &EmailMessage{
				Header: make(mail.Header),
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
		{
			name: "Missing some required headers",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From": "sender@example.com",
				}),
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := scorer.generateRequiredHeadersCheck(tt.email)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Headers {
				t.Errorf("Category = %v, want %v", check.Category, api.Headers)
			}
		})
	}
}

func TestGenerateMessageIDCheck(t *testing.T) {
	tests := []struct {
		name           string
		messageID      string
		expectedStatus api.CheckStatus
	}{
		{
			name:           "Valid Message-ID",
			messageID:      "<abc123@example.com>",
			expectedStatus: api.CheckStatusPass,
		},
		{
			name:           "Invalid Message-ID format",
			messageID:      "invalid-message-id",
			expectedStatus: api.CheckStatusWarn,
		},
		{
			name:           "Missing Message-ID",
			messageID:      "",
			expectedStatus: api.CheckStatusFail,
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"Message-ID": tt.messageID,
				}),
			}

			check := scorer.generateMessageIDCheck(email)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Category != api.Headers {
				t.Errorf("Category = %v, want %v", check.Category, api.Headers)
			}
		})
	}
}

func TestGenerateMIMEStructureCheck(t *testing.T) {
	tests := []struct {
		name           string
		parts          []MessagePart
		expectedStatus api.CheckStatus
	}{
		{
			name: "With MIME parts",
			parts: []MessagePart{
				{ContentType: "text/plain", Content: "test"},
				{ContentType: "text/html", Content: "<p>test</p>"},
			},
			expectedStatus: api.CheckStatusPass,
		},
		{
			name:           "No MIME parts",
			parts:          []MessagePart{},
			expectedStatus: api.CheckStatusWarn,
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: make(mail.Header),
				Parts:  tt.parts,
			}

			check := scorer.generateMIMEStructureCheck(email)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
		})
	}
}

func TestGenerateHeaderChecks(t *testing.T) {
	tests := []struct {
		name      string
		email     *EmailMessage
		minChecks int
	}{
		{
			name:      "Nil email",
			email:     nil,
			minChecks: 0,
		},
		{
			name: "Complete email",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"To":         "recipient@example.com",
					"Subject":    "Test",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
					"Reply-To":   "reply@example.com",
				}),
				Parts: []MessagePart{{ContentType: "text/plain", Content: "test"}},
			},
			minChecks: 4, // Required, Recommended, Message-ID, MIME
		},
	}

	scorer := NewDeliverabilityScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := scorer.GenerateHeaderChecks(tt.email)

			if len(checks) < tt.minChecks {
				t.Errorf("Got %d checks, want at least %d", len(checks), tt.minChecks)
			}

			// Verify all checks have the Headers category
			for _, check := range checks {
				if check.Category != api.Headers {
					t.Errorf("Check %s has category %v, want %v", check.Name, check.Category, api.Headers)
				}
			}
		})
	}
}

func TestGetScoreSummary(t *testing.T) {
	result := &ScoringResult{
		OverallScore:   8.5,
		Rating:         "Good",
		AuthScore:      2.5,
		SpamScore:      1.8,
		BlacklistScore: 2.0,
		ContentScore:   1.5,
		HeaderScore:    0.7,
		CategoryBreakdown: map[string]CategoryScore{
			"Authentication":  {Score: 2.5, MaxScore: 3.0, Percentage: 83.3, Status: "Pass"},
			"Spam Filters":    {Score: 1.8, MaxScore: 2.0, Percentage: 90.0, Status: "Pass"},
			"Blacklists":      {Score: 2.0, MaxScore: 2.0, Percentage: 100.0, Status: "Pass"},
			"Content Quality": {Score: 1.5, MaxScore: 2.0, Percentage: 75.0, Status: "Warn"},
			"Email Structure": {Score: 0.7, MaxScore: 1.0, Percentage: 70.0, Status: "Warn"},
		},
		Recommendations: []string{
			"Improve content quality",
			"Add more headers",
		},
	}

	scorer := NewDeliverabilityScorer()
	summary := scorer.GetScoreSummary(result)

	// Check that summary contains key information
	if !strings.Contains(summary, "8.5") {
		t.Error("Summary should contain overall score")
	}
	if !strings.Contains(summary, "Good") {
		t.Error("Summary should contain rating")
	}
	if !strings.Contains(summary, "Authentication") {
		t.Error("Summary should contain category names")
	}
	if !strings.Contains(summary, "Recommendations") {
		t.Error("Summary should contain recommendations section")
	}
}

// Helper function to create mail.Header with specific fields
func createHeaderWithFields(fields map[string]string) mail.Header {
	header := make(mail.Header)
	for key, value := range fields {
		if value != "" {
			// Use canonical MIME header key format
			canonicalKey := textproto.CanonicalMIMEHeaderKey(key)
			header[canonicalKey] = []string{value}
		}
	}
	return header
}
