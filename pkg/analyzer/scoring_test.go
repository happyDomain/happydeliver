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

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name           string
		authResults    *api.AuthenticationResults
		spamResult     *SpamAssassinResult
		rblResults     *RBLResults
		contentResults *ContentResults
		email          *EmailMessage
		minScore       int
		maxScore       int
		expectedGrade  string
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
			minScore:      90.0,
			maxScore:      100.0,
			expectedGrade: "A+",
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
			minScore:      0.0,
			maxScore:      50.0,
			expectedGrade: "C",
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
			minScore:      60.0,
			maxScore:      90.0,
			expectedGrade: "A",
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
			if result.Grade != api.ReportGrade(tt.expectedGrade) {
				t.Errorf("Grade = %q, want %q", result.Grade, tt.expectedGrade)
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
			if len(result.Recommendations) == 0 && result.Grade != "A+" {
				t.Error("Expected recommendations for non-excellent rating")
			}

			// Verify category scores add up to overall score
			totalCategoryScore := result.AuthScore + result.SpamScore + result.BlacklistScore + result.ContentScore + result.HeaderScore
			if totalCategoryScore != result.OverallScore {
				t.Errorf("Category scores sum (%d) doesn't match overall score (%d)",
					totalCategoryScore, result.OverallScore)
			}
		})
	}
}
