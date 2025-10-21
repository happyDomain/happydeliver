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
	"testing"

	"git.happydns.org/happyDeliver/internal/api"
)

func TestCalculateHeaderScore(t *testing.T) {
	tests := []struct {
		name     string
		email    *EmailMessage
		minScore int
		maxScore int
	}{
		{
			name:     "Nil email",
			email:    nil,
			minScore: 0,
			maxScore: 0,
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
			minScore: 70,
			maxScore: 100,
		},
		{
			name: "Missing required headers",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"Subject": "Test",
				}),
			},
			minScore: 0,
			maxScore: 40,
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
			minScore: 40,
			maxScore: 80,
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
			minScore: 70,
			maxScore: 100,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.calculateHeaderScore(tt.email)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("calculateHeaderScore() = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestGenerateRequiredHeadersCheck(t *testing.T) {
	tests := []struct {
		name           string
		email          *EmailMessage
		expectedStatus api.CheckStatus
		expectedScore  int
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
			expectedScore:  40,
		},
		{
			name: "Missing all required headers",
			email: &EmailMessage{
				Header: make(mail.Header),
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0,
		},
		{
			name: "Missing some required headers",
			email: &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From": "sender@example.com",
				}),
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateRequiredHeadersCheck(tt.email)

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

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"Message-ID": tt.messageID,
				}),
			}

			check := analyzer.generateMessageIDCheck(email)

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

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: make(mail.Header),
				Parts:  tt.parts,
			}

			check := analyzer.generateMIMEStructureCheck(email)

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

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.GenerateHeaderChecks(tt.email)

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
