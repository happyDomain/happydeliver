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
			// Generate header analysis first
			analysis := analyzer.GenerateHeaderAnalysis(tt.email)
			score := analyzer.CalculateHeaderScore(analysis)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("CalculateHeaderScore() = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestCheckHeader(t *testing.T) {
	tests := []struct {
		name              string
		headerName        string
		headerValue       string
		importance        string
		expectedPresent   bool
		expectedValid     bool
		expectedIssuesLen int
	}{
		{
			name:              "Valid Message-ID",
			headerName:        "Message-ID",
			headerValue:       "<abc123@example.com>",
			importance:        "required",
			expectedPresent:   true,
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
		{
			name:              "Invalid Message-ID format",
			headerName:        "Message-ID",
			headerValue:       "invalid-message-id",
			importance:        "required",
			expectedPresent:   true,
			expectedValid:     false,
			expectedIssuesLen: 1,
		},
		{
			name:              "Missing required header",
			headerName:        "From",
			headerValue:       "",
			importance:        "required",
			expectedPresent:   false,
			expectedValid:     false,
			expectedIssuesLen: 1,
		},
		{
			name:              "Missing optional header",
			headerName:        "Reply-To",
			headerValue:       "",
			importance:        "optional",
			expectedPresent:   false,
			expectedValid:     false,
			expectedIssuesLen: 0,
		},
		{
			name:              "Valid Date header",
			headerName:        "Date",
			headerValue:       "Mon, 01 Jan 2024 12:00:00 +0000",
			importance:        "required",
			expectedPresent:   true,
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					tt.headerName: tt.headerValue,
				}),
			}

			check := analyzer.checkHeader(email, tt.headerName, tt.importance)

			if check.Present != tt.expectedPresent {
				t.Errorf("Present = %v, want %v", check.Present, tt.expectedPresent)
			}

			if check.Valid != nil && *check.Valid != tt.expectedValid {
				t.Errorf("Valid = %v, want %v", *check.Valid, tt.expectedValid)
			}

			if check.Importance == nil {
				t.Error("Importance is nil")
			} else if string(*check.Importance) != tt.importance {
				t.Errorf("Importance = %v, want %v", *check.Importance, tt.importance)
			}

			issuesLen := 0
			if check.Issues != nil {
				issuesLen = len(*check.Issues)
			}
			if issuesLen != tt.expectedIssuesLen {
				t.Errorf("Issues length = %d, want %d", issuesLen, tt.expectedIssuesLen)
			}
		})
	}
}

func TestHeaderAnalyzer_IsValidMessageID(t *testing.T) {
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
			name:      "Valid with complex local part",
			messageID: "<complex.id-123_xyz@subdomain.example.com>",
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
			name:      "Empty local part",
			messageID: "<@example.com>",
			expected:  false,
		},
		{
			name:      "Empty domain",
			messageID: "<abc123@>",
			expected:  false,
		},
		{
			name:      "Multiple @ symbols",
			messageID: "<abc@123@example.com>",
			expected:  false,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.isValidMessageID(tt.messageID)
			if result != tt.expected {
				t.Errorf("isValidMessageID(%q) = %v, want %v", tt.messageID, result, tt.expected)
			}
		})
	}
}

func TestHeaderAnalyzer_ExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "Simple email",
			email:    "user@example.com",
			expected: "example.com",
		},
		{
			name:     "Email with angle brackets",
			email:    "<user@example.com>",
			expected: "example.com",
		},
		{
			name:     "Email with display name",
			email:    "User Name <user@example.com>",
			expected: "example.com",
		},
		{
			name:     "Email with spaces",
			email:    " user@example.com ",
			expected: "example.com",
		},
		{
			name:     "Invalid email",
			email:    "not-an-email",
			expected: "",
		},
		{
			name:     "Empty string",
			email:    "",
			expected: "",
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractDomain(tt.email)
			if result != tt.expected {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.email, result, tt.expected)
			}
		})
	}
}

func TestAnalyzeDomainAlignment(t *testing.T) {
	tests := []struct {
		name            string
		fromHeader      string
		returnPath      string
		expectAligned   bool
		expectIssuesLen int
	}{
		{
			name:            "Aligned domains",
			fromHeader:      "sender@example.com",
			returnPath:      "bounce@example.com",
			expectAligned:   true,
			expectIssuesLen: 0,
		},
		{
			name:            "Misaligned domains",
			fromHeader:      "sender@example.com",
			returnPath:      "bounce@different.com",
			expectAligned:   false,
			expectIssuesLen: 1,
		},
		{
			name:            "Only From header",
			fromHeader:      "sender@example.com",
			returnPath:      "",
			expectAligned:   true,
			expectIssuesLen: 0,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: createHeaderWithFields(map[string]string{
					"From":        tt.fromHeader,
					"Return-Path": tt.returnPath,
				}),
			}

			alignment := analyzer.analyzeDomainAlignment(email)

			if alignment == nil {
				t.Fatal("Expected non-nil alignment")
			}

			if alignment.Aligned == nil {
				t.Fatal("Expected non-nil Aligned field")
			}

			if *alignment.Aligned != tt.expectAligned {
				t.Errorf("Aligned = %v, want %v", *alignment.Aligned, tt.expectAligned)
			}

			issuesLen := 0
			if alignment.Issues != nil {
				issuesLen = len(*alignment.Issues)
			}
			if issuesLen != tt.expectIssuesLen {
				t.Errorf("Issues length = %d, want %d", issuesLen, tt.expectIssuesLen)
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
