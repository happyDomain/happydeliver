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
			// Generate header analysis first
			analysis := analyzer.GenerateHeaderAnalysis(tt.email)
			score, _ := analyzer.CalculateHeaderScore(analysis)
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

func TestParseReceivedChain(t *testing.T) {
	tests := []struct {
		name            string
		receivedHeaders []string
		expectedHops    int
		validateFirst   func(*testing.T, *EmailMessage, []api.ReceivedHop)
	}{
		{
			name:            "No Received headers",
			receivedHeaders: []string{},
			expectedHops:    0,
		},
		{
			name: "Single Received header",
			receivedHeaders: []string{
				"from mail.example.com (mail.example.com [192.0.2.1]) by mx.receiver.com (Postfix) with ESMTPS id ABC123 for <user@receiver.com>; Mon, 01 Jan 2024 12:00:00 +0000",
			},
			expectedHops: 1,
			validateFirst: func(t *testing.T, email *EmailMessage, hops []api.ReceivedHop) {
				if len(hops) == 0 {
					t.Fatal("Expected at least one hop")
				}
				hop := hops[0]

				if hop.From == nil || *hop.From != "mail.example.com" {
					t.Errorf("From = %v, want 'mail.example.com'", hop.From)
				}
				if hop.By == nil || *hop.By != "mx.receiver.com" {
					t.Errorf("By = %v, want 'mx.receiver.com'", hop.By)
				}
				if hop.With == nil || *hop.With != "ESMTPS" {
					t.Errorf("With = %v, want 'ESMTPS'", hop.With)
				}
				if hop.Id == nil || *hop.Id != "ABC123" {
					t.Errorf("Id = %v, want 'ABC123'", hop.Id)
				}
				if hop.Ip == nil || *hop.Ip != "192.0.2.1" {
					t.Errorf("Ip = %v, want '192.0.2.1'", hop.Ip)
				}
				if hop.Timestamp == nil {
					t.Error("Timestamp should not be nil")
				}
			},
		},
		{
			name: "Multiple Received headers",
			receivedHeaders: []string{
				"from mail1.example.com (mail1.example.com [192.0.2.1]) by mx1.receiver.com with ESMTP id 111; Mon, 01 Jan 2024 12:00:00 +0000",
				"from mail2.example.com (mail2.example.com [192.0.2.2]) by mx2.receiver.com with SMTP id 222; Mon, 01 Jan 2024 11:59:00 +0000",
			},
			expectedHops: 2,
			validateFirst: func(t *testing.T, email *EmailMessage, hops []api.ReceivedHop) {
				if len(hops) != 2 {
					t.Fatalf("Expected 2 hops, got %d", len(hops))
				}

				// Check first hop
				if hops[0].From == nil || *hops[0].From != "mail1.example.com" {
					t.Errorf("First hop From = %v, want 'mail1.example.com'", hops[0].From)
				}

				// Check second hop
				if hops[1].From == nil || *hops[1].From != "mail2.example.com" {
					t.Errorf("Second hop From = %v, want 'mail2.example.com'", hops[1].From)
				}
			},
		},
		{
			name: "IPv6 address",
			receivedHeaders: []string{
				"from mail.example.com (unknown [IPv6:2607:5300:203:2818::1]) by mx.receiver.com with ESMTPS; Sun, 19 Oct 2025 09:40:33 +0000 (UTC)",
			},
			expectedHops: 1,
			validateFirst: func(t *testing.T, email *EmailMessage, hops []api.ReceivedHop) {
				if len(hops) == 0 {
					t.Fatal("Expected at least one hop")
				}
				hop := hops[0]

				if hop.Ip == nil {
					t.Fatal("IP should not be nil for IPv6 address")
				}
				// Should strip the "IPv6:" prefix
				if *hop.Ip != "2607:5300:203:2818::1" {
					t.Errorf("Ip = %v, want '2607:5300:203:2818::1'", *hop.Ip)
				}
			},
		},
		{
			name: "Multiline Received header",
			receivedHeaders: []string{
				`from nemunai.re (unknown [IPv6:2607:5300:203:2818::1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange x25519 server-signature ECDSA (prime256v1) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: nemunaire)
	by djehouty.pomail.fr (Postfix) with ESMTPSA id 1EFD11611EA
	for <test-9a9ce364-c394-4fa9-acef-d46ff2f482bf@deliver.happydomain.org>; Sun, 19 Oct 2025 09:40:33 +0000 (UTC)`,
			},
			expectedHops: 1,
			validateFirst: func(t *testing.T, email *EmailMessage, hops []api.ReceivedHop) {
				if len(hops) == 0 {
					t.Fatal("Expected at least one hop")
				}
				hop := hops[0]

				if hop.From == nil || *hop.From != "nemunai.re" {
					t.Errorf("From = %v, want 'nemunai.re'", hop.From)
				}
				if hop.By == nil || *hop.By != "djehouty.pomail.fr" {
					t.Errorf("By = %v, want 'djehouty.pomail.fr'", hop.By)
				}
				if hop.With == nil {
					t.Error("With should not be nil")
				} else if *hop.With != "ESMTPSA" {
					t.Errorf("With = %q, want 'ESMTPSA'", *hop.With)
				}
				if hop.Id == nil || *hop.Id != "1EFD11611EA" {
					t.Errorf("Id = %v, want '1EFD11611EA'", hop.Id)
				}
			},
		},
		{
			name: "Received header with minimal information",
			receivedHeaders: []string{
				"from unknown by localhost",
			},
			expectedHops: 1,
			validateFirst: func(t *testing.T, email *EmailMessage, hops []api.ReceivedHop) {
				if len(hops) == 0 {
					t.Fatal("Expected at least one hop")
				}
				hop := hops[0]

				if hop.From == nil || *hop.From != "unknown" {
					t.Errorf("From = %v, want 'unknown'", hop.From)
				}
				if hop.By == nil || *hop.By != "localhost" {
					t.Errorf("By = %v, want 'localhost'", hop.By)
				}
			},
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(mail.Header)
			if len(tt.receivedHeaders) > 0 {
				header["Received"] = tt.receivedHeaders
			}

			email := &EmailMessage{
				Header: header,
			}

			chain := analyzer.parseReceivedChain(email)

			if len(chain) != tt.expectedHops {
				t.Errorf("parseReceivedChain() returned %d hops, want %d", len(chain), tt.expectedHops)
			}

			if tt.validateFirst != nil {
				tt.validateFirst(t, email, chain)
			}
		})
	}
}

func TestParseReceivedHeader(t *testing.T) {
	tests := []struct {
		name          string
		receivedValue string
		expectFrom    *string
		expectBy      *string
		expectWith    *string
		expectId      *string
		expectIp      *string
		expectHasTs   bool
	}{
		{
			name:          "Complete Received header",
			receivedValue: "from mail.example.com (mail.example.com [192.0.2.1]) by mx.receiver.com (Postfix) with ESMTPS id ABC123 for <user@receiver.com>; Mon, 01 Jan 2024 12:00:00 +0000",
			expectFrom:    strPtr("mail.example.com"),
			expectBy:      strPtr("mx.receiver.com"),
			expectWith:    strPtr("ESMTPS"),
			expectId:      strPtr("ABC123"),
			expectIp:      strPtr("192.0.2.1"),
			expectHasTs:   true,
		},
		{
			name:          "Minimal Received header",
			receivedValue: "from sender.example.com by receiver.example.com",
			expectFrom:    strPtr("sender.example.com"),
			expectBy:      strPtr("receiver.example.com"),
			expectWith:    nil,
			expectId:      nil,
			expectIp:      nil,
			expectHasTs:   false,
		},
		{
			name:          "Received header with ESMTPA",
			receivedValue: "from [192.0.2.50] by mail.example.com with ESMTPA id XYZ789; Tue, 02 Jan 2024 08:30:00 -0500",
			expectFrom:    strPtr("[192.0.2.50]"),
			expectBy:      strPtr("mail.example.com"),
			expectWith:    strPtr("ESMTPA"),
			expectId:      strPtr("XYZ789"),
			expectIp:      strPtr("192.0.2.50"),
			expectHasTs:   true,
		},
		{
			name:          "Received header without IP",
			receivedValue: "from mail.example.com by mx.receiver.com with SMTP; Wed, 03 Jan 2024 14:20:00 +0000",
			expectFrom:    strPtr("mail.example.com"),
			expectBy:      strPtr("mx.receiver.com"),
			expectWith:    strPtr("SMTP"),
			expectId:      nil,
			expectIp:      nil,
			expectHasTs:   true,
		},
		{
			name:          "Postfix local delivery with userid",
			receivedValue: "by grunt.ycc.fr (Postfix, from userid 1000) id 67276801A8; Fri, 24 Oct 2025 04:17:25 +0200 (CEST)",
			expectFrom:    nil,
			expectBy:      strPtr("grunt.ycc.fr"),
			expectWith:    nil,
			expectId:      strPtr("67276801A8"),
			expectIp:      nil,
			expectHasTs:   true,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop := analyzer.parseReceivedHeader(tt.receivedValue)

			if hop == nil {
				t.Fatal("parseReceivedHeader returned nil")
			}

			// Check From
			if !equalStrPtr(hop.From, tt.expectFrom) {
				t.Errorf("From = %v, want %v", ptrToStr(hop.From), ptrToStr(tt.expectFrom))
			}

			// Check By
			if !equalStrPtr(hop.By, tt.expectBy) {
				t.Errorf("By = %v, want %v", ptrToStr(hop.By), ptrToStr(tt.expectBy))
			}

			// Check With
			if !equalStrPtr(hop.With, tt.expectWith) {
				t.Errorf("With = %v, want %v", ptrToStr(hop.With), ptrToStr(tt.expectWith))
			}

			// Check Id
			if !equalStrPtr(hop.Id, tt.expectId) {
				t.Errorf("Id = %v, want %v", ptrToStr(hop.Id), ptrToStr(tt.expectId))
			}

			// Check Ip
			if !equalStrPtr(hop.Ip, tt.expectIp) {
				t.Errorf("Ip = %v, want %v", ptrToStr(hop.Ip), ptrToStr(tt.expectIp))
			}

			// Check Timestamp
			if tt.expectHasTs {
				if hop.Timestamp == nil {
					t.Error("Timestamp should not be nil")
				}
			}
		})
	}
}

func TestGenerateHeaderAnalysis_WithReceivedChain(t *testing.T) {
	analyzer := NewHeaderAnalyzer()

	email := &EmailMessage{
		Header: createHeaderWithFields(map[string]string{
			"From":       "sender@example.com",
			"To":         "recipient@example.com",
			"Subject":    "Test",
			"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
			"Message-ID": "<abc123@example.com>",
		}),
		MessageID: "<abc123@example.com>",
		Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
		Parts:     []MessagePart{{ContentType: "text/plain", Content: "test"}},
	}

	// Add Received headers
	email.Header["Received"] = []string{
		"from mail.example.com (mail.example.com [192.0.2.1]) by mx.receiver.com with ESMTP id ABC123; Mon, 01 Jan 2024 12:00:00 +0000",
		"from relay.example.com (relay.example.com [192.0.2.2]) by mail.example.com with SMTP id DEF456; Mon, 01 Jan 2024 11:59:00 +0000",
	}

	analysis := analyzer.GenerateHeaderAnalysis(email)

	if analysis == nil {
		t.Fatal("GenerateHeaderAnalysis returned nil")
	}

	if analysis.ReceivedChain == nil {
		t.Fatal("ReceivedChain should not be nil")
	}

	chain := *analysis.ReceivedChain
	if len(chain) != 2 {
		t.Fatalf("Expected 2 hops in ReceivedChain, got %d", len(chain))
	}

	// Check first hop
	if chain[0].From == nil || *chain[0].From != "mail.example.com" {
		t.Errorf("First hop From = %v, want 'mail.example.com'", chain[0].From)
	}

	// Check second hop
	if chain[1].From == nil || *chain[1].From != "relay.example.com" {
		t.Errorf("Second hop From = %v, want 'relay.example.com'", chain[1].From)
	}
}

// Helper functions for testing
func strPtr(s string) *string {
	return &s
}

func ptrToStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func equalStrPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
