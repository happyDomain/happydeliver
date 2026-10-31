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
	"net/mail"
	"net/textproto"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

func TestCalculateHeaderScore(t *testing.T) {
	tests := []struct {
		name     string
		email    *mailmsg.Message
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
			email: &mailmsg.Message{
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
				Parts:     []mailmsg.Part{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 70,
			maxScore: 100,
		},
		{
			name: "Missing required headers",
			email: &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					"Subject": "Test",
				}),
			},
			minScore: 0,
			maxScore: 40,
		},
		{
			name: "Required only, no recommended",
			email: &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					"From":       "sender@example.com",
					"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
					"Message-ID": "<abc123@example.com>",
				}),
				MessageID: "<abc123@example.com>",
				Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
				Parts:     []mailmsg.Part{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 80,
			maxScore: 90,
		},
		{
			name: "Invalid Message-ID format",
			email: &mailmsg.Message{
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
				Parts:     []mailmsg.Part{{ContentType: "text/plain", Content: "test"}},
			},
			minScore: 70,
			maxScore: 100,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate header analysis first
			analysis := analyzer.GenerateHeaderAnalysis(tt.email, nil)
			score, _ := analyzer.CalculateHeaderScore(analysis, nil)
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
			name:              "MIME-Version with a comment",
			headerName:        "MIME-Version",
			headerValue:       `1.0 (Mac OS X Mail 16.0 \(3864.700.51.1.1\))`,
			importance:        "recommended",
			expectedPresent:   true,
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
		{
			name:              "MIME-Version with a comment between tokens",
			headerName:        "MIME-Version",
			headerValue:       "1.(produced by MetaSend Vx.x)0",
			importance:        "recommended",
			expectedPresent:   true,
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
		{
			name:              "MIME-Version other than 1.0",
			headerName:        "MIME-Version",
			headerValue:       "2.0 (1.0)",
			importance:        "recommended",
			expectedPresent:   true,
			expectedValid:     false,
			expectedIssuesLen: 1,
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
			email := &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					tt.headerName: tt.headerValue,
				}),
			}

			check, issues := analyzer.checkHeader(email, tt.headerName, tt.importance)

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

			issuesLen := len(issues)
			if issuesLen != tt.expectedIssuesLen {
				t.Errorf("Issues length = %d, want %d", issuesLen, tt.expectedIssuesLen)
			}
		})
	}
}

// TestHeaderAnalyzer_IsValidMessageID exercises isValidMessageID. A
// Message-ID is valid only in the RFC 5322 "<local@domain>" shape:
// surrounded by angle brackets, exactly one "@" splitting a non-empty local
// part from a non-empty domain, e.g. "<abc123@example.com>". Missing the
// brackets, missing or duplicated "@", or an empty local/domain part (e.g.
// "<@example.com>" or "<abc123@>") are all invalid.
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

// TestAddressDomain exercises addressDomain, which returns everything after
// the last "@" in the input, after trimming leading/trailing '<', '>' and
// spaces. It tolerates a display name before the address ("User Name
// <user@example.com>" -> "example.com") and surrounding whitespace, but
// returns "" when there's no "@" at all (e.g. "not-an-email" or "").
func TestAddressDomain(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mailmsg.AddressDomain(tt.email)
			if result != tt.expected {
				t.Errorf("mailmsg.AddressDomain(%q) = %q, want %q", tt.email, result, tt.expected)
			}
		})
	}
}

func TestAnalyzeDomainAlignment(t *testing.T) {
	tests := []struct {
		name          string
		fromHeader    string
		returnPath    string
		expectAligned bool
		expectIssues  []model.IssueType
		// The address reported for the Return-Path, nil when there is none
		expectReturnPath *string
	}{
		{
			name:             "Aligned domains",
			fromHeader:       "sender@example.com",
			returnPath:       "<bounce@example.com>",
			expectAligned:    true,
			expectIssues:     nil,
			expectReturnPath: utils.PtrTo("bounce@example.com"),
		},
		{
			name:             "Misaligned domains",
			fromHeader:       "sender@example.com",
			returnPath:       "bounce@different.com",
			expectAligned:    false,
			expectIssues:     []model.IssueType{model.IssueTypeDomainMisaligned},
			expectReturnPath: utils.PtrTo("bounce@different.com"),
		},
		{
			name:          "Only From header",
			fromHeader:    "sender@example.com",
			returnPath:    "",
			expectAligned: true,
			expectIssues:  nil,
		},
		{
			// A bounce has no domain to compare
			name:             "Null sender",
			fromHeader:       "sender@example.com",
			returnPath:       "<>",
			expectAligned:    true,
			expectIssues:     nil,
			expectReturnPath: utils.PtrTo(""),
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					"From":        tt.fromHeader,
					"Return-Path": tt.returnPath,
				}),
			}

			alignment := analyzer.analyzeDomainAlignment(email, nil)

			if alignment == nil {
				t.Fatal("Expected non-nil alignment")
			}

			if alignment.Aligned == nil {
				t.Fatal("Expected non-nil Aligned field")
			}

			if *alignment.Aligned != tt.expectAligned {
				t.Errorf("Aligned = %v, want %v", *alignment.Aligned, tt.expectAligned)
			}

			if tt.expectReturnPath == nil && alignment.ReturnPath != nil {
				t.Errorf("ReturnPath = %q, want none", *alignment.ReturnPath)
			} else if tt.expectReturnPath != nil && (alignment.ReturnPath == nil || *alignment.ReturnPath != *tt.expectReturnPath) {
				t.Errorf("ReturnPath = %v, want %q", alignment.ReturnPath, *tt.expectReturnPath)
			}

			if _, issues := calculateAlignmentScore(alignment, nil); fmt.Sprint(issueTypes(issues)) != fmt.Sprint(tt.expectIssues) {
				t.Errorf("issues = %v, want %v", issueTypes(issues), tt.expectIssues)
			}
		})
	}
}

// The Return-Path is reported as the address it wraps, the null sender of a
// bounce as an empty one.
func TestReturnPathAddress(t *testing.T) {
	for value, want := range map[string]string{
		"<bounce@example.com>":            "bounce@example.com",
		"bounce@example.com":              "bounce@example.com",
		" <bounce+tag@mail.example.com> ": "bounce+tag@mail.example.com",
		"<>":                              "",
		"<bounce@example.com> (comment)":  "bounce@example.com",
	} {
		if got := returnPathAddress(value); got != want {
			t.Errorf("returnPathAddress(%q) = %q, want %q", value, got, want)
		}
	}
}

// The alignment issues end up in the analysis, and a message without
// alignment data is told it is misaligned.
func TestAlignmentIssuesStoredByHeaderScore(t *testing.T) {
	if score, issues := calculateAlignmentScore(nil, nil); score != 0 || fmt.Sprint(issueTypes(issues)) != fmt.Sprint([]model.IssueType{model.IssueTypeDomainMisaligned}) {
		t.Errorf("nil alignment: score %d, issues %v", score, issueTypes(issues))
	}
	email := &mailmsg.Message{Header: createHeaderWithFields(map[string]string{
		"From": "sender@example.com", "Return-Path": "<bounce@other.net>",
	})}
	a := NewHeaderAnalyzer()
	analysis := a.GenerateHeaderAnalysis(email, nil)
	a.CalculateHeaderScore(analysis, nil)
	if analysis.Issues.DomainAlignment == nil || (*analysis.Issues.DomainAlignment)[0].Type != model.IssueTypeDomainMisaligned {
		t.Errorf("domain_alignment issues = %v", analysis.Issues.DomainAlignment)
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

// TestParseReceivedChain exercises parseReceivedChain, which turns each
// "Received:" header into a hop by pulling out loosely-ordered clauses:
// "from <host> (... [<ip>])", "by <host>", "with <protocol>", "id <id>", and
// a trailing date. Only "from" and "by" are needed for a hop to be produced
// at all (e.g. "from unknown by localhost" still yields one hop with just
// those two fields); the IP is taken from inside the "from" clause's
// brackets and has any "IPv6:" label stripped (e.g. "[IPv6:2607:...]" ->
// "2607:..."); folded/multi-line header values are unfolded before parsing,
// so a clause split across lines is still recognized.
func TestParseReceivedChain(t *testing.T) {
	tests := []struct {
		name            string
		receivedHeaders []string
		expectedHops    int
		validateFirst   func(*testing.T, *mailmsg.Message, []model.ReceivedHop)
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
			validateFirst: func(t *testing.T, email *mailmsg.Message, hops []model.ReceivedHop) {
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
			validateFirst: func(t *testing.T, email *mailmsg.Message, hops []model.ReceivedHop) {
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
			validateFirst: func(t *testing.T, email *mailmsg.Message, hops []model.ReceivedHop) {
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
			validateFirst: func(t *testing.T, email *mailmsg.Message, hops []model.ReceivedHop) {
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
			validateFirst: func(t *testing.T, email *mailmsg.Message, hops []model.ReceivedHop) {
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

			email := &mailmsg.Message{
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

// TestParseReceivedHeader exercises parseReceivedHeader, the single-header
// parser behind parseReceivedChain (see the criteria documented on
// TestParseReceivedChain above). It additionally covers a "by"-only hop with
// no "from" clause at all ("by grunt.ycc.fr ... id 67276801A8"), e.g. a
// Postfix local-delivery line, which still produces a hop.
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
			expectFrom:    utils.PtrTo("mail.example.com"),
			expectBy:      utils.PtrTo("mx.receiver.com"),
			expectWith:    utils.PtrTo("ESMTPS"),
			expectId:      utils.PtrTo("ABC123"),
			expectIp:      utils.PtrTo("192.0.2.1"),
			expectHasTs:   true,
		},
		{
			name:          "Minimal Received header",
			receivedValue: "from sender.example.com by receiver.example.com",
			expectFrom:    utils.PtrTo("sender.example.com"),
			expectBy:      utils.PtrTo("receiver.example.com"),
			expectWith:    nil,
			expectId:      nil,
			expectIp:      nil,
			expectHasTs:   false,
		},
		{
			name:          "Received header with ESMTPA",
			receivedValue: "from [192.0.2.50] by mail.example.com with ESMTPA id XYZ789; Tue, 02 Jan 2024 08:30:00 -0500",
			expectFrom:    utils.PtrTo("[192.0.2.50]"),
			expectBy:      utils.PtrTo("mail.example.com"),
			expectWith:    utils.PtrTo("ESMTPA"),
			expectId:      utils.PtrTo("XYZ789"),
			expectIp:      utils.PtrTo("192.0.2.50"),
			expectHasTs:   true,
		},
		{
			name:          "Received header without IP",
			receivedValue: "from mail.example.com by mx.receiver.com with SMTP; Wed, 03 Jan 2024 14:20:00 +0000",
			expectFrom:    utils.PtrTo("mail.example.com"),
			expectBy:      utils.PtrTo("mx.receiver.com"),
			expectWith:    utils.PtrTo("SMTP"),
			expectId:      nil,
			expectIp:      nil,
			expectHasTs:   true,
		},
		{
			name:          "Postfix local delivery with userid",
			receivedValue: "by grunt.ycc.fr (Postfix, from userid 1000) id 67276801A8; Fri, 24 Oct 2025 04:17:25 +0200 (CEST)",
			expectFrom:    nil,
			expectBy:      utils.PtrTo("grunt.ycc.fr"),
			expectWith:    nil,
			expectId:      utils.PtrTo("67276801A8"),
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

func TestParseReceivedTLS(t *testing.T) {
	tests := []struct {
		name           string
		receivedValue  string
		expectNil      bool
		expectVersion  *string
		expectCipher   *string
		expectBits     *int
		expectVerified *bool
	}{
		{
			name: "TLS 1.3 no client certificate",
			receivedValue: "from mail.example.com (unknown [IPv6:2001:db8::1]) " +
				"(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) " +
				"key-exchange x25519 server-signature ECDSA (prime256v1) server-digest SHA256) " +
				"(No client certificate requested) " +
				"by mx.example.org (Postfix) with ESMTPSA id 1EFD11611EA; Sun, 19 Oct 2025 09:40:33 +0000 (UTC)",
			expectVersion:  utils.PtrTo("TLSv1.3"),
			expectCipher:   utils.PtrTo("TLS_AES_256_GCM_SHA384"),
			expectBits:     utils.PtrTo(256),
			expectVerified: nil,
		},
		{
			name: "TLS with verified client certificate",
			receivedValue: "from mail.example.com (mail.example.com [192.0.2.1]) " +
				"(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits)) " +
				"(Client CN \"example\", Issuer \"CA\" (verified OK)) " +
				"by mx.receiver.com (Postfix) with ESMTPS id ABC; Mon, 01 Jan 2024 12:00:00 +0000",
			expectVersion:  utils.PtrTo("TLSv1.2"),
			expectCipher:   utils.PtrTo("ECDHE-RSA-AES128-GCM-SHA256"),
			expectBits:     utils.PtrTo(128),
			expectVerified: utils.PtrTo(true),
		},
		{
			name:          "Plaintext (no TLS)",
			receivedValue: "from mail.example.com (mail.example.com [192.0.2.1]) by mx.receiver.com (Postfix) with ESMTP id ABC; Mon, 01 Jan 2024 12:00:00 +0000",
			expectNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := strings.Join(strings.Fields(tt.receivedValue), " ")
			tls := parseReceivedTLS(normalized)

			if tt.expectNil {
				if tls != nil {
					t.Fatalf("expected nil TLS info, got %+v", tls)
				}
				return
			}

			if tls == nil {
				t.Fatal("parseReceivedTLS returned nil")
			}
			if !equalStrPtr(tls.Version, tt.expectVersion) {
				t.Errorf("Version = %v, want %v", ptrToStr(tls.Version), ptrToStr(tt.expectVersion))
			}
			if !equalStrPtr(tls.Cipher, tt.expectCipher) {
				t.Errorf("Cipher = %v, want %v", ptrToStr(tls.Cipher), ptrToStr(tt.expectCipher))
			}
			if (tls.Bits == nil) != (tt.expectBits == nil) || (tls.Bits != nil && *tls.Bits != *tt.expectBits) {
				t.Errorf("Bits = %v, want %v", tls.Bits, tt.expectBits)
			}
			if (tls.Verified == nil) != (tt.expectVerified == nil) || (tls.Verified != nil && *tls.Verified != *tt.expectVerified) {
				t.Errorf("Verified = %v, want %v", tls.Verified, tt.expectVerified)
			}
		})
	}
}

func TestGenerateHeaderAnalysis_WithReceivedChain(t *testing.T) {
	analyzer := NewHeaderAnalyzer()

	email := &mailmsg.Message{
		Header: createHeaderWithFields(map[string]string{
			"From":       "sender@example.com",
			"To":         "recipient@example.com",
			"Subject":    "Test",
			"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
			"Message-ID": "<abc123@example.com>",
		}),
		MessageID: "<abc123@example.com>",
		Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
		Parts:     []mailmsg.Part{{ContentType: "text/plain", Content: "test"}},
	}

	// Add Received headers
	email.Header["Received"] = []string{
		"from mail.example.com (mail.example.com [192.0.2.1]) by mx.receiver.com with ESMTP id ABC123; Mon, 01 Jan 2024 12:00:00 +0000",
		"from relay.example.com (relay.example.com [192.0.2.2]) by mail.example.com with SMTP id DEF456; Mon, 01 Jan 2024 11:59:00 +0000",
	}

	analysis := analyzer.GenerateHeaderAnalysis(email, nil)

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

// TestHeaderAnalyzer_ParseEmailDate exercises parseEmailDate. Accepted input
// is an RFC 5322-style date, with or without a leading day-of-week, a
// single- or double-digit day, and either a numeric zone offset ("-0700") or
// zone abbreviation ("MST"), optionally followed by a parenthesized zone
// comment ("+0000 (UTC)") — e.g. "Mon, 02 Jan 2006 15:04:05 -0700" and
// "2 Jan 2006 15:04:05 -0700" both parse. Anything else fails, including
// well-formed-but-different formats: an empty string, free text ("not a
// date"), and even ISO 8601 ("2024-01-01T12:00:00Z") are all rejected.
func TestHeaderAnalyzer_ParseEmailDate(t *testing.T) {
	tests := []struct {
		name        string
		dateStr     string
		expectError bool
		expectYear  int
		expectMonth int
		expectDay   int
	}{
		{
			name:        "RFC1123Z format",
			dateStr:     "Mon, 02 Jan 2006 15:04:05 -0700",
			expectError: false,
			expectYear:  2006,
			expectMonth: 1,
			expectDay:   2,
		},
		{
			name:        "RFC1123 format",
			dateStr:     "Mon, 02 Jan 2006 15:04:05 MST",
			expectError: false,
			expectYear:  2006,
			expectMonth: 1,
			expectDay:   2,
		},
		{
			name:        "Single digit day",
			dateStr:     "Mon, 2 Jan 2006 15:04:05 -0700",
			expectError: false,
			expectYear:  2006,
			expectMonth: 1,
			expectDay:   2,
		},
		{
			name:        "Without day of week",
			dateStr:     "2 Jan 2006 15:04:05 -0700",
			expectError: false,
			expectYear:  2006,
			expectMonth: 1,
			expectDay:   2,
		},
		{
			name:        "With timezone name in parentheses",
			dateStr:     "Mon, 01 Jan 2024 12:00:00 +0000 (UTC)",
			expectError: false,
			expectYear:  2024,
			expectMonth: 1,
			expectDay:   1,
		},
		{
			name:        "With timezone name in parentheses 2",
			dateStr:     "Sun, 19 Oct 2025 09:40:33 +0000 (UTC)",
			expectError: false,
			expectYear:  2025,
			expectMonth: 10,
			expectDay:   19,
		},
		{
			name:        "With CEST timezone",
			dateStr:     "Fri, 24 Oct 2025 04:17:25 +0200 (CEST)",
			expectError: false,
			expectYear:  2025,
			expectMonth: 10,
			expectDay:   24,
		},
		{
			name:        "Invalid date format",
			dateStr:     "not a date",
			expectError: true,
		},
		{
			name:        "Empty string",
			dateStr:     "",
			expectError: true,
		},
		{
			name:        "ISO 8601 format (should fail)",
			dateStr:     "2024-01-01T12:00:00Z",
			expectError: true,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzer.parseEmailDate(tt.dateStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("parseEmailDate(%q) expected error, got nil", tt.dateStr)
				}
			} else {
				if err != nil {
					t.Errorf("parseEmailDate(%q) unexpected error: %v", tt.dateStr, err)
					return
				}

				if result.Year() != tt.expectYear {
					t.Errorf("Year = %d, want %d", result.Year(), tt.expectYear)
				}
				if int(result.Month()) != tt.expectMonth {
					t.Errorf("Month = %d, want %d", result.Month(), tt.expectMonth)
				}
				if result.Day() != tt.expectDay {
					t.Errorf("Day = %d, want %d", result.Day(), tt.expectDay)
				}
			}
		})
	}
}

func TestCheckHeader_DateValidation(t *testing.T) {
	tests := []struct {
		name              string
		dateValue         string
		expectedValid     bool
		expectedIssuesLen int
	}{
		{
			name:              "Valid RFC1123Z date",
			dateValue:         "Mon, 02 Jan 2006 15:04:05 -0700",
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
		{
			name:              "Valid date with timezone name",
			dateValue:         "Mon, 01 Jan 2024 12:00:00 +0000 (UTC)",
			expectedValid:     true,
			expectedIssuesLen: 0,
		},
		{
			name:              "Invalid date format",
			dateValue:         "2024-01-01",
			expectedValid:     false,
			expectedIssuesLen: 1,
		},
		{
			name:              "Invalid date string",
			dateValue:         "not a date",
			expectedValid:     false,
			expectedIssuesLen: 1,
		},
		{
			name:              "Empty date",
			dateValue:         "",
			expectedValid:     false,
			expectedIssuesLen: 1,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					"Date": tt.dateValue,
				}),
			}

			check, issues := analyzer.checkHeader(email, "Date", "required")

			if check.Valid != nil && *check.Valid != tt.expectedValid {
				t.Errorf("Valid = %v, want %v", *check.Valid, tt.expectedValid)
			}

			issuesLen := len(issues)
			if issuesLen != tt.expectedIssuesLen {
				t.Errorf("Issues length = %d, want %d (issues: %v)", issuesLen, tt.expectedIssuesLen, issues)
			}
		})
	}
}

// TestHasReplyPrefix exercises hasReplyPrefix, which reports true if the
// subject, case-insensitively, starts with one of a fixed list of
// reply/forward markers immediately followed by ":" — "re:", "fwd:", "fw:",
// plus non-English equivalents like German "aw:"/"wg:" or French "rép:"/
// "tr:" (e.g. "RE: Hello" and "aw: Hallo" both match). A word that merely
// starts with the same letters but isn't followed by ":" at that position
// does not match, even if it looks similar — "react:" doesn't match "re:"
// (the third character is "a", not ":"), and "reference:" doesn't either.
func TestHasReplyPrefix(t *testing.T) {
	tests := []struct {
		subject  string
		expected bool
	}{
		// Positive cases
		{"Re: Hello", true},
		{"RE: Hello", true},
		{"re: Hello", true},
		{"Fwd: Hello", true},
		{"FWD: Hello", true},
		{"fw: Hello", true},
		{"FW: Hello", true},
		{"Aw: Hallo", true},
		{"WG: Weitergeleitet", true},
		{"Sv: Hej", true},
		{"Vs: Vastaus", true},
		{"Ref: something", true},
		{"Rép: Bonjour", true},
		{"TR: Transféré", true},
		{"Odp: Odpowiedź", true},
		{"Ynt: Yanıt", true},
		{"Res: Resposta", true},
		{"Enc: Reenviado", true},
		{"Vl: Verwijzing", true},
		{"Antw: Antwoord", true},
		{"Rv: Svar", true},
		// Negative cases
		{"Hello", false},
		{"", false},
		{"react: something", false},
		{"reference: check this", false},
		{"Resources available", false},
		{"Friendly reminder", false},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			result := analyzer.hasReplyPrefix(tt.subject)
			if result != tt.expected {
				t.Errorf("hasReplyPrefix(%q) = %v, want %v", tt.subject, result, tt.expected)
			}
		})
	}
}

func TestFindHeaderIssues_FakeReply(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		expectIssueType string // non-empty means we expect an issue containing this substring
	}{
		{
			name: "Re: subject without thread headers",
			headers: map[string]string{
				"From":       "sender@example.com",
				"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
				"Message-ID": "<abc@example.com>",
				"Subject":    "Re: Your invoice",
			},
			expectIssueType: "References or In-Reply-To",
		},
		{
			name: "Fwd: subject without thread headers",
			headers: map[string]string{
				"From":       "sender@example.com",
				"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
				"Message-ID": "<abc@example.com>",
				"Subject":    "Fwd: Important update",
			},
			expectIssueType: "References or In-Reply-To",
		},
		{
			name: "Re: subject with References header - no issue",
			headers: map[string]string{
				"From":       "sender@example.com",
				"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
				"Message-ID": "<abc@example.com>",
				"Subject":    "Re: Your invoice",
				"References": "<original@example.com>",
			},
			expectIssueType: "",
		},
		{
			name: "Re: subject with In-Reply-To only - no issue",
			headers: map[string]string{
				"From":        "sender@example.com",
				"Date":        "Mon, 01 Jan 2024 12:00:00 +0000",
				"Message-ID":  "<abc@example.com>",
				"Subject":     "Re: Your invoice",
				"In-Reply-To": "<original@example.com>",
			},
			expectIssueType: "",
		},
		{
			name: "Normal subject without thread headers - no issue",
			headers: map[string]string{
				"From":       "sender@example.com",
				"Date":       "Mon, 01 Jan 2024 12:00:00 +0000",
				"Message-ID": "<abc@example.com>",
				"Subject":    "Your invoice",
			},
			expectIssueType: "",
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: createHeaderWithFields(tt.headers),
			}

			issues := analyzer.findHeaderIssues(email)

			found := false
			for _, issue := range issues {
				if strings.Contains(issue.Message, tt.expectIssueType) {
					found = true
					break
				}
			}

			if tt.expectIssueType != "" && !found {
				t.Errorf("expected issue containing %q, but none found (issues: %v)", tt.expectIssueType, issues)
			}
			if tt.expectIssueType == "" {
				for _, issue := range issues {
					if strings.Contains(issue.Message, "References or In-Reply-To") {
						t.Errorf("unexpected fake-reply issue found: %s", issue.Message)
					}
				}
			}
		})
	}
}

func TestCheckHeaderReportsIssues(t *testing.T) {
	analyzer := NewHeaderAnalyzer()
	tests := []struct {
		name, header, value, importance string
		wantType                        model.IssueType
		wantSeverity                    model.IssueSeverity
	}{
		{"missing From", "From", "", "required", model.IssueTypeMissingHeader, model.IssueSeverityCritical},
		{"missing To", "To", "", "required", model.IssueTypeMissingHeader, model.IssueSeverityMedium},
		{"unreadable Date", "Date", "yesterday", "required", model.IssueTypeInvalidDate, model.IssueSeverityMedium},
		{"MIME-Version 2.0", "MIME-Version", "2.0", "recommended", model.IssueTypeInvalidMimeVersion, model.IssueSeverityLow},
		{"malformed From", "From", "not an address", "required", model.IssueTypeInvalidAddress, model.IssueSeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{Header: createHeaderWithFields(map[string]string{tt.header: tt.value})}
			check, issues := analyzer.checkHeader(email, tt.header, tt.importance)
			if len(issues) != 1 || issues[0].Type != tt.wantType || issues[0].Severity != tt.wantSeverity || utils.Deref(issues[0].Location) != tt.header {
				t.Fatalf("issues = %+v, want one %s (%s) at %s", issues, tt.wantType, tt.wantSeverity, tt.header)
			}
			if check.Valid == nil || *check.Valid {
				t.Errorf("Valid = %v, want false", check.Valid)
			}
		})
	}

	// Two Message-ID headers
	email := &mailmsg.Message{Header: mail.Header{"Message-Id": {"<a@example.com>", "<b@example.com>"}}}
	if _, issues := analyzer.checkHeader(email, "Message-ID", "required"); fmt.Sprint(issueTypes(issues)) != fmt.Sprint([]model.IssueType{model.IssueTypeDuplicateHeader}) {
		t.Errorf("duplicate Message-ID: issues = %v", issueTypes(issues))
	}
}

// A malformed Message-ID used to be reported by checkHeader and findHeaderIssues both.
func TestGenerateHeaderAnalysisReportsMessageIDOnce(t *testing.T) {
	email := &mailmsg.Message{Header: createHeaderWithFields(map[string]string{
		"From": "sender@example.com", "To": "rcpt@example.com", "Subject": "Hi",
		"Date": "Mon, 01 Jan 2024 12:00:00 +0000", "Message-ID": "not-a-message-id",
	})}
	analysis := NewHeaderAnalyzer().GenerateHeaderAnalysis(email, nil)
	n := 0
	for _, issue := range *analysis.Issues.Headers {
		if issue.Type == model.IssueTypeInvalidMessageId {
			n++
		}
	}
	if n != 1 {
		t.Errorf("invalid_message_id reported %d times, want once", n)
	}
}

// Header issues are Issues located at their header, filed under
// deliverability, and not charged one by one.
func TestFindHeaderIssuesLocatesEachAtItsHeader(t *testing.T) {
	email := &mailmsg.Message{Header: createHeaderWithFields(map[string]string{
		"From":       "sender@example.com",
		"Message-ID": "not-an-id",
		"Subject":    "Re: hello",
	})}

	issues := NewHeaderAnalyzer().findHeaderIssues(email)

	// The missing Date and the malformed Message-ID are checkHeader's to report
	want := map[string]model.IssueType{
		"Subject": model.IssueTypeReplyWithoutReferences,
	}
	if len(issues) != len(want) {
		t.Fatalf("%d issues, want %d", len(issues), len(want))
	}
	for _, issue := range issues {
		if issue.Location == nil || want[*issue.Location] != issue.Type {
			t.Errorf("%s located at %v", issue.Type, issue.Location)
		}
		if issue.Category != model.IssueCategoryDeliverability {
			t.Errorf("%s filed under %s", issue.Type, issue.Category)
		}
		if issue.Penalty != nil {
			t.Errorf("%s charged %d, header issues are not charged", issue.Type, *issue.Penalty)
		}
	}
}

// Helper functions for testing
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

func TestAnalyzeDomainAlignment_WithDKIM(t *testing.T) {
	tests := []struct {
		name                 string
		fromHeader           string
		returnPath           string
		dkimDomains          []string
		expectStrictAligned  bool
		expectRelaxedAligned bool
		expectIssues         []model.IssueType
		expectScore          int
	}{
		{
			name:                 "DKIM strict alignment with From domain",
			fromHeader:           "sender@example.com",
			returnPath:           "",
			dkimDomains:          []string{"example.com"},
			expectStrictAligned:  true,
			expectRelaxedAligned: true,
			expectIssues:         nil,
			expectScore:          25,
		},
		{
			name:                 "DKIM relaxed alignment only",
			fromHeader:           "sender@mail.example.com",
			returnPath:           "",
			dkimDomains:          []string{"example.com"},
			expectStrictAligned:  false,
			expectRelaxedAligned: true,
			expectIssues:         []model.IssueType{model.IssueTypeDomainRelaxedAligned},
			expectScore:          20,
		},
		{
			name:                 "DKIM no alignment",
			fromHeader:           "sender@example.com",
			returnPath:           "",
			dkimDomains:          []string{"different.com"},
			expectStrictAligned:  false,
			expectRelaxedAligned: false,
			expectIssues:         []model.IssueType{model.IssueTypeDomainMisaligned},
			expectScore:          0,
		},
		{
			name:                 "Multiple DKIM signatures - one aligns",
			fromHeader:           "sender@example.com",
			returnPath:           "",
			dkimDomains:          []string{"different.com", "example.com"},
			expectStrictAligned:  true,
			expectRelaxedAligned: true,
			expectIssues:         nil,
			expectScore:          25,
		},
		{
			name:                 "Return-Path misaligned but DKIM aligned",
			fromHeader:           "sender@example.com",
			returnPath:           "bounce@different.com",
			dkimDomains:          []string{"example.com"},
			expectStrictAligned:  true,
			expectRelaxedAligned: true,
			expectIssues:         []model.IssueType{model.IssueTypeReturnPathMisaligned},
			expectScore:          25,
		},
		{
			name:                 "Return-Path aligned, no DKIM",
			fromHeader:           "sender@example.com",
			returnPath:           "bounce@example.com",
			dkimDomains:          []string{},
			expectStrictAligned:  true,
			expectRelaxedAligned: true,
			expectIssues:         nil,
			expectScore:          25,
		},
		{
			name:                 "Both Return-Path and DKIM misaligned",
			fromHeader:           "sender@example.com",
			returnPath:           "bounce@other.com",
			dkimDomains:          []string{"different.com"},
			expectStrictAligned:  false,
			expectRelaxedAligned: false,
			expectIssues:         []model.IssueType{model.IssueTypeDomainMisaligned},
			expectScore:          0,
		},
	}

	analyzer := NewHeaderAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: createHeaderWithFields(map[string]string{
					"From":        tt.fromHeader,
					"Return-Path": tt.returnPath,
				}),
			}

			// Create authentication results with DKIM signatures
			var authResults *model.AuthenticationResults
			if len(tt.dkimDomains) > 0 {
				dkimResults := make([]model.AuthResult, 0, len(tt.dkimDomains))
				for _, domain := range tt.dkimDomains {
					dkimResults = append(dkimResults, model.AuthResult{
						Result: model.AuthResultResultPass,
						Domain: &domain,
					})
				}
				authResults = &model.AuthenticationResults{
					Dkim: &dkimResults,
				}
			}

			alignment := analyzer.analyzeDomainAlignment(email, authResults)

			if alignment == nil {
				t.Fatal("Expected non-nil alignment")
			}

			if alignment.Aligned == nil {
				t.Fatal("Expected non-nil Aligned field")
			}

			if *alignment.Aligned != tt.expectStrictAligned {
				t.Errorf("Aligned = %v, want %v", *alignment.Aligned, tt.expectStrictAligned)
			}

			if alignment.RelaxedAligned == nil {
				t.Fatal("Expected non-nil RelaxedAligned field")
			}

			if *alignment.RelaxedAligned != tt.expectRelaxedAligned {
				t.Errorf("RelaxedAligned = %v, want %v", *alignment.RelaxedAligned, tt.expectRelaxedAligned)
			}

			// Check DKIM domains are populated
			if len(tt.dkimDomains) > 0 {
				if alignment.DkimDomains == nil {
					t.Error("Expected DkimDomains to be populated")
				} else if len(*alignment.DkimDomains) != len(tt.dkimDomains) {
					t.Errorf("Expected %d DKIM domains, got %d", len(tt.dkimDomains), len(*alignment.DkimDomains))
				}
			}

			score, issues := calculateAlignmentScore(alignment, nil)
			if score != tt.expectScore {
				t.Errorf("score = %d, want %d", score, tt.expectScore)
			}
			if fmt.Sprint(issueTypes(issues)) != fmt.Sprint(tt.expectIssues) {
				t.Errorf("issues = %v, want %v", issueTypes(issues), tt.expectIssues)
			}
			if got := penalties(issues); got != 25-score {
				t.Errorf("penalties add up to %d, the alignment lost %d", got, 25-score)
			}
		})
	}
}

// DMARC aligns each identity in the mode its policy sets for it: a domain
// sharing the organizational domain only counts in relaxed mode.
func TestAlignmentScoreFollowsDMARCModes(t *testing.T) {
	alignment := &model.DomainAlignment{
		FromDomain:          utils.PtrTo("example.com"),
		FromOrgDomain:       utils.PtrTo("example.com"),
		ReturnPathDomain:    utils.PtrTo("mailer.example.net"),
		ReturnPathOrgDomain: utils.PtrTo("example.net"),
		DkimDomains:         &[]model.DKIMDomainInfo{{Domain: "news.example.com", OrgDomain: "example.com"}},
	}
	record := func(aspf, adkim string) *model.DMARCRecord {
		return &model.DMARCRecord{
			Valid:         true,
			SpfAlignment:  utils.PtrTo(model.DMARCRecordSpfAlignment(aspf)),
			DkimAlignment: utils.PtrTo(model.DMARCRecordDkimAlignment(adkim)),
		}
	}

	tests := []struct {
		name   string
		dmarc  *model.DMARCRecord
		score  int
		issues []model.IssueType
	}{
		{"no record", nil, 20, []model.IssueType{model.IssueTypeDomainRelaxedAligned, model.IssueTypeReturnPathMisaligned}},
		{"relaxed", record("relaxed", "relaxed"), 20, []model.IssueType{model.IssueTypeDomainRelaxedAligned, model.IssueTypeReturnPathMisaligned}},
		{"strict DKIM", record("relaxed", "strict"), 0, []model.IssueType{model.IssueTypeDomainMisaligned}},
		// An invalid record has no mode to impose
		{"invalid record", &model.DMARCRecord{DkimAlignment: utils.PtrTo(model.DMARCRecordDkimAlignmentStrict)}, 20, []model.IssueType{model.IssueTypeDomainRelaxedAligned, model.IssueTypeReturnPathMisaligned}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, issues := calculateAlignmentScore(alignment, tt.dmarc)
			if score != tt.score {
				t.Errorf("score = %d, want %d", score, tt.score)
			}
			if fmt.Sprint(issueTypes(issues)) != fmt.Sprint(tt.issues) {
				t.Errorf("issues = %v, want %v", issueTypes(issues), tt.issues)
			}
			if got := penalties(issues); got != 25-score {
				t.Errorf("penalties add up to %d, the alignment lost %d", got, 25-score)
			}
		})
	}

	// Strict SPF with the same Return-Path domain: aligned, while a DKIM
	// signature of a subdomain only counts as long as adkim is relaxed.
	sameRP := *alignment
	sameRP.ReturnPathDomain, sameRP.ReturnPathOrgDomain = utils.PtrTo("example.com"), utils.PtrTo("example.com")
	score, issues := calculateAlignmentScore(&sameRP, record("strict", "strict"))
	if score != 25 || fmt.Sprint(issueTypes(issues)) != fmt.Sprint([]model.IssueType{model.IssueTypeDkimMisaligned}) {
		t.Errorf("score = %d, issues = %v, want 25 and dkim_misaligned", score, issueTypes(issues))
	}
	if !strings.Contains(issues[0].Message, "adkim=s") {
		t.Errorf("message = %q, want it to name adkim=s", issues[0].Message)
	}

	// Strict SPF with a Return-Path on a subdomain: misaligned, and the
	// message says aspf=s is why.
	subRP := *alignment
	subRP.ReturnPathDomain, subRP.ReturnPathOrgDomain = utils.PtrTo("bounce.example.com"), utils.PtrTo("example.com")
	subRP.DkimDomains = &[]model.DKIMDomainInfo{{Domain: "esp.example.net", OrgDomain: "example.net"}}
	score, issues = calculateAlignmentScore(&subRP, record("strict", "relaxed"))
	if score != 0 || len(issues) != 1 || issues[0].Type != model.IssueTypeDomainMisaligned || !strings.Contains(issues[0].Message, "aspf=s") {
		t.Errorf("score = %d, issues = %+v, want 0 and domain_misaligned naming aspf=s", score, issues)
	}
}
