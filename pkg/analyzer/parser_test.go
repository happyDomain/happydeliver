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
	"strings"
	"testing"
)

func TestParseEmail_SimplePlainText(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Message-ID: <test123@example.com>
Date: Mon, 15 Oct 2025 12:00:00 +0000

This is a plain text email body.
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if email.From.Address != "sender@example.com" {
		t.Errorf("Expected From: sender@example.com, got: %s", email.From.Address)
	}

	if email.Subject != "Test Email" {
		t.Errorf("Expected Subject: Test Email, got: %s", email.Subject)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}

	if !email.Parts[0].IsText {
		t.Error("Expected part to be text")
	}

	if !strings.Contains(email.Parts[0].Content, "plain text email body") {
		t.Error("Expected body content not found")
	}
}

func TestParseEmail_MultipartAlternative(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Multipart Email
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

This is the plain text version.

--boundary123
Content-Type: text/html; charset=utf-8

<html><body><p>This is the HTML version.</p></body></html>

--boundary123--
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if len(email.Parts) != 2 {
		t.Fatalf("Expected 2 parts, got: %d", len(email.Parts))
	}

	textParts := email.GetTextParts()
	if len(textParts) != 1 {
		t.Errorf("Expected 1 text part, got: %d", len(textParts))
	}

	htmlParts := email.GetHTMLParts()
	if len(htmlParts) != 1 {
		t.Errorf("Expected 1 HTML part, got: %d", len(htmlParts))
	}

	if !strings.Contains(htmlParts[0].Content, "<html>") {
		t.Error("Expected HTML content not found")
	}
}

func TestGetAuthenticationResults(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Authentication-Results: example.com; spf=pass smtp.mailfrom=sender@example.com
Authentication-Results: example.com; dkim=pass header.d=example.com

Body content.
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	authResults := email.GetAuthenticationResults("example.com")
	if len(authResults) != 2 {
		t.Errorf("Expected 2 Authentication-Results headers, got: %d", len(authResults))
	}
}

func TestGetSpamAssassinHeaders(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
X-Spam-Status: No, score=2.3 required=5.0
X-Spam-Score: 2.3
X-Spam-Flag: NO

Body content.
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	saHeaders := email.GetSpamAssassinHeaders()
	if len(saHeaders) != 3 {
		t.Errorf("Expected 3 SpamAssassin headers, got: %d", len(saHeaders))
	}

	if saHeaders["X-Spam-Score"] != "2.3" {
		t.Errorf("Expected X-Spam-Score: 2.3, got: %s", saHeaders["X-Spam-Score"])
	}
}

func TestHasHeader(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Message-ID: <test123@example.com>

Body content.
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if !email.HasHeader("Message-ID") {
		t.Error("Expected Message-ID header to exist")
	}

	if email.HasHeader("List-Unsubscribe") {
		t.Error("Expected List-Unsubscribe header to not exist")
	}
}

func TestParseAuthservID(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "bare authserv-id",
			value:    "mx.example.com; spf=pass smtp.mailfrom=sender@example.net",
			expected: "mx.example.com",
		},
		{
			name:     "version token is not part of the identifier",
			value:    "mx.example.com 1; dkim=pass header.d=example.net",
			expected: "mx.example.com",
		},
		{
			name:     "whitespace before the first result",
			value:    "  mx.example.com ; dmarc=pass header.from=example.net",
			expected: "mx.example.com",
		},
		{
			name:     "CFWS comment after the identifier",
			value:    "mx.example.com (happyDeliver); spf=pass",
			expected: "mx.example.com",
		},
		{
			name:     "CFWS comment before the identifier",
			value:    "(added by) mx.example.com; spf=pass",
			expected: "mx.example.com",
		},
		{
			name:     "quoted identifier",
			value:    `"mx.example.com"; spf=pass`,
			expected: "mx.example.com",
		},
		{
			name:     "semicolon inside a comment does not end the identifier",
			value:    "mx.example.com (a; b); spf=pass",
			expected: "mx.example.com",
		},
		{
			name:     "no result at all",
			value:    "mx.example.com; none",
			expected: "mx.example.com",
		},
		{
			name:     "empty value",
			value:    "",
			expected: "",
		},
		{
			name:     "comment only",
			value:    "(nothing here)",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseAuthservID(tt.value); got != tt.expected {
				t.Errorf("parseAuthservID(%q) = %q, expected %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestAuthservIDs(t *testing.T) {
	rawEmail := `From: sender@example.net
To: recipient@example.com
Subject: Test
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=sender@example.net
Authentication-Results: MX.EXAMPLE.COM; dkim=pass header.d=example.net
Authentication-Results: relay.example.org 1; dmarc=fail header.from=example.net

Body
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	// Topmost header first, and the case-insensitive duplicate is dropped
	expected := []string{"mx.example.com", "relay.example.org"}

	ids := email.AuthservIDs()
	if len(ids) != len(expected) {
		t.Fatalf("AuthservIDs() = %v, expected %v", ids, expected)
	}
	for i, want := range expected {
		if ids[i] != want {
			t.Errorf("AuthservIDs()[%d] = %q, expected %q", i, ids[i], want)
		}
	}
}

func TestGetAuthenticationResultsFiltersOnAuthservID(t *testing.T) {
	rawEmail := `From: sender@example.net
To: recipient@example.com
Subject: Test
Authentication-Results: mx.example.com 1 ; spf=pass smtp.mailfrom=sender@example.net
Authentication-Results: relay.example.org; spf=fail smtp.mailfrom=sender@example.net

Body
`

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	// The version token and the space before the semicolon must not defeat the match
	results := email.GetAuthenticationResults("mx.example.com")
	if len(results) != 1 {
		t.Fatalf("GetAuthenticationResults(mx.example.com) returned %d headers, expected 1: %v", len(results), results)
	}
	if !strings.Contains(results[0], "spf=pass") {
		t.Errorf("Expected the mx.example.com header, got %q", results[0])
	}

	// Matching is case-insensitive
	if got := email.GetAuthenticationResults("MX.Example.Com"); len(got) != 1 {
		t.Errorf("GetAuthenticationResults is case-sensitive: returned %d headers, expected 1", len(got))
	}

	// An unknown authority yields nothing
	if got := email.GetAuthenticationResults("other.example.net"); len(got) != 0 {
		t.Errorf("GetAuthenticationResults(other.example.net) returned %d headers, expected 0", len(got))
	}

	// No authority means everything is returned
	if got := email.GetAuthenticationResults(""); len(got) != 2 {
		t.Errorf("GetAuthenticationResults(\"\") returned %d headers, expected 2", len(got))
	}
}
