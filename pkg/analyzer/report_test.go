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
	"time"

	"git.happydns.org/happyDeliver/internal/utils"
	"github.com/google/uuid"
)

func TestNewReportGenerator(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)
	if gen == nil {
		t.Fatal("Expected report generator, got nil")
	}

	if gen.authAnalyzer == nil {
		t.Error("authAnalyzer should not be nil")
	}
	if gen.spamAnalyzer == nil {
		t.Error("spamAnalyzer should not be nil")
	}
	if gen.dnsAnalyzer == nil {
		t.Error("dnsAnalyzer should not be nil")
	}
	if gen.rblChecker == nil {
		t.Error("rblChecker should not be nil")
	}
	if gen.contentAnalyzer == nil {
		t.Error("contentAnalyzer should not be nil")
	}
}

func TestAnalyzeEmail(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)

	email := createTestEmail()

	results := gen.AnalyzeEmail(email)

	if results == nil {
		t.Fatal("Expected analysis results, got nil")
	}

	if results.Email == nil {
		t.Error("Email should not be nil")
	}

	if results.Authentication == nil {
		t.Error("Authentication should not be nil")
	}
}

func TestGenerateReport(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)
	testID := uuid.New()

	email := createTestEmail()
	results := gen.AnalyzeEmail(email)

	report := gen.GenerateReport(testID, results)

	if report == nil {
		t.Fatal("Expected report, got nil")
	}

	// Verify required fields
	if report.Id == "" {
		t.Error("Report ID should not be empty")
	}

	// Convert testID to base32 for comparison
	expectedTestID := utils.UUIDToBase32(testID)
	if report.TestId != expectedTestID {
		t.Errorf("TestId = %s, want %s", report.TestId, expectedTestID)
	}

	if report.Score < 0 || report.Score > 100 {
		t.Errorf("Score %v is out of bounds", report.Score)
	}

	if report.Summary == nil {
		t.Error("Summary should not be nil")
	}

	// Verify score summary (all scores are 0-100 percentages)
	if report.Summary != nil {
		if report.Summary.AuthenticationScore < 0 || report.Summary.AuthenticationScore > 100 {
			t.Errorf("AuthenticationScore %v is out of bounds", report.Summary.AuthenticationScore)
		}
		if report.Summary.SpamScore < 0 || report.Summary.SpamScore > 100 {
			t.Errorf("SpamScore %v is out of bounds", report.Summary.SpamScore)
		}
		if report.Summary.BlacklistScore < 0 || report.Summary.BlacklistScore > 100 {
			t.Errorf("BlacklistScore %v is out of bounds", report.Summary.BlacklistScore)
		}
		if report.Summary.ContentScore < 0 || report.Summary.ContentScore > 100 {
			t.Errorf("ContentScore %v is out of bounds", report.Summary.ContentScore)
		}
		if report.Summary.HeaderScore < 0 || report.Summary.HeaderScore > 100 {
			t.Errorf("HeaderScore %v is out of bounds", report.Summary.HeaderScore)
		}
		if report.Summary.DnsScore < 0 || report.Summary.DnsScore > 100 {
			t.Errorf("DnsScore %v is out of bounds", report.Summary.DnsScore)
		}
	}
}

func TestGenerateReportWithSpamAssassin(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)
	testID := uuid.New()

	email := createTestEmailWithSpamAssassin()
	results := gen.AnalyzeEmail(email)

	report := gen.GenerateReport(testID, results)

	if report.Spamassassin == nil {
		t.Error("SpamAssassin result should not be nil")
	}

	if report.Spamassassin != nil {
		if report.Spamassassin.Score == 0 && report.Spamassassin.RequiredScore == 0 {
			t.Error("SpamAssassin scores should be set")
		}
	}
}

func TestGenerateRawEmail(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)

	tests := []struct {
		name     string
		email    *EmailMessage
		expected string
	}{
		{
			name:     "Nil email",
			email:    nil,
			expected: "",
		},
		{
			name: "Email with headers only",
			email: &EmailMessage{
				RawHeaders: "From: sender@example.com\nTo: recipient@example.com\n",
				RawBody:    "",
			},
			expected: "From: sender@example.com\nTo: recipient@example.com\n",
		},
		{
			name: "Email with headers and body",
			email: &EmailMessage{
				RawHeaders: "From: sender@example.com\n",
				RawBody:    "This is the email body",
			},
			expected: "From: sender@example.com\n\nThis is the email body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := gen.GenerateRawEmail(tt.email)
			if raw != tt.expected {
				t.Errorf("GenerateRawEmail() = %q, want %q", raw, tt.expected)
			}
		})
	}
}

// Helper functions

func createTestEmail() *EmailMessage {
	header := make(mail.Header)
	header[textproto.CanonicalMIMEHeaderKey("From")] = []string{"sender@example.com"}
	header[textproto.CanonicalMIMEHeaderKey("To")] = []string{"recipient@example.com"}
	header[textproto.CanonicalMIMEHeaderKey("Subject")] = []string{"Test Email"}
	header[textproto.CanonicalMIMEHeaderKey("Date")] = []string{"Mon, 01 Jan 2024 12:00:00 +0000"}
	header[textproto.CanonicalMIMEHeaderKey("Message-ID")] = []string{"<test123@example.com>"}

	return &EmailMessage{
		Header:    header,
		From:      &mail.Address{Address: "sender@example.com"},
		To:        []*mail.Address{{Address: "recipient@example.com"}},
		Subject:   "Test Email",
		MessageID: "<test123@example.com>",
		Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
		Parts: []MessagePart{
			{
				ContentType: "text/plain",
				Content:     "This is a test email",
				IsText:      true,
			},
		},
		RawHeaders: "From: sender@example.com\nTo: recipient@example.com\nSubject: Test Email\nDate: Mon, 01 Jan 2024 12:00:00 +0000\nMessage-ID: <test123@example.com>\n",
		RawBody:    "This is a test email",
	}
}

func createTestEmailWithSpamAssassin() *EmailMessage {
	email := createTestEmail()
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Status")] = []string{"No, score=2.3 required=5.0"}
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Score")] = []string{"2.3"}
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Flag")] = []string{"NO"}
	return email
}
