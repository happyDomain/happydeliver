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
	"time"

	"git.happydns.org/happyDeliver/internal/api"
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
	if gen.scorer == nil {
		t.Error("scorer should not be nil")
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

	// SpamAssassin might be nil if headers don't exist
	// DNS results should exist
	// RBL results should exist
	// Content results should exist

	if results.Score == nil {
		t.Error("Score should not be nil")
	}

	// Verify score is within bounds
	if results.Score.OverallScore < 0 || results.Score.OverallScore > 10 {
		t.Errorf("Overall score %v is out of bounds", results.Score.OverallScore)
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

	if report.Score < 0 || report.Score > 10 {
		t.Errorf("Score %v is out of bounds", report.Score)
	}

	if report.Summary == nil {
		t.Error("Summary should not be nil")
	}

	if len(report.Checks) == 0 {
		t.Error("Checks should not be empty")
	}

	// Verify score summary
	if report.Summary != nil {
		if report.Summary.AuthenticationScore < 0 || report.Summary.AuthenticationScore > 3 {
			t.Errorf("AuthenticationScore %v is out of bounds", report.Summary.AuthenticationScore)
		}
		if report.Summary.SpamScore < 0 || report.Summary.SpamScore > 2 {
			t.Errorf("SpamScore %v is out of bounds", report.Summary.SpamScore)
		}
		if report.Summary.BlacklistScore < 0 || report.Summary.BlacklistScore > 2 {
			t.Errorf("BlacklistScore %v is out of bounds", report.Summary.BlacklistScore)
		}
		if report.Summary.ContentScore < 0 || report.Summary.ContentScore > 2 {
			t.Errorf("ContentScore %v is out of bounds", report.Summary.ContentScore)
		}
		if report.Summary.HeaderScore < 0 || report.Summary.HeaderScore > 1 {
			t.Errorf("HeaderScore %v is out of bounds", report.Summary.HeaderScore)
		}
	}

	// Verify checks have required fields
	for i, check := range report.Checks {
		if string(check.Category) == "" {
			t.Errorf("Check %d: Category should not be empty", i)
		}
		if check.Name == "" {
			t.Errorf("Check %d: Name should not be empty", i)
		}
		if string(check.Status) == "" {
			t.Errorf("Check %d: Status should not be empty", i)
		}
		if check.Message == "" {
			t.Errorf("Check %d: Message should not be empty", i)
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

func TestBuildDNSRecords(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)

	tests := []struct {
		name          string
		dns           *DNSResults
		expectedCount int
		expectTypes   []api.DNSRecordRecordType
	}{
		{
			name:          "Nil DNS results",
			dns:           nil,
			expectedCount: 0,
		},
		{
			name: "Complete DNS results",
			dns: &DNSResults{
				Domain: "example.com",
				MXRecords: []MXRecord{
					{Host: "mail.example.com", Priority: 10, Valid: true},
				},
				SPFRecord: &SPFRecord{
					Record: "v=spf1 include:_spf.example.com -all",
					Valid:  true,
				},
				DKIMRecords: []DKIMRecord{
					{
						Selector: "default",
						Domain:   "example.com",
						Record:   "v=DKIM1; k=rsa; p=...",
						Valid:    true,
					},
				},
				DMARCRecord: &DMARCRecord{
					Record: "v=DMARC1; p=quarantine",
					Valid:  true,
				},
			},
			expectedCount: 4, // MX, SPF, DKIM, DMARC
			expectTypes:   []api.DNSRecordRecordType{api.MX, api.SPF, api.DKIM, api.DMARC},
		},
		{
			name: "Missing records",
			dns: &DNSResults{
				Domain: "example.com",
				SPFRecord: &SPFRecord{
					Valid: false,
					Error: "No SPF record found",
				},
			},
			expectedCount: 1,
			expectTypes:   []api.DNSRecordRecordType{api.SPF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := gen.buildDNSRecords(tt.dns)

			if len(records) != tt.expectedCount {
				t.Errorf("Got %d DNS records, want %d", len(records), tt.expectedCount)
			}

			// Verify expected types are present
			if tt.expectTypes != nil {
				foundTypes := make(map[api.DNSRecordRecordType]bool)
				for _, record := range records {
					foundTypes[record.RecordType] = true
				}

				for _, expectedType := range tt.expectTypes {
					if !foundTypes[expectedType] {
						t.Errorf("Expected DNS record type %s not found", expectedType)
					}
				}
			}

			// Verify all records have required fields
			for i, record := range records {
				if record.Domain == "" {
					t.Errorf("Record %d: Domain should not be empty", i)
				}
				if string(record.RecordType) == "" {
					t.Errorf("Record %d: RecordType should not be empty", i)
				}
				if string(record.Status) == "" {
					t.Errorf("Record %d: Status should not be empty", i)
				}
			}
		})
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

func TestGetRecommendations(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)

	tests := []struct {
		name        string
		results     *AnalysisResults
		expectCount int
	}{
		{
			name:        "Nil results",
			results:     nil,
			expectCount: 0,
		},
		{
			name: "Results with score",
			results: &AnalysisResults{
				Score: &ScoringResult{
					OverallScore:   5.0,
					Rating:         "Fair",
					AuthScore:      1.5,
					SpamScore:      1.0,
					BlacklistScore: 1.5,
					ContentScore:   0.5,
					HeaderScore:    0.5,
					Recommendations: []string{
						"Improve authentication",
						"Fix content issues",
					},
				},
			},
			expectCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := gen.GetRecommendations(tt.results)
			if len(recs) != tt.expectCount {
				t.Errorf("Got %d recommendations, want %d", len(recs), tt.expectCount)
			}
		})
	}
}

func TestGetScoreSummaryText(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)

	tests := []struct {
		name         string
		results      *AnalysisResults
		expectEmpty  bool
		expectString string
	}{
		{
			name:        "Nil results",
			results:     nil,
			expectEmpty: true,
		},
		{
			name: "Results with score",
			results: &AnalysisResults{
				Score: &ScoringResult{
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
				},
			},
			expectEmpty:  false,
			expectString: "8.5/10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := gen.GetScoreSummaryText(tt.results)
			if tt.expectEmpty {
				if summary != "" {
					t.Errorf("Expected empty summary, got %q", summary)
				}
			} else {
				if summary == "" {
					t.Error("Expected non-empty summary")
				}
				if tt.expectString != "" && !strings.Contains(summary, tt.expectString) {
					t.Errorf("Summary should contain %q, got %q", tt.expectString, summary)
				}
			}
		})
	}
}

func TestReportCategories(t *testing.T) {
	gen := NewReportGenerator(10*time.Second, 10*time.Second, DefaultRBLs)
	testID := uuid.New()

	email := createComprehensiveTestEmail()
	results := gen.AnalyzeEmail(email)
	report := gen.GenerateReport(testID, results)

	// Verify all check categories are present
	categories := make(map[api.CheckCategory]bool)
	for _, check := range report.Checks {
		categories[check.Category] = true
	}

	expectedCategories := []api.CheckCategory{
		api.Authentication,
		api.Dns,
		api.Headers,
	}

	for _, cat := range expectedCategories {
		if !categories[cat] {
			t.Errorf("Expected category %s not found in checks", cat)
		}
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

func createComprehensiveTestEmail() *EmailMessage {
	email := createTestEmailWithSpamAssassin()

	// Add authentication headers
	email.Header[textproto.CanonicalMIMEHeaderKey("Authentication-Results")] = []string{
		"example.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com; dmarc=pass",
	}

	// Add HTML content
	email.Parts = append(email.Parts, MessagePart{
		ContentType: "text/html",
		Content:     "<html><body><p>Test</p><a href='https://example.com'>Link</a></body></html>",
		IsHTML:      true,
	})

	return email
}
