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
	"encoding/base64"
	"fmt"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/pkg/grade"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// mzStub is a minimal PE-looking payload (MZ magic), which the attachment
// analysis reads as a Windows executable.
var mzStub = append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 62)...)

// buildAttachmentEmail assembles a multipart email carrying one attachment.
func buildAttachmentEmail(filename, contentType string, payload []byte) string {
	var sb strings.Builder
	sb.WriteString("From: sender@example.com\r\n")
	sb.WriteString("To: recipient@example.com\r\n")
	sb.WriteString("Subject: Attachment analysis test\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n")
	sb.WriteString("\r\n")
	sb.WriteString("--BOUNDARY\r\n")
	sb.WriteString("Content-Type: text/plain\r\n")
	sb.WriteString("\r\n")
	sb.WriteString("Please find the file attached.\r\n")
	sb.WriteString("--BOUNDARY\r\n")
	fmt.Fprintf(&sb, "Content-Type: %s; name=\"%s\"\r\n", contentType, filename)
	sb.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&sb, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename)
	sb.WriteString("\r\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(payload))
	sb.WriteString("\r\n--BOUNDARY--\r\n")
	return sb.String()
}

func TestNewReportGenerator(t *testing.T) {
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})
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
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})

	email := createTestEmail()

	results := gen.AnalyzeEmail(email, AnalysisOptions{})

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
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})
	testID := uuid.New()

	email := createTestEmail()
	results := gen.AnalyzeEmail(email, AnalysisOptions{})

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
		if report.Summary.AttachmentsScore < 0 || report.Summary.AttachmentsScore > 100 {
			t.Errorf("AttachmentsScore %v is out of bounds", report.Summary.AttachmentsScore)
		}
	}
}

// TestGenerateReportFoldsDomainReputationIntoBlacklistScore checks that a
// sender domain's reputation (from the checker-blacklist aggregation) is
// combined with the IP-level RBL score as the worse of the two, the same
// pattern already used to fold the DNSWL grade into the blacklist grade.
func TestGenerateReportFoldsDomainReputationIntoBlacklistScore(t *testing.T) {
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})

	// Half of the non-informational RBLs report a listing: a deterministic,
	// middling score/grade to combine the domain reputation against.
	rblResults := &DNSListResults{
		Checks:              map[string][]model.BlacklistCheck{"192.0.2.1": {{Rbl: "zen.spamhaus.org", Listed: true}}},
		IPsChecked:          []string{"192.0.2.1"},
		ListedCount:         6,
		RelevantListedCount: 6,
	}
	baseScore, baseGrade := gen.rblChecker.CalculateScore(rblResults, false)
	if baseGrade == "" {
		t.Fatalf("baseGrade is empty, fixture did not produce a scorable RBL result")
	}

	t.Run("domain reputation worse than RBL", func(t *testing.T) {
		repScore := 10
		domainRep := &model.DomainBlacklistResult{Score: &repScore}
		results := &AnalysisResults{RBL: rblResults, DNSWL: &DNSListResults{}, DomainReputation: domainRep}

		report := gen.GenerateReport(uuid.New(), results)

		wantScore := min(baseScore, repScore)
		wantGrade := grade.Min(baseGrade, grade.Of(repScore))
		if report.Summary.BlacklistScore != wantScore {
			t.Errorf("BlacklistScore = %d, want %d", report.Summary.BlacklistScore, wantScore)
		}
		if string(report.Summary.BlacklistGrade) != wantGrade {
			t.Errorf("BlacklistGrade = %s, want %s", report.Summary.BlacklistGrade, wantGrade)
		}
		if report.DomainReputation != domainRep {
			t.Errorf("DomainReputation = %v, want %v", report.DomainReputation, domainRep)
		}
	})

	t.Run("domain reputation better than RBL", func(t *testing.T) {
		repScore := 100
		domainRep := &model.DomainBlacklistResult{Score: &repScore}
		results := &AnalysisResults{RBL: rblResults, DNSWL: &DNSListResults{}, DomainReputation: domainRep}

		report := gen.GenerateReport(uuid.New(), results)

		wantScore := min(baseScore, repScore)
		wantGrade := grade.Min(baseGrade, grade.Of(repScore))
		if report.Summary.BlacklistScore != wantScore {
			t.Errorf("BlacklistScore = %d, want %d", report.Summary.BlacklistScore, wantScore)
		}
		if string(report.Summary.BlacklistGrade) != wantGrade {
			t.Errorf("BlacklistGrade = %s, want %s", report.Summary.BlacklistGrade, wantGrade)
		}
	})

	t.Run("domain reputation alone, no RBL data", func(t *testing.T) {
		for _, repScore := range []int{42, 90, 100} {
			domainRep := &model.DomainBlacklistResult{Score: &repScore}
			results := &AnalysisResults{DomainReputation: domainRep}

			report := gen.GenerateReport(uuid.New(), results)

			if report.Summary.BlacklistScore != repScore {
				t.Errorf("%d: BlacklistScore = %d, want %d", repScore, report.Summary.BlacklistScore, repScore)
			}
			if string(report.Summary.BlacklistGrade) != grade.Of(repScore) {
				t.Errorf("%d: BlacklistGrade = %q, want %q", repScore, report.Summary.BlacklistGrade, grade.Of(repScore))
			}
		}
	})

	// The DNSWLs vouching for a clean IP raise it to A+; a clean domain
	// does not cap it to its own A.
	t.Run("clean domain keeps a whitelisted sender's A+", func(t *testing.T) {
		repScore := 100
		results := &AnalysisResults{
			RBL:              &DNSListResults{IPsChecked: []string{"192.0.2.1"}},
			DNSWL:            &DNSListResults{IPsChecked: []string{"192.0.2.1"}, ListedCount: 1},
			DomainReputation: &model.DomainBlacklistResult{Score: &repScore},
		}

		report := gen.GenerateReport(uuid.New(), results)

		if report.Summary.BlacklistScore != 100 || report.Summary.BlacklistGrade != "A+" {
			t.Errorf("Blacklist = %d%% (%s), want 100%% (A+)", report.Summary.BlacklistScore, report.Summary.BlacklistGrade)
		}
	})

	t.Run("no domain reputation", func(t *testing.T) {
		results := &AnalysisResults{RBL: rblResults, DNSWL: &DNSListResults{}}

		report := gen.GenerateReport(uuid.New(), results)

		if report.Summary.BlacklistScore != baseScore {
			t.Errorf("BlacklistScore = %d, want %d (unaffected by absent reputation)", report.Summary.BlacklistScore, baseScore)
		}
		if report.DomainReputation != nil {
			t.Errorf("DomainReputation = %v, want nil", report.DomainReputation)
		}
	})
}

func TestGenerateReportAttachments(t *testing.T) {
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})
	testID := uuid.New()

	// An email without attachments leaves the category out of the scale
	// rather than earning a perfect mark on it.
	email := createTestEmail()
	report := gen.GenerateReport(testID, gen.AnalyzeEmail(email, AnalysisOptions{}))

	if report.Summary.AttachmentsGrade != "" {
		t.Errorf("AttachmentsGrade = %q without attachments, want no grade", report.Summary.AttachmentsGrade)
	}
	if report.AttachmentAnalysis == nil {
		t.Fatal("AttachmentAnalysis should be present")
	}
	if report.AttachmentAnalysis.HasAttachments {
		t.Error("HasAttachments should be false")
	}

	// Email with a disguised executable attachment tanks the category and
	// drags the overall grade down
	rawEmail := buildAttachmentEmail("invoice.pdf.exe", "application/pdf", mzStub)
	parsed, err := mailmsg.Parse([]byte(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}
	report = gen.GenerateReport(testID, gen.AnalyzeEmail(parsed, AnalysisOptions{}))

	if report.Summary.AttachmentsScore > 30 {
		t.Errorf("AttachmentsScore = %d for a disguised executable, want heavily degraded", report.Summary.AttachmentsScore)
	}
	if !report.AttachmentAnalysis.HasAttachments {
		t.Error("HasAttachments should be true")
	}
	if report.AttachmentAnalysis.Attachments == nil || len(*report.AttachmentAnalysis.Attachments) != 1 {
		t.Fatal("Expected one attachment check in the report")
	}
}

func TestGenerateReportWithSpamAssassin(t *testing.T) {
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})
	testID := uuid.New()

	email := createTestEmailWithSpamAssassin()
	results := gen.AnalyzeEmail(email, AnalysisOptions{})

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

// TestGenerateReportExcludesCategoriesThatDidNotRun checks that a category with no
// grade (blacklist: no IPs to check because the test email has no Received headers;
// spam: no SpamAssassin/rspamd result) is left out of both the overall score average
// and the overall grade, instead of being averaged in as if it scored 0.
func TestGenerateReportExcludesCategoriesThatDidNotRun(t *testing.T) {
	gen := NewReportGenerator(GeneratorOptions{DNSTimeout: 10 * time.Second, HTTPTimeout: 10 * time.Second, RBLs: DefaultRBLs, DNSWLs: DefaultDNSWLs})
	testID := uuid.New()

	email := createTestEmail()
	results := gen.AnalyzeEmail(email, AnalysisOptions{})

	report := gen.GenerateReport(testID, results)

	if report.Summary == nil {
		t.Fatal("Summary should not be nil")
	}

	if report.Summary.BlacklistGrade != "" {
		t.Fatalf("expected blacklist to have no grade (no IPs to check), got %q", report.Summary.BlacklistGrade)
	}
	if report.Summary.SpamGrade != "" {
		t.Fatalf("expected spam to have no grade (no filter ran), got %q", report.Summary.SpamGrade)
	}

	var totalScore, categoryCount int
	for _, s := range []struct {
		score int
		grade string
	}{
		{report.Summary.DnsScore, string(report.Summary.DnsGrade)},
		{report.Summary.AuthenticationScore, string(report.Summary.AuthenticationGrade)},
		{report.Summary.ContentScore, string(report.Summary.ContentGrade)},
		{report.Summary.HeaderScore, string(report.Summary.HeaderGrade)},
		{report.Summary.AttachmentsScore, string(report.Summary.AttachmentsGrade)},
	} {
		if s.grade == "" {
			continue
		}
		totalScore += s.score
		categoryCount++
	}
	expectedScore := totalScore / categoryCount

	if report.Score != expectedScore {
		t.Errorf("Score = %v, want %v (average of categories that ran, excluding blacklist and spam)", report.Score, expectedScore)
	}
}

// Helper functions

func createTestEmail() *mailmsg.Message {
	header := make(mail.Header)
	header[textproto.CanonicalMIMEHeaderKey("From")] = []string{"sender@example.com"}
	header[textproto.CanonicalMIMEHeaderKey("To")] = []string{"recipient@example.com"}
	header[textproto.CanonicalMIMEHeaderKey("Subject")] = []string{"Test Email"}
	header[textproto.CanonicalMIMEHeaderKey("Date")] = []string{"Mon, 01 Jan 2024 12:00:00 +0000"}
	header[textproto.CanonicalMIMEHeaderKey("Message-ID")] = []string{"<test123@example.com>"}

	return &mailmsg.Message{
		Header:    header,
		From:      &mail.Address{Address: "sender@example.com"},
		To:        []*mail.Address{{Address: "recipient@example.com"}},
		Subject:   "Test Email",
		MessageID: "<test123@example.com>",
		Date:      "Mon, 01 Jan 2024 12:00:00 +0000",
		Parts: []mailmsg.Part{
			{
				ContentType: "text/plain",
				Content:     "This is a test email",
				IsText:      true,
			},
		},
		RawHeaders: "From: sender@example.com\nTo: recipient@example.com\nSubject: Test Email\nDate: Mon, 01 Jan 2024 12:00:00 +0000\nMessage-ID: <test123@example.com>\n",
	}
}

func createTestEmailWithSpamAssassin() *mailmsg.Message {
	email := createTestEmail()
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Status")] = []string{"No, score=2.3 required=5.0"}
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Score")] = []string{"2.3"}
	email.Header[textproto.CanonicalMIMEHeaderKey("X-Spam-Flag")] = []string{"NO"}
	return email
}

// TestAnalyzeEmailSourceSelectsAuthservID checks which authority is trusted depending on
// where the message comes from: our own receiver hostname for a message we received, the
// topmost Authentication-Results header for a file the user supplied.
func TestAnalyzeEmailSourceSelectsAuthservID(t *testing.T) {
	newEmail := func() *mailmsg.Message {
		email := createTestEmail()
		email.Header[textproto.CanonicalMIMEHeaderKey("Authentication-Results")] = []string{
			"mx.example.org; spf=pass smtp.mailfrom=sender@example.com",
			"relay.example.net; spf=fail smtp.mailfrom=sender@example.com",
		}
		return email
	}

	t.Run("received message trusts the configured receiver hostname", func(t *testing.T) {
		gen := NewReportGenerator(GeneratorOptions{ReceiverHostname: "mx.example.org", DNSTimeout: time.Second, HTTPTimeout: time.Second})

		results := gen.AnalyzeEmail(newEmail(), AnalysisOptions{Source: model.ReportSourceReceived})

		if results.Source != model.ReportSourceReceived {
			t.Errorf("Source = %q, expected %q", results.Source, model.ReportSourceReceived)
		}
		if results.AuthservID != "mx.example.org" {
			t.Errorf("AuthservID = %q, expected mx.example.org", results.AuthservID)
		}
	})

	t.Run("received message ignores a foreign authority", func(t *testing.T) {
		gen := NewReportGenerator(GeneratorOptions{ReceiverHostname: "mx.happydeliver.test", DNSTimeout: time.Second, HTTPTimeout: time.Second})

		results := gen.AnalyzeEmail(newEmail(), AnalysisOptions{Source: model.ReportSourceReceived})

		if results.Authentication.Spf != nil {
			t.Errorf("Expected no SPF result from a foreign authority, got %+v", results.Authentication.Spf)
		}
	})

	t.Run("uploaded message trusts the topmost header", func(t *testing.T) {
		// The configured hostname appears nowhere in the file, yet the verdicts of the
		// server that actually received the message must still be read.
		gen := NewReportGenerator(GeneratorOptions{ReceiverHostname: "mx.happydeliver.test", DNSTimeout: time.Second, HTTPTimeout: time.Second})

		results := gen.AnalyzeEmail(newEmail(), AnalysisOptions{Source: model.ReportSourceUploaded})

		if results.Source != model.ReportSourceUploaded {
			t.Errorf("Source = %q, expected %q", results.Source, model.ReportSourceUploaded)
		}
		if results.AuthservID != "mx.example.org" {
			t.Errorf("AuthservID = %q, expected mx.example.org", results.AuthservID)
		}
		if results.Authentication.Spf == nil {
			t.Fatal("Expected the SPF result from mx.example.org, got none")
		}
		// The topmost header wins: pass, not the relay's fail
		if results.Authentication.Spf.Result != model.AuthResultResultPass {
			t.Errorf("Spf.Result = %q, expected pass", results.Authentication.Spf.Result)
		}

		report := gen.GenerateReport(uuid.New(), results)
		if report.Source == nil || *report.Source != model.ReportSourceUploaded {
			t.Errorf("report.Source = %v, expected %q", report.Source, model.ReportSourceUploaded)
		}
		if report.AuthservId == nil || *report.AuthservId != "mx.example.org" {
			t.Errorf("report.AuthservId = %v, expected mx.example.org", report.AuthservId)
		}
		if report.AuthservIdsFound == nil || len(*report.AuthservIdsFound) != 2 {
			t.Errorf("report.AuthservIdsFound = %v, expected both authorities", report.AuthservIdsFound)
		}
	})

	t.Run("uploaded message without any authentication header", func(t *testing.T) {
		gen := NewReportGenerator(GeneratorOptions{ReceiverHostname: "mx.happydeliver.test", DNSTimeout: time.Second, HTTPTimeout: time.Second})

		results := gen.AnalyzeEmail(createTestEmail(), AnalysisOptions{Source: model.ReportSourceUploaded})

		if results.AuthservID != "" {
			t.Errorf("AuthservID = %q, expected empty", results.AuthservID)
		}

		report := gen.GenerateReport(uuid.New(), results)
		if report.AuthservId != nil {
			t.Errorf("report.AuthservId = %v, expected nil", report.AuthservId)
		}
		if report.AuthservIdsFound != nil {
			t.Errorf("report.AuthservIdsFound = %v, expected nil", report.AuthservIdsFound)
		}
	})

	t.Run("default options record a received message", func(t *testing.T) {
		gen := NewReportGenerator(GeneratorOptions{ReceiverHostname: "mx.example.org", DNSTimeout: time.Second, HTTPTimeout: time.Second})

		results := gen.AnalyzeEmail(newEmail(), AnalysisOptions{})

		report := gen.GenerateReport(uuid.New(), results)
		if report.Source == nil || *report.Source != model.ReportSourceReceived {
			t.Errorf("report.Source = %v, expected %q", report.Source, model.ReportSourceReceived)
		}
	})
}
