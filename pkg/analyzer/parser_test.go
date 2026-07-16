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

func TestParseEmail_Base64Attachment(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Attachment test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"See attached.\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: application/pdf; name=\"report.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"report.pdf\"\r\n" +
		"\r\n" +
		"JVBERi0xLjQK\r\n" +
		"JeLjz9MK\r\n" +
		"--BOUNDARY--\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(attachments))
	}

	att := attachments[0]
	if att.Filename != "report.pdf" {
		t.Errorf("Expected filename report.pdf, got %q", att.Filename)
	}
	if att.Disposition != "attachment" {
		t.Errorf("Expected disposition attachment, got %q", att.Disposition)
	}
	if att.IsInline() {
		t.Error("Attachment should not be inline")
	}

	decoded, err := att.DecodedBytes()
	if err != nil {
		t.Fatalf("DecodedBytes failed: %v", err)
	}
	if !strings.HasPrefix(string(decoded), "%PDF-1.4") {
		t.Errorf("Decoded content should start with %%PDF-1.4, got %q", string(decoded[:8]))
	}
}

func TestParseEmail_QuotedPrintableAttachment(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: QP test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/csv\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Content-Disposition: attachment; filename=\"data.csv\"\r\n" +
		"\r\n" +
		"col1;col2\r\n" +
		"caf=C3=A9;42\r\n" +
		"--BOUNDARY--\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(attachments))
	}

	decoded, err := attachments[0].DecodedBytes()
	if err != nil {
		t.Fatalf("DecodedBytes failed: %v", err)
	}
	if !strings.Contains(string(decoded), "café;42") {
		t.Errorf("Decoded content should contain café;42, got %q", string(decoded))
	}
}

func TestParseEmail_FilenameFromContentTypeName(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: name= fallback\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: application/octet-stream; name=\"legacy.bin\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"AAAA\r\n" +
		"--BOUNDARY--\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(attachments))
	}
	if attachments[0].Filename != "legacy.bin" {
		t.Errorf("Expected filename legacy.bin, got %q", attachments[0].Filename)
	}
}

func TestParseEmail_InlineImageWithContentID(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: inline image\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><img src=\"cid:logo@example.com\"></html>\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: inline\r\n" +
		"Content-ID: <logo@example.com>\r\n" +
		"\r\n" +
		"iVBORw0KGgo=\r\n" +
		"--BOUNDARY--\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment (the inline image), got %d", len(attachments))
	}

	att := attachments[0]
	if att.ContentID != "logo@example.com" {
		t.Errorf("Expected ContentID logo@example.com, got %q", att.ContentID)
	}
	if !att.IsInline() {
		t.Error("Part with inline disposition should be inline")
	}
}

func TestParseEmail_SinglePartPDF(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: bare pdf\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: application/pdf; name=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
		"\r\n" +
		"JVBERi0xLjQK\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(attachments))
	}

	att := attachments[0]
	if att.Filename != "doc.pdf" {
		t.Errorf("Expected filename doc.pdf, got %q", att.Filename)
	}
	decoded, err := att.DecodedBytes()
	if err != nil {
		t.Fatalf("DecodedBytes failed: %v", err)
	}
	if !strings.HasPrefix(string(decoded), "%PDF") {
		t.Errorf("Expected decoded PDF magic, got %q", string(decoded))
	}
}

func TestDecodedBytes_CorruptBase64(t *testing.T) {
	part := MessagePart{
		Encoding: "base64",
		Content:  "!!!not base64!!!",
	}
	if _, err := part.DecodedBytes(); err == nil {
		t.Error("Expected error decoding corrupt base64")
	}
}

func TestGetAttachments_NoAttachments(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: text only\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<p>Hello</p>\r\n" +
		"--BOUNDARY--\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if attachments := email.GetAttachments(); len(attachments) != 0 {
		t.Errorf("Expected no attachments, got %d", len(attachments))
	}
}
