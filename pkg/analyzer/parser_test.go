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
	"encoding/base64"
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

func TestParseEmail_QuotedPrintableBody(t *testing.T) {
	// A quoted-printable HTML part: =3D is `=`, =22 is `"`, and the trailing
	// `=` is a soft line break that splits the long URL.
	rawEmail := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: QP Test\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"<a href=3D=22https://example.com/subscription/4bdad7fe-ef=\r\n" +
		"36-4abc=22>Unsub</a>\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}

	content := email.Parts[0].Content
	want := `<a href="https://example.com/subscription/4bdad7fe-ef36-4abc">Unsub</a>`
	if !strings.Contains(content, want) {
		t.Errorf("Expected decoded content to contain %q, got: %q", want, content)
	}
	if strings.Contains(content, "3D") || strings.Contains(content, "=\r\n") {
		t.Errorf("Quoted-printable artifacts leaked into content: %q", content)
	}
}

func TestParseEmail_Base64Body(t *testing.T) {
	htmlSnippet := `<p>Hello <a href="https://example.com/x">link</a></p>`
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlSnippet))

	rawEmail := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: B64 Test\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + encoded + "\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}
	if got := email.Parts[0].Content; got != htmlSnippet {
		t.Errorf("Expected base64 round-trip %q, got: %q", htmlSnippet, got)
	}
}

func TestParseEmail_CharsetISO88591(t *testing.T) {
	// 0xE9 is 'é' in ISO-8859-1; it must become the UTF-8 form.
	rawEmail := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Charset Test\r\n" +
		"Content-Type: text/plain; charset=\"ISO-8859-1\"\r\n" +
		"\r\n" +
		"Caf\xe9 cr\xe8me\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}
	if got := email.Parts[0].Content; !strings.Contains(got, "Café crème") {
		t.Errorf("Expected charset-decoded UTF-8 'Café crème', got: %q", got)
	}
}

func TestDecodeBody_Passthrough(t *testing.T) {
	body := []byte("plain <a href=3D\"x\"> stays literal only if not QP")
	for _, enc := range []string{"7bit", "8bit", "binary", ""} {
		if got := decodeBody(body, enc, ""); got != string(body) {
			t.Errorf("encoding %q: expected passthrough, got: %q", enc, got)
		}
	}
}
