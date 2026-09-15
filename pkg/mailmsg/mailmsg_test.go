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

package mailmsg

import (
	"encoding/base64"
	"net/mail"
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	authResults := email.GetAuthenticationResults("example.com")
	if len(authResults) != 2 {
		t.Errorf("Expected 2 Authentication-Results headers, got: %d", len(authResults))
	}
}

func TestHasHeader(t *testing.T) {
	rawEmail := `From: sender@example.com
To: recipient@example.com
Subject: Test Email
Message-ID: <test123@example.com>

Body content.
`

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

	email, err := Parse([]byte(rawEmail))
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

// singlePartEmail builds a one-part message with the given encoding, charset
// and body, so a decoding behaviour can be asserted through Parse rather
// than against an internal helper.
func singlePartEmail(t *testing.T, encoding, charset, body string) Part {
	t.Helper()

	contentType := "text/plain"
	if charset != "" {
		contentType += "; charset=\"" + charset + "\""
	}

	raw := "From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Encoding Test\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"Content-Transfer-Encoding: " + encoding + "\r\n" +
		"\r\n" + body

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}

	return email.Parts[0]
}

func TestParseEmail_EncodingPassthrough(t *testing.T) {
	body := "plain <a href=3D\"x\"> stays literal only if not QP"
	for _, enc := range []string{"7bit", "8bit", "binary", ""} {
		if got := singlePartEmail(t, enc, "", body).Content; got != body {
			t.Errorf("encoding %q: expected passthrough, got: %q", enc, got)
		}
	}
}

func TestParseEmail_UnknownEncodingPassthrough(t *testing.T) {
	// An encoding no library knows must not abort the parse: the payload is
	// handed over untouched so the rest of the report is still produced.
	body := "NOT-DECODED-RAW-PAYLOAD"
	if got := singlePartEmail(t, "x-nonsense", "", body).Content; !strings.Contains(got, body) {
		t.Errorf("expected raw payload %q to survive, got: %q", body, got)
	}
}

func TestParseEmail_QuotedPrintablePartialDecodeOnError(t *testing.T) {
	// "=3D" decodes to "=" cleanly; "=ZZ" is an invalid hex escape that
	// makes the reader error. The valid prefix must still come out decoded
	// rather than the whole part reverting to its raw encoded form.
	got := singlePartEmail(t, "quoted-printable", "", "hello=3Dworld=ZZ").Content
	if !strings.HasPrefix(got, "hello=world") {
		t.Errorf("expected decoded prefix %q, got: %q", "hello=world", got)
	}
	if strings.Contains(got, "=3D") {
		t.Errorf("quoted-printable prefix was reverted to raw encoded form: %q", got)
	}
}

func TestParseEmail_Base64Whitespace(t *testing.T) {
	// MIME line breaks are ignored by the decoder itself, but some encoders
	// also indent continuation lines: both must decode to the same thing as
	// the unbroken payload.
	encoded := base64.StdEncoding.EncodeToString([]byte("hello whitespace world"))
	for name, body := range map[string]string{
		"plain":    encoded,
		"crlf":     encoded[:8] + "\r\n" + encoded[8:],
		"indented": encoded[:8] + "\r\n\t " + encoded[8:],
	} {
		if got := singlePartEmail(t, "base64", "", body).Content; got != "hello whitespace world" {
			t.Errorf("%s: expected %q, got %q", name, "hello whitespace world", got)
		}
	}
}

func TestParseEmail_Base64PartialDecodeOnError(t *testing.T) {
	// A valid base64-encoded "hello" followed by characters outside the
	// base64 alphabet, which makes the decoder error partway through.
	body := base64.StdEncoding.EncodeToString([]byte("hello")) + "!!!!"
	got := singlePartEmail(t, "base64", "", body).Content
	if !strings.HasPrefix(got, "hello") {
		t.Errorf("expected decoded prefix %q, got: %q", "hello", got)
	}
}

func TestParseEmail_DecodesEncodedWords(t *testing.T) {
	// RFC 2047 encoded words in Subject and in a From display name must reach
	// the report as the text a mail client would show.
	raw := "From: =?UTF-8?Q?Caf=C3=A9_Cr=C3=A8me?= <sender@example.com>\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: =?ISO-8859-1?Q?Re=3A_d=E9j=E0_vu?=\r\n" +
		"\r\n" +
		"body\r\n"

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if want := "Re: déjà vu"; email.Subject != want {
		t.Errorf("Expected decoded subject %q, got: %q", want, email.Subject)
	}
	if email.From == nil {
		t.Fatal("Expected a From address")
	}
	if want := "Café Crème"; email.From.Name != want {
		t.Errorf("Expected decoded display name %q, got: %q", want, email.From.Name)
	}
	if email.From.Address != "sender@example.com" {
		t.Errorf("Expected From address sender@example.com, got: %s", email.From.Address)
	}
}

func TestParseEmail_RawHeadersKeepWireForm(t *testing.T) {
	// The header block is shown as-is in the report, so it must keep the
	// original order, casing and folding rather than being rebuilt from the
	// parsed map.
	raw := "Received: from a.example.com (a.example.com [192.0.2.1])\r\n" +
		"\tby b.example.com with ESMTP id 42\r\n" +
		"from: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"\r\n" +
		"body\r\n"

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	wantHeaders := strings.TrimSuffix(raw, "body\r\n")
	wantHeaders = strings.TrimSuffix(wantHeaders, "\r\n")
	if email.RawHeaders != wantHeaders {
		t.Errorf("RawHeaders lost the wire form:\n got: %q\nwant: %q", email.RawHeaders, wantHeaders)
	}
}

func TestParseEmail_TruncatedMultipart(t *testing.T) {
	// A message cut short by a size-capped relay never gets its closing
	// "--boundary--" delimiter. The parts that did arrive still say plenty
	// about deliverability, so they must survive rather than take the whole
	// report down with them.
	raw := `From: sender@example.com
To: recipient@example.com
Subject: Truncated
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

This part arrived in full.

--boundary123
Content-Type: text/plain; charset=utf-8

This one was cut off half`

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(email.Parts) != 2 {
		t.Fatalf("Expected the 2 parts read before the truncation, got: %d", len(email.Parts))
	}
	if !strings.Contains(email.Parts[0].Content, "arrived in full") {
		t.Errorf("First part lost its content: %q", email.Parts[0].Content)
	}
	if !strings.Contains(email.Parts[1].Content, "cut off half") {
		t.Errorf("Truncated part lost what had been read: %q", email.Parts[1].Content)
	}
	if !email.BodyIncomplete {
		t.Error("A body stopping before its closing delimiter must be reported as incomplete")
	}
}

func TestParseEmail_BoundaryNeverAppears(t *testing.T) {
	// A Content-Type announcing a boundary the body never uses yields no part at
	// all. That looks exactly like a message carrying no content, so the report
	// would silently claim there was nothing to analyse: the parser has to say
	// that the body was unreadable instead.
	raw := `From: sender@example.com
To: recipient@example.com
Subject: Boundary lost in transit
Content-Type: multipart/mixed; boundary="boundary123"

This body was never split along the boundary declared above.
`

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(email.Parts) != 0 {
		t.Fatalf("Expected no part to be read, got: %d", len(email.Parts))
	}
	if !email.BodyIncomplete {
		t.Error("A body whose declared boundary never appears must be reported as incomplete")
	}
}

func TestParseEmail_WellFormedBodyIsComplete(t *testing.T) {
	// The counterpart of the two tests above: a body closing on its delimiter,
	// nested multipart included, must never be flagged.
	raw := `From: sender@example.com
To: recipient@example.com
Subject: Well formed
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=utf-8

Plain text.
--inner
Content-Type: text/html; charset=utf-8

<p>HTML</p>
--inner--

--outer--
`

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if email.BodyIncomplete {
		t.Error("A body closing on its delimiter must not be reported as incomplete")
	}
	if len(email.Parts) != 1 || len(email.Parts[0].Parts) != 2 {
		t.Fatalf("Expected 1 part holding 2 nested ones, got: %#v", email.Parts)
	}
}

func TestParseEmail_NestedBoundaryNeverAppears(t *testing.T) {
	// The flag has to climb back out of the recursion: only the inner body is
	// broken here, and the outer one closes perfectly well.
	raw := `From: sender@example.com
To: recipient@example.com
Subject: Inner boundary lost
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

The inner boundary is nowhere to be seen.
--outer--
`

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !email.BodyIncomplete {
		t.Error("A broken nested body must be reported as incomplete too")
	}
}

func TestParseEmail_UnparsableContentTypeIsNotText(t *testing.T) {
	// An unquoted filename with a space defeats mime.ParseMediaType, which
	// then hands back the whole header value: "contexte" must not make the
	// attachment look like text/*.
	raw := `From: sender@example.com
To: recipient@example.com
Subject: Attachment
Content-Type: application/pdf; name=Rapport contexte.pdf

%PDF-1.4 binary payload
`

	email, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}
	if email.Parts[0].IsText || email.Parts[0].IsHTML {
		t.Errorf("PDF attachment reported as text=%v html=%v", email.Parts[0].IsText, email.Parts[0].IsHTML)
	}
}

func TestDKIMSignatures(t *testing.T) {
	tests := []struct {
		name       string
		signatures []string
		expected   []DKIMSignature
	}{
		{
			name:       "Empty input",
			signatures: nil,
			expected:   nil,
		},
		{
			name:       "Empty string",
			signatures: []string{""},
			expected:   nil,
		},
		{
			name: "Simple Gmail-style",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20210112; h=from:to:subject:date:message-id; bh=abcdef1234567890=; b=SIGNATURE_DATA_HERE==`,
			},
			expected: []DKIMSignature{{Domain: "gmail.com", Selector: "20210112", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Microsoft 365 style",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=contoso.com; s=selector1; h=From:Date:Subject:Message-ID; bh=UErATeHehIIPIXPeUA==; b=SIGNATURE_DATA==`,
			},
			expected: []DKIMSignature{{Domain: "contoso.com", Selector: "selector1", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Tab-folded multiline (Postfix-style)",
			signatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/simple; d=nemunai.re; s=thot;\r\n\tt=1760866834; bh=YNB7c8Qgm8YGn9X1FAXTcdpO7t4YSZFiMrmpCfD/3zw=;\r\n\th=From:To:Subject;\r\n\tb=T4TFaypMpsHGYCl3PGLwmzOYRF11rYjC7lF8V5VFU+ldvG8WBpFn==",
			},
			expected: []DKIMSignature{{Domain: "nemunai.re", Selector: "thot", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Space-folded multiline (RFC-style)",
			signatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=test; t=1528637909; h=from:to:subject;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8Gwps==",
			},
			expected: []DKIMSignature{{Domain: "football.example.com", Selector: "test", Algorithm: "rsa-sha256"}},
		},
		{
			name: "d= and s= on separate continuation lines",
			signatures: []string{
				"v=1; a=rsa-sha256;\r\n\tc=relaxed/relaxed;\r\n\td=mycompany.com;\r\n\ts=selector1;\r\n\tbh=hash=;\r\n\tb=sig==",
			},
			expected: []DKIMSignature{{Domain: "mycompany.com", Selector: "selector1", Algorithm: "rsa-sha256"}},
		},
		{
			name: "No space after semicolons",
			signatures: []string{
				`v=1;a=rsa-sha256;c=relaxed/relaxed;d=example.net;s=mail;h=from:to:subject;bh=abc=;b=xyz==`,
			},
			expected: []DKIMSignature{{Domain: "example.net", Selector: "mail", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Multiple spaces after semicolons",
			signatures: []string{
				`v=1;  a=rsa-sha256;  c=relaxed/relaxed;  d=example.com;  s=myselector;  bh=hash=;  b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "example.com", Selector: "myselector", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Ed25519 signature (RFC 8463)",
			signatures: []string{
				"v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=brisbane; t=1528637909; h=from:to:subject;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQ==",
			},
			expected: []DKIMSignature{{Domain: "football.example.com", Selector: "brisbane", Algorithm: "ed25519-sha256"}},
		},
		{
			name: "Multiple signatures (ESP double-signing)",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=mydomain.com; s=mail; h=from:to:subject; bh=hash1=; b=sig1==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendib.com; s=mail; h=from:to:subject; bh=hash1=; b=sig2==`,
			},
			expected: []DKIMSignature{
				{Domain: "mydomain.com", Selector: "mail", Algorithm: "rsa-sha256"},
				{Domain: "sendib.com", Selector: "mail", Algorithm: "rsa-sha256"},
			},
		},
		{
			name: "Dual-algorithm signing (Ed25519 + RSA, same domain, different selectors)",
			signatures: []string{
				`v=1; a=ed25519-sha256; c=relaxed/relaxed; d=football.example.com; s=brisbane; h=from:to:subject; bh=hash=; b=edSig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=football.example.com; s=test; h=from:to:subject; bh=hash=; b=rsaSig==`,
			},
			expected: []DKIMSignature{
				{Domain: "football.example.com", Selector: "brisbane", Algorithm: "ed25519-sha256"},
				{Domain: "football.example.com", Selector: "test", Algorithm: "rsa-sha256"},
			},
		},
		{
			name: "Amazon SES long selectors",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/simple; d=amazonses.com; s=224i4yxa5dv7c2xz3womw6peuabd; h=from:to:subject; bh=sesHash=; b=sesSig==`,
				`v=1; a=rsa-sha256; c=relaxed/simple; d=customerdomain.io; s=ug7nbtf4gccmlpwj322ax3p6ow6fovbt; h=from:to:subject; bh=sesHash=; b=customSig==`,
			},
			expected: []DKIMSignature{
				{Domain: "amazonses.com", Selector: "224i4yxa5dv7c2xz3womw6peuabd", Algorithm: "rsa-sha256"},
				{Domain: "customerdomain.io", Selector: "ug7nbtf4gccmlpwj322ax3p6ow6fovbt", Algorithm: "rsa-sha256"},
			},
		},
		{
			name: "Subdomain in d=",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example.co.uk; s=dkim2025; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "mail.example.co.uk", Selector: "dkim2025", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Deeply nested subdomain",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=bounce.transactional.mail.example.com; s=s2048; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "bounce.transactional.mail.example.com", Selector: "s2048", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Selector with hyphens (Microsoft 365 custom domain style)",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1-contoso-com; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "example.com", Selector: "selector1-contoso-com", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Selector with dots",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=smtp.mail; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "example.com", Selector: "smtp.mail", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Single-character selector",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=tiny.io; s=x; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{{Domain: "tiny.io", Selector: "x", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Postmark-style timestamp selector, s= before d=",
			signatures: []string{
				`v=1; a=rsa-sha1; c=relaxed/relaxed; s=20130519032151pm; d=postmarkapp.com; h=From:Date:Subject; bh=vYFvy46eesUDGJ45hyBTH30JfN4=; b=iHeFQ+7rCiSQs3DPjR2eUSZSv4i==`,
			},
			expected: []DKIMSignature{{Domain: "postmarkapp.com", Selector: "20130519032151pm", Algorithm: "rsa-sha1"}},
		},
		{
			name: "d= and s= at the very end",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:to:subject; bh=hash=; b=sig==; d=example.net; s=trailing`,
			},
			expected: []DKIMSignature{{Domain: "example.net", Selector: "trailing", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Full tag set",
			signatures: []string{
				`v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/simple; q=dns/txt; i=user@example.com; t=1255993973; x=1256598773; h=From:Sender:Reply-To:Subject:Date:Message-Id:To:Cc; bh=+7qxGePcmmrtZAIVQAtkSSGHfQ/ftNuvUTWJ3vXC9Zc=; b=dB85+qM+If1KGQmqMLNpqLgNtUaG5dhGjYjQD6/QXtXmViJx8tf9gLEjcHr+musLCAvr0Fsn1DA3ZLLlUxpf4AR==`,
			},
			expected: []DKIMSignature{{Domain: "example.com", Selector: "selector1", Algorithm: "rsa-sha256"}},
		},
		{
			name: "Missing d= tag",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; s=selector1; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Missing s= tag",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Missing both d= and s= tags",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Mix of valid and invalid signatures",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=good.com; s=sel1; h=from:to; bh=hash=; b=sig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; s=orphan; h=from:to; bh=hash=; b=sig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=also-good.com; s=sel2; h=from:to; bh=hash=; b=sig==`,
			},
			expected: []DKIMSignature{
				{Domain: "good.com", Selector: "sel1", Algorithm: "rsa-sha256"},
				{Domain: "also-good.com", Selector: "sel2", Algorithm: "rsa-sha256"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := &Message{Header: mail.Header{"Dkim-Signature": tt.signatures}}
			result := message.DKIMSignatures()
			if len(result) != len(tt.expected) {
				t.Fatalf(" returned %d results, want %d\n  got:  %+v\n  want: %+v", len(result), len(tt.expected), result, tt.expected)
			}
			for i := range tt.expected {
				if result[i].Domain != tt.expected[i].Domain {
					t.Errorf("result[%d].Domain = %q, want %q", i, result[i].Domain, tt.expected[i].Domain)
				}
				if result[i].Selector != tt.expected[i].Selector {
					t.Errorf("result[%d].Selector = %q, want %q", i, result[i].Selector, tt.expected[i].Selector)
				}
				if result[i].Algorithm != tt.expected[i].Algorithm {
					t.Errorf("result[%d].Algorithm = %q, want %q", i, result[i].Algorithm, tt.expected[i].Algorithm)
				}
			}
		})
	}
}

func TestGetAttachments_Base64Attachment(t *testing.T) {
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

	email, err := Parse([]byte(rawEmail))
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
	if decoded := string(att.DecodedBytes()); !strings.HasPrefix(decoded, "%PDF-1.4") {
		t.Errorf("Decoded content should start with %%PDF-1.4, got %q", decoded)
	}
}

func TestGetAttachments_QuotedPrintableAttachment(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: QP test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n" +
		"\r\n" +
		"--BOUNDARY\r\n" +
		"Content-Type: text/csv; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Content-Disposition: attachment; filename=\"data.csv\"\r\n" +
		"\r\n" +
		"col1;col2\r\n" +
		"caf=C3=A9;42\r\n" +
		"--BOUNDARY--\r\n"

	email, err := Parse([]byte(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	attachments := email.GetAttachments()
	if len(attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(attachments))
	}

	if decoded := string(attachments[0].DecodedBytes()); !strings.Contains(decoded, "café;42") {
		t.Errorf("Decoded content should contain café;42, got %q", decoded)
	}
}

func TestGetAttachments_FilenameFromContentTypeName(t *testing.T) {
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

	email, err := Parse([]byte(rawEmail))
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

func TestGetAttachments_InlineImageWithContentID(t *testing.T) {
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

	email, err := Parse([]byte(rawEmail))
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

func TestGetAttachments_SinglePartPDF(t *testing.T) {
	rawEmail := "From: sender@example.com\r\n" +
		"Subject: bare pdf\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: application/pdf; name=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
		"\r\n" +
		"JVBERi0xLjQK\r\n"

	email, err := Parse([]byte(rawEmail))
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
	if decoded := string(att.DecodedBytes()); !strings.HasPrefix(decoded, "%PDF") {
		t.Errorf("Expected decoded PDF magic, got %q", decoded)
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

	email, err := Parse([]byte(rawEmail))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	if attachments := email.GetAttachments(); len(attachments) != 0 {
		t.Errorf("Expected no attachments, got %d", len(attachments))
	}
}
