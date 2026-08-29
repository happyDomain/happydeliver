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

// singlePartEmail builds a one-part message with the given encoding, charset
// and body, so a decoding behaviour can be asserted through ParseEmail rather
// than against an internal helper.
func singlePartEmail(t *testing.T, encoding, charset, body string) MessagePart {
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
	}

	wantHeaders := strings.TrimSuffix(raw, "body\r\n")
	wantHeaders = strings.TrimSuffix(wantHeaders, "\r\n")
	if email.RawHeaders != wantHeaders {
		t.Errorf("RawHeaders lost the wire form:\n got: %q\nwant: %q", email.RawHeaders, wantHeaders)
	}
	if string(email.Raw) != raw {
		t.Errorf("Raw is not the received octets: %q", email.Raw)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
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

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail returned error: %v", err)
	}

	if len(email.Parts) != 1 {
		t.Fatalf("Expected 1 part, got: %d", len(email.Parts))
	}
	if email.Parts[0].IsText || email.Parts[0].IsHTML {
		t.Errorf("PDF attachment reported as text=%v html=%v", email.Parts[0].IsText, email.Parts[0].IsHTML)
	}
}
