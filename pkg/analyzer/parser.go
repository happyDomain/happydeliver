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
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/emersion/go-message"
	// Importing the charset package registers a decoder covering the IANA
	// charset registry, so a part announcing e.g. ISO-8859-15 or Shift_JIS is
	// converted to UTF-8 rather than read as if it were ASCII.
	_ "github.com/emersion/go-message/charset"
	gomail "github.com/emersion/go-message/mail"
)

// EmailMessage represents a parsed email message
type EmailMessage struct {
	Header     mail.Header
	From       *mail.Address
	To         []*mail.Address
	Subject    string
	MessageID  string
	Date       string
	ReturnPath string
	Parts      []MessagePart

	// BodyIncomplete reports that the MIME body could not be read through to its
	// end: a multipart body cut short before its closing delimiter, or one whose
	// declared boundary never appears at all. Parts still holds everything that
	// did arrive, but it is not the whole message, so the absence of something
	// there says nothing about the message that was sent.
	BodyIncomplete bool

	// RawHeaders is the message's header block as it appeared on the wire,
	// unparsed: the original order, folding, casing and line endings are all
	// preserved, because it is shown as-is in the report.
	RawHeaders string
	RawBody    string

	// Raw is the message exactly as it was received, octet for octet. DKIM and
	// ARC sign those octets, so signature verification can only ever work from
	// this field.
	Raw []byte
}

// MessagePart represents a MIME part of an email
type MessagePart struct {
	ContentType string
	Encoding    string
	Content     string
	IsHTML      bool
	IsText      bool
	Boundary    string
	Parts       []MessagePart // For nested multipart messages
}

// ParseEmail parses an email message from a reader.
//
// Transfer encodings and charsets are decoded by go-message, so every text part
// comes out as UTF-8 whatever the wire format was. A part announcing an encoding
// or a charset the library does not know is not an error: its payload is left
// untouched and the rest of the message is still analysed.
func ParseEmail(r io.Reader) (*EmailMessage, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read email message: %w", err)
	}

	return ParseEmailBytes(raw)
}

// ParseEmailBytes parses an email message already held in memory, which is how
// every caller but a test has it: reading it back out of a reader would leave
// two copies of the whole message in memory for as long as the analysis runs.
//
// The slice becomes the message's Raw field rather than being copied, so callers
// must not modify it afterwards.
func ParseEmailBytes(raw []byte) (*EmailMessage, error) {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && !isDecodeError(err) {
		return nil, fmt.Errorf("failed to parse email message: %w", err)
	}

	email := &EmailMessage{
		Raw:        raw,
		Header:     mail.Header(entity.Header.Map()),
		MessageID:  entity.Header.Get("Message-ID"),
		Date:       entity.Header.Get("Date"),
		ReturnPath: entity.Header.Get("Return-Path"),
		RawHeaders: rawHeaderBlock(raw),
	}

	// Subject and the display names of From/To may be RFC 2047 encoded words:
	// go-message decodes them, so what lands in the report is the text a human
	// would see in their client rather than "=?UTF-8?B?...?=".
	//
	// A malformed value comes back unchanged alongside an error, which is
	// exactly the degradation wanted here, so the errors are deliberately not
	// propagated.
	mailHeader := gomail.Header{Header: entity.Header}
	email.Subject, _ = mailHeader.Subject()
	if from, err := mailHeader.AddressList("From"); err == nil && len(from) > 0 {
		email.From = from[0]
	}
	if to, err := mailHeader.AddressList("To"); err == nil {
		email.To = to
	}

	email.Parts, email.BodyIncomplete = messageParts(entity)

	return email, nil
}

// isDecodeError reports whether err merely says that a transfer encoding or a
// charset is unknown. go-message returns those alongside a perfectly usable
// entity whose payload is left in its original form, so they must not abort the
// analysis of the rest of the message.
func isDecodeError(err error) bool {
	return message.IsUnknownEncoding(err) || message.IsUnknownCharset(err)
}

// messageParts returns the parts of a whole message: the children of the root
// entity when it is multipart, or the message itself as a single part. The
// second result is EmailMessage.BodyIncomplete.
func messageParts(e *message.Entity) ([]MessagePart, bool) {
	// MultipartReader consumes the body, so it must be called exactly once per
	// entity: the value is threaded through rather than asked for twice.
	if mr := e.MultipartReader(); mr != nil {
		return readMultipart(mr)
	}

	part := describePart(e)
	readContent(e, &part)

	return []MessagePart{part}, false
}

// readMultipart turns every part of a multipart body into a MessagePart,
// recursing into the ones that are themselves multipart. A malformed body is
// reported as far as it could be read: a message truncated before its closing
// delimiter, as a size-capped relay leaves it, still says plenty about
// deliverability through the parts that did arrive.
//
// It also says whether the body ended where it should have, because "no parts
// were found" and "the body was unreadable" must not look alike to the report:
// a message announcing a boundary that never appears in its body yields no part
// at all, and would otherwise be indistinguishable from one that genuinely
// carries no content.
func readMultipart(mr message.MultipartReader) (parts []MessagePart, incomplete bool) {
	for {
		child, err := mr.NextPart()
		if err != nil && !isDecodeError(err) {
			// mime/multipart returns io.EOF itself, unwrapped, only once it has
			// read a well-formed closing delimiter; every other failure — a body
			// cut short, a boundary that never shows up — comes back inside a
			// "multipart: NextPart" error. Hence the identity comparison rather
			// than errors.Is: only the bare value means the body really ended.
			// NextPart hands back no entity in either case, so what was read so
			// far is all there is.
			return parts, incomplete || err != io.EOF
		}

		part := describePart(child)
		if nestedReader := child.MultipartReader(); nestedReader != nil {
			var nestedIncomplete bool
			part.Parts, nestedIncomplete = readMultipart(nestedReader)
			incomplete = incomplete || nestedIncomplete
		} else {
			readContent(child, &part)
		}

		parts = append(parts, part)
	}
}

// describePart fills in everything about a part that can be told from its
// header alone.
func describePart(e *message.Entity) MessagePart {
	contentType := e.Header.Get("Content-Type")
	if contentType == "" {
		// A part without a Content-Type is text/plain per RFC 2045 section 5.2.
		contentType = "text/plain"
	}

	// ContentType reports the media type alone and falls back to text/plain
	// when the header is absent. A header it cannot parse comes back verbatim,
	// parameters included, so keep only what precedes the first parameter:
	// otherwise an unquoted filename such as "Rapport contexte.pdf" would make
	// the attachment look like text. Casing is not normalised either, hence the
	// fold.
	mediaType, _, err := e.Header.ContentType()
	if err != nil {
		mediaType, _, _ = strings.Cut(mediaType, ";")
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	return MessagePart{
		ContentType: contentType,
		Encoding:    e.Header.Get("Content-Transfer-Encoding"),
		IsHTML:      strings.Contains(mediaType, "html"),
		IsText:      strings.Contains(mediaType, "text"),
	}
}

// readContent decodes a leaf part's body into part.Content.
//
// Only text parts are ever read back, by GetTextParts and GetHTMLParts:
// decoding an attachment would allocate and then throw away its whole payload.
// NextPart() skips over whatever is left unconsumed.
//
// Reading is best-effort: ReadAll returns the bytes decoded so far alongside any
// error, so a part that is malformed partway through still contributes the
// prefix that decoded fine instead of breaking the whole report.
func readContent(e *message.Entity, part *MessagePart) {
	if !part.IsText && !part.IsHTML {
		return
	}

	content, _ := io.ReadAll(e.Body)
	part.Content = string(content)
}

// rawHeaderBlock returns the header block of a raw message, stopping before the
// empty line that separates it from the body. Both line ending conventions are
// accepted, and whichever separator appears first wins: a message using bare LF
// must not be cut at the first CRLF pair that happens to occur in its body.
func rawHeaderBlock(raw []byte) string {
	end := len(raw)

	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		end = i + len("\r\n")
	}
	// Only what precedes the CRLF separator can still hold an earlier LF one, so
	// the second scan stops there rather than running over the whole body.
	if i := bytes.Index(raw[:end], []byte("\n\n")); i >= 0 {
		end = i + len("\n")
	}

	return string(raw[:end])
}

// parseAuthservID extracts the authserv-id from an Authentication-Results header value.
//
// Per RFC 8601 section 2.2 the value opens with the authserv-id, optionally followed by a
// version number, then the results separated by semicolons. CFWS comments may appear
// anywhere, so they are stripped before the identifier is isolated.
func parseAuthservID(value string) string {
	var head strings.Builder
	depth := 0
	inQuotes := false

scan:
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case inQuotes:
			if c == '\\' && i+1 < len(value) {
				i++
				head.WriteByte(value[i])
			} else if c == '"' {
				inQuotes = false
			} else {
				head.WriteByte(c)
			}
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case depth > 0:
			// Inside a comment: ignored.
		case c == '"':
			inQuotes = true
		case c == ';':
			break scan
		default:
			head.WriteByte(c)
		}
	}

	// What remains is "authserv-id [version]": keep the first token.
	fields := strings.Fields(head.String())
	if len(fields) == 0 {
		return ""
	}

	return fields[0]
}

// GetAuthenticationResults extracts Authentication-Results headers
// If receiverHostname is provided, only returns headers whose authserv-id is that hostname
func (e *EmailMessage) GetAuthenticationResults(receiverHostname string) []string {
	allResults := e.Header[textproto.CanonicalMIMEHeaderKey("Authentication-Results")]

	// If no hostname specified, return all results
	if receiverHostname == "" {
		return allResults
	}

	// Filter results whose authserv-id matches the specified hostname
	var filtered []string
	for _, result := range allResults {
		if strings.EqualFold(parseAuthservID(result), receiverHostname) {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// AuthservIDs lists the authserv-id of every Authentication-Results header found in the
// message, most recent (topmost) first and without duplicates.
//
// This is how the authority to trust is picked for messages this instance did not receive
// itself, such as an uploaded EML file: the topmost header was written by the last server
// that handled the message, usually the recipient's own MTA.
func (e *EmailMessage) AuthservIDs() []string {
	allResults := e.Header[textproto.CanonicalMIMEHeaderKey("Authentication-Results")]

	var ids []string
	seen := make(map[string]bool, len(allResults))
	for _, result := range allResults {
		id := parseAuthservID(result)
		if id == "" {
			continue
		}

		key := strings.ToLower(id)
		if seen[key] {
			continue
		}
		seen[key] = true

		ids = append(ids, id)
	}

	return ids
}

// GetSpamAssassinHeaders extracts SpamAssassin-related headers
func (e *EmailMessage) GetSpamAssassinHeaders() map[string]string {
	headers := make(map[string]string)

	// Common SpamAssassin headers
	saHeaders := []string{
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Flag",
		"X-Spam-Level",
		"X-Spam-Report",
		"X-Spam-Checker-Version",
	}

	for _, headerName := range saHeaders {
		values := e.Header[headerName]
		if len(values) == 0 {
			if value := e.Header.Get(headerName); value != "" {
				values = []string{value}
			}
		}

		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			// Leave rspamd's own X-Spam-Status to GetRspamdHeaders: reading it here
			// would report rspamd's verdict as a SpamAssassin one.
			if headerName == "X-Spam-Status" && spamStatusIsRspamd(value) {
				continue
			}
			headers[headerName] = value
			break
		}
	}

	return headers
}

// spamStatusIsRspamd reports whether an X-Spam-Status value was written by rspamd
// rather than by SpamAssassin. Hosts running both milters emit one X-Spam-Status
// header each; rspamd's variant carries its score as "rspamdscore=".
func spamStatusIsRspamd(value string) bool {
	return strings.Contains(strings.ToLower(value), "rspamdscore=")
}

// GetRspamdHeaders extracts rspamd-related headers
func (e *EmailMessage) GetRspamdHeaders() map[string]string {
	headers := make(map[string]string)

	rspamdHeaders := []string{
		"X-Spamd-Result",
		"X-Rspamd-Score",
		"X-Rspamd-Action",
		"X-Rspamd-Server",
	}

	for _, headerName := range rspamdHeaders {
		if value := e.Header.Get(headerName); value != "" {
			headers[headerName] = value
		}
	}

	// rspamd also emits a SpamAssassin-shaped status header when it runs alongside
	// one, e.g. "No, rspamdscore=-4.78, required=10.00".
	for _, value := range e.Header["X-Spam-Status"] {
		if spamStatusIsRspamd(value) {
			headers["X-Spam-Status"] = value
			break
		}
	}

	return headers
}

// GetTextParts returns all text/plain parts
func (e *EmailMessage) GetTextParts() []MessagePart {
	return filterParts(e.Parts, func(p MessagePart) bool {
		return p.IsText && !p.IsHTML
	})
}

// GetHTMLParts returns all text/html parts
func (e *EmailMessage) GetHTMLParts() []MessagePart {
	return filterParts(e.Parts, func(p MessagePart) bool {
		return p.IsHTML
	})
}

// filterParts recursively filters message parts
func filterParts(parts []MessagePart, predicate func(MessagePart) bool) []MessagePart {
	var result []MessagePart
	for _, part := range parts {
		if len(part.Parts) > 0 {
			// Recursively filter nested parts
			result = append(result, filterParts(part.Parts, predicate)...)
		} else if predicate(part) {
			result = append(result, part)
		}
	}
	return result
}

// GetHeaderValue safely gets a header value
func (e *EmailMessage) GetHeaderValue(key string) string {
	return e.Header.Get(key)
}

// HasHeader checks if a header exists
func (e *EmailMessage) HasHeader(key string) bool {
	return e.Header.Get(key) != ""
}

// GetListUnsubscribeURLs parses the List-Unsubscribe header and returns all URLs.
// The header format is: <url1>, <url2>, ...
func (e *EmailMessage) GetListUnsubscribeURLs() []string {
	value := e.Header.Get("List-Unsubscribe")
	if value == "" {
		return nil
	}
	var urls []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">") {
			urls = append(urls, part[1:len(part)-1])
		}
	}
	return urls
}
