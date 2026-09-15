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

// Package mailmsg reads a raw message into the shape everything else looks at:
// its headers, the addresses they name, and the parts its body is made of.
//
// It parses and it reports what it parsed; it judges nothing. What a header
// means, whether a part is what it claims to be, which of them a reader will
// ever see: those are readings, and they belong to whoever makes them.
package mailmsg

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	gomail "github.com/emersion/go-message/mail"

	"git.happydns.org/happyDeliver/pkg/authresults"
)

// Message is a message as it was received, parsed.
type Message struct {
	Header     mail.Header
	From       *mail.Address
	To         []*mail.Address
	Subject    string
	MessageID  string
	Date       string
	ReturnPath string
	Parts      []Part

	// BodyIncomplete reports that the MIME body could not be read through to its
	// end: cut short before its closing delimiter, or a declared boundary that
	// never appears. Parts holds everything that did arrive, so the absence of
	// something there says nothing about the message that was sent.
	BodyIncomplete bool

	// RawHeaders is the header block as it appeared on the wire: order, folding,
	// casing and line endings preserved, because it is shown as-is in the report.
	RawHeaders string

	// Raw is the whole message as it was handed to mailmsg.Parse. It aliases the
	// caller's slice rather than copying it, so nothing here may write to it.
	//
	// It is kept because some analyses need the message and not its parsed
	// form: re-serialising Parts would change the transfer encodings and the
	// MIME boundaries, and those are themselves what a filter reads when it
	// raises MIME_BASE64_TEXT or SUSPICIOUS_BOUNDARY.
	Raw []byte
}

// Part represents a MIME part of an email
type Part struct {
	ContentType string
	Content     string

	// MediaType is the type the Content-Type header names, without its
	// parameters and lowercased: "application/pdf", "multipart/mixed".
	MediaType string

	// Filename is what the part calls itself: the Content-Disposition
	// filename= parameter, falling back to the deprecated Content-Type name=.
	// RFC 2047 encoded words and RFC 2231 continuations are already decoded.
	Filename string

	// Disposition is the Content-Disposition type, lowercased: "attachment",
	// "inline", or empty when the part carries no such header.
	Disposition string

	// ContentID is the Content-ID header with its angle brackets stripped, the
	// name an HTML body refers to an embedded resource by (cid:...).
	ContentID string

	// Body is the payload of a leaf part with its transfer encoding undone
	// and nothing else: the bytes of the file as the sender attached it. A
	// text part also has Content, the same payload converted to UTF-8.
	Body []byte

	IsHTML bool
	IsText bool
	Parts  []Part // For nested multipart messages
}

// DecodedBytes returns the payload of the part as the sender attached it,
// transfer encoding undone but charset untouched: a text file declared in
// windows-1252 comes back in windows-1252, so that its hash and size are the
// file's own.
func (p *Part) DecodedBytes() []byte {
	if p.Body != nil {
		return p.Body
	}

	return []byte(p.Content)
}

// go-message converts the body of every text part to UTF-8 through this
// package-level hook, before the part is handed out. The conversion is wanted
// for reading the body; it is not for hashing an attached text file or
// handing it to a scanner, which need the bytes that were actually sent. The
// hook is thus wrapped so that the input it consumes is kept alongside the
// conversion, for messageParts to pick up once the part has been read.
func init() {
	message.CharsetReader = func(name string, input io.Reader) (io.Reader, error) {
		kept := &keptInput{}
		converted, err := charset.Reader(name, io.TeeReader(input, &kept.raw))
		if err != nil {
			return nil, err
		}
		kept.Reader = converted

		return kept, nil
	}
}

// keptInput is a charset-converting reader that remembers what it read from
// its input.
type keptInput struct {
	io.Reader
	raw bytes.Buffer
}

// IsInline reports whether the part is an inline resource (e.g. an image
// embedded in the HTML body) rather than a regular attachment.
func (p *Part) IsInline() bool {
	return p.Disposition == "inline" || (p.Disposition == "" && p.ContentID != "")
}

// Parse parses a raw email message.
//
// go-message decodes transfer encodings and charsets, so every text part comes
// out as UTF-8. An unknown encoding or charset is not an error: the payload is
// left untouched and the rest of the message is analysed.
func Parse(raw []byte) (*Message, error) {
	return parse(raw, 0)
}

// maxEmbeddedDepth bounds how deep embedded messages are parsed: each level
// reads and keeps its whole payload again, so a message made of nested
// message/rfc822 headers would otherwise cost quadratic time and memory.
// Forwards and bounces rarely nest more than twice.
const maxEmbeddedDepth = 5

// parse is Parse at a given embedded-message depth.
func parse(raw []byte, depth int) (*Message, error) {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && !isDecodeError(err) {
		return nil, fmt.Errorf("failed to parse email message: %w", err)
	}

	email := &Message{
		Header:     mail.Header(entity.Header.Map()),
		MessageID:  entity.Header.Get("Message-ID"),
		Date:       entity.Header.Get("Date"),
		ReturnPath: entity.Header.Get("Return-Path"),
		RawHeaders: rawHeaderBlock(raw),
		Raw:        raw,
	}

	// Subject and the display names of From/To may be RFC 2047 encoded words:
	// go-message decodes them, so the report shows the text a human would see
	// rather than "=?UTF-8?B?...?=". A malformed value comes back unchanged
	// alongside an error, the degradation wanted here, hence the ignored errors.
	mailHeader := gomail.Header{Header: entity.Header}
	email.Subject, _ = mailHeader.Subject()
	if from, err := mailHeader.AddressList("From"); err == nil && len(from) > 0 {
		email.From = from[0]
	}
	if to, err := mailHeader.AddressList("To"); err == nil {
		email.To = to
	}

	email.Parts, email.BodyIncomplete = messageParts(entity, depth)

	return email, nil
}

// isDecodeError reports whether err merely says a transfer encoding or charset
// is unknown. go-message returns those alongside a usable entity whose payload
// is left as-is, so they must not abort the analysis.
func isDecodeError(err error) bool {
	return message.IsUnknownEncoding(err) || message.IsUnknownCharset(err)
}

// messageParts returns the parts of a whole message: the children of the root
// entity when it is multipart, or the message itself as a single part. The
// second result is Message.BodyIncomplete.
//
// The root is unwrapped rather than reported as a part of its own, so that a
// message declaring a boundary never found in its body comes out with no part
// at all rather than with an empty root.
func messageParts(e *message.Entity, depth int) ([]Part, bool) {
	if mr := e.MultipartReader(); mr != nil {
		return readMultipart(mr, depth)
	}

	part, _ := entityPart(e, depth)

	return []Part{part}, false
}

// entityPart turns one entity into a Part, recursing into it when it is
// itself multipart. The second result is whether a nested body was truncated.
func entityPart(e *message.Entity, depth int) (Part, bool) {
	part := describePart(e)

	if mr := e.MultipartReader(); mr != nil {
		var incomplete bool
		part.Parts, incomplete = readMultipart(mr, depth)
		return part, incomplete
	}

	// Every leaf part is read back: the text ones by GetTextParts and
	// GetHTMLParts, the others by whoever analyses the attachments. A part is
	// read once, here, because e.Body is a stream NextPart() would otherwise
	// skip past.
	//
	// Best-effort: ReadAll returns the bytes decoded so far alongside any error,
	// so a part malformed partway through still contributes its valid prefix.
	content, _ := io.ReadAll(e.Body)
	part.Body = content
	if part.IsText || part.IsHTML {
		part.Content = string(content)
		// A body that went through a charset conversion had its original
		// bytes kept along the way; one that did not (no charset, UTF-8 or
		// US-ASCII, or a charset nobody knows) was read as sent already.
		if kept, ok := e.Body.(*keptInput); ok {
			part.Body = kept.raw.Bytes()
		}
	}

	// A forwarded or bounced message carries its own parts, and whatever it
	// attaches must stay reachable rather than sit behind an opaque leaf. Its
	// payload is a whole message, so it is parsed as one; a body too malformed
	// to parse leaves the part as the leaf it already is, and so does one
	// nested deeper than maxEmbeddedDepth.
	if isEmbeddedMessage(part.MediaType) && depth < maxEmbeddedDepth {
		if nested, err := parse(content, depth+1); err == nil {
			part.Parts = nested.Parts
		}
	}

	return part, false
}

// isEmbeddedMessage reports whether a part's media type says its payload is
// itself a message: RFC 2046 message/rfc822, its RFC 6532 internationalised
// counterpart message/global, and message/news.
func isEmbeddedMessage(mediaType string) bool {
	switch mediaType {
	case "message/rfc822", "message/global", "message/news":
		return true
	}

	return false
}

// readMultipart turns every part of a multipart body into a Part,
// recursing into the ones that are themselves multipart. A malformed body is
// reported as far as it could be read: a message truncated before its closing
// delimiter still says plenty about deliverability through the parts that did
// arrive. The second result keeps "no parts found" distinguishable from "body
// unreadable", which would otherwise look alike to the report.
func readMultipart(mr message.MultipartReader, depth int) (parts []Part, incomplete bool) {
	for {
		child, err := mr.NextPart()
		if err != nil && !isDecodeError(err) {
			// mime/multipart returns io.EOF unwrapped only once it has read a
			// well-formed closing delimiter; every other failure comes back
			// wrapped in a "multipart: NextPart" error. Hence the identity
			// comparison rather than errors.Is.
			return parts, incomplete || err != io.EOF
		}

		part, nestedIncomplete := entityPart(child, depth)
		incomplete = incomplete || nestedIncomplete

		parts = append(parts, part)
	}
}

// MediaType is the type a Content-Type value names, without its parameters
// and lowercased.
//
// A header too malformed to parse still names its type in the token before the
// first parameter, and that token is kept: an unquoted filename such as
// "Rapport contexte.pdf" must not be allowed to turn an attachment into
// something else.
func MediaType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType, _, _ = strings.Cut(contentType, ";")
	}

	return strings.ToLower(strings.TrimSpace(mediaType))
}

// describePart fills in everything about a part that can be told from its
// header alone.
func describePart(e *message.Entity) Part {
	contentType := e.Header.Get("Content-Type")
	if contentType == "" {
		// A part without a Content-Type is text/plain per RFC 2045 section 5.2.
		contentType = "text/plain"
	}

	// A header ContentType cannot parse comes back verbatim, parameters
	// included, and MediaType keeps only what precedes the first one. The
	// header is parsed here rather than from contentType above, because its
	// parameters are wanted alongside the type.
	mediaType, ctParams, err := e.Header.ContentType()
	if err != nil {
		mediaType = MediaType(mediaType)
	}

	// go-message only applies charset decoding to a strict "text/" media type
	// (see its entity.go), so a type such as application/xhtml+xml must not be
	// read back as text here: its body would come through undecoded.
	isText := strings.HasPrefix(mediaType, "text/")

	disposition, dispParams, err := e.Header.ContentDisposition()
	if err != nil {
		// A header too malformed to parse still names its type in the token
		// before the first parameter.
		disposition, _, _ = strings.Cut(e.Header.Get("Content-Disposition"), ";")
	}
	disposition = strings.ToLower(strings.TrimSpace(disposition))

	return Part{
		ContentType: contentType,
		MediaType:   mediaType,
		Filename:    partFilename(dispParams, ctParams),
		Disposition: disposition,
		ContentID:   strings.Trim(e.Header.Get("Content-Id"), "<>"),
		IsHTML:      mediaType == "text/html",
		IsText:      isText,
	}
}

// partFilename returns the name a part gives itself: the Content-Disposition
// filename= parameter, or the Content-Type name= one deprecated by RFC 2183
// but still emitted by older senders.
func partFilename(dispParams, ctParams map[string]string) string {
	if filename := dispParams["filename"]; filename != "" {
		return filename
	}

	return ctParams["name"]
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
	// Only what precedes the CRLF separator can hold an earlier LF one.
	if i := bytes.Index(raw[:end], []byte("\n\n")); i >= 0 {
		end = i + len("\n")
	}

	return string(raw[:end])
}

// parseAuthservID extracts the authserv-id from an Authentication-Results header value.
//
// Per RFC 8601 section 2.2 the value opens with the authserv-id, optionally followed by a
// version number, then the results separated by semicolons. CFWS comments may appear
// anywhere, which is one of the reasons the field is read by a package of its own.
func parseAuthservID(value string) string {
	header, read := authresults.Parse(value)
	if !read {
		return ""
	}

	return header.AuthservID
}

// GetAuthenticationResults extracts Authentication-Results headers
// If receiverHostname is provided, only returns headers whose authserv-id is that hostname
func (e *Message) GetAuthenticationResults(receiverHostname string) []string {
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
func (e *Message) AuthservIDs() []string {
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

// GetTextParts returns all text/plain parts
func (e *Message) GetTextParts() []Part {
	return filterParts(e.Parts, false, func(p Part) bool {
		return p.IsText && !p.IsHTML
	})
}

// GetHTMLParts returns all text/html parts
func (e *Message) GetHTMLParts() []Part {
	return filterParts(e.Parts, false, func(p Part) bool {
		return p.IsHTML
	})
}

// GetAttachments returns every part carrying a payload to analyze: explicit
// attachments, parts naming a file, inline resources such as embedded images,
// and any leaf part that is not a text body. A text part is a body unless it
// is declared an attachment or named: a Content-ID alone does not make it
// one, since multipart/related designates its root body that way (start=).
func (e *Message) GetAttachments() []Part {
	return filterParts(e.Parts, true, func(p Part) bool {
		if p.Disposition == "attachment" || p.Filename != "" {
			return true
		}
		if p.ContentID != "" && !p.IsText && !p.IsHTML {
			return true
		}

		return p.MediaType != "" &&
			!strings.HasPrefix(p.MediaType, "text/") &&
			!strings.HasPrefix(p.MediaType, "multipart/") &&
			!strings.HasPrefix(p.MediaType, "message/")
	})
}

// filterParts walks the MIME tree and returns the parts matching predicate.
// multipart/* nodes are structure only and never match themselves. An
// embedded message is both a part of the outer message and a message of its
// own: it is tested like any other part, and its own parts are walked only
// when crossMessages is set, since a forwarded body is not the body of the
// message that forwards it.
func filterParts(parts []Part, crossMessages bool, predicate func(Part) bool) []Part {
	var result []Part
	for _, part := range parts {
		embedded := isEmbeddedMessage(part.MediaType)
		if len(part.Parts) == 0 || embedded {
			if predicate(part) {
				result = append(result, part)
			}
		}
		if len(part.Parts) > 0 && (!embedded || crossMessages) {
			result = append(result, filterParts(part.Parts, crossMessages, predicate)...)
		}
	}
	return result
}

// GetHeaderValue safely gets a header value
func (e *Message) GetHeaderValue(key string) string {
	return e.Header.Get(key)
}

// HasHeader checks if a header exists
func (e *Message) HasHeader(key string) bool {
	return e.Header.Get(key) != ""
}

// GetListUnsubscribeURLs parses the List-Unsubscribe header and returns all URLs.
// The header format is: <url1>, <url2>, ...
func (e *Message) GetListUnsubscribeURLs() []string {
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

// LocalPart extracts the local-part of an address header, the part before
// the '@'. It parses the header properly first, so that a display name and a
// quoted local-part are handled, and falls back to cutting at the last '@' the
// way the domain is extracted, so that an address a strict parser rejects
// still yields what it plainly holds. It returns an empty string when there is
// no address to read.
func LocalPart(address string) string {
	if addr, err := mail.ParseAddress(address); err == nil {
		address = addr.Address
	} else {
		address = strings.Trim(address, "<> ")
	}

	at := strings.LastIndex(address, "@")
	if at <= 0 {
		return ""
	}
	return address[:at]
}

// AddressDomain extracts the domain of an address header, the part after the
// '@'. It is the symmetric of LocalPart, and as forgiving: an address a strict
// parser rejects still yields what it plainly holds. It returns an empty string
// when there is no domain to read.
func AddressDomain(address string) string {
	if addr, err := mail.ParseAddress(address); err == nil {
		address = addr.Address
	} else {
		address = strings.Trim(address, "<> ")
	}

	at := strings.LastIndex(address, "@")
	if at == -1 {
		return ""
	}

	return strings.TrimRight(address[at+1:], ">")
}

// DKIMSignature holds the domain, selector and signing algorithm from a DKIM-Signature header.
type DKIMSignature struct {
	Domain    string
	Selector  string
	Algorithm string // from a= tag (e.g. rsa-sha256, ed25519-sha256)
}

// DKIMSignatures reads what each DKIM-Signature header of the message claims:
// the domain it signs for, the selector naming the key, and the algorithm. It
// reports what is written, and says nothing about whether any of it verifies.
func (e *Message) DKIMSignatures() []DKIMSignature {
	signatures := e.Header["Dkim-Signature"]

	var results []DKIMSignature
	for _, sig := range signatures {
		var domain, selector, algorithm string
		for _, part := range strings.Split(sig, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch key {
			case "d":
				domain = val
			case "s":
				selector = val
			case "a":
				algorithm = val
			}
		}
		if domain != "" && selector != "" {
			results = append(results, DKIMSignature{Domain: domain, Selector: selector, Algorithm: algorithm})
		}
	}
	return results
}
