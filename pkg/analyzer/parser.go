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
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
)

var hostname = ""

func init() {
	hostname, _ = os.Hostname()
}

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
	RawHeaders string
	RawBody    string
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

// ParseEmail parses an email message from a reader
func ParseEmail(r io.Reader) (*EmailMessage, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read email message: %w", err)
	}

	email := &EmailMessage{
		Header:     msg.Header,
		Subject:    msg.Header.Get("Subject"),
		MessageID:  msg.Header.Get("Message-ID"),
		Date:       msg.Header.Get("Date"),
		ReturnPath: msg.Header.Get("Return-Path"),
	}

	// Parse From address
	if fromStr := msg.Header.Get("From"); fromStr != "" {
		from, err := mail.ParseAddress(fromStr)
		if err == nil {
			email.From = from
		}
	}

	// Parse To addresses
	if toStr := msg.Header.Get("To"); toStr != "" {
		toAddrs, err := mail.ParseAddressList(toStr)
		if err == nil {
			email.To = toAddrs
		}
	}

	// Build raw headers string
	email.RawHeaders = buildRawHeaders(msg.Header)

	// Parse MIME parts
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// Plain text email without MIME
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read email body: %w", err)
		}
		email.RawBody = string(body)
		email.Parts = []MessagePart{
			{
				ContentType: "text/plain",
				Content:     string(body),
				IsText:      true,
			},
		}
	} else {
		// Parse MIME message
		parts, err := parseMIMEParts(msg.Body, contentType)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MIME parts: %w", err)
		}
		email.Parts = parts
	}

	return email, nil
}

// parseMIMEParts recursively parses MIME parts
func parseMIMEParts(body io.Reader, contentType string) ([]MessagePart, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse media type: %w", err)
	}

	var parts []MessagePart

	if strings.HasPrefix(mediaType, "multipart/") {
		// Handle multipart messages
		boundary := params["boundary"]
		if boundary == "" {
			return nil, fmt.Errorf("multipart message missing boundary")
		}

		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read multipart part: %w", err)
			}

			partContentType := part.Header.Get("Content-Type")
			if partContentType == "" {
				partContentType = "text/plain"
			}

			// Check if this part is also multipart
			partMediaType, _, _ := mime.ParseMediaType(partContentType)
			if strings.HasPrefix(partMediaType, "multipart/") {
				// Recursively parse nested multipart
				nestedParts, err := parseMIMEParts(part, partContentType)
				if err != nil {
					return nil, err
				}
				parts = append(parts, MessagePart{
					ContentType: partContentType,
					Encoding:    part.Header.Get("Content-Transfer-Encoding"),
					Parts:       nestedParts,
				})
			} else {
				// Read the part content
				content, err := io.ReadAll(part)
				if err != nil {
					return nil, fmt.Errorf("failed to read part content: %w", err)
				}

				messagePart := MessagePart{
					ContentType: partContentType,
					Encoding:    part.Header.Get("Content-Transfer-Encoding"),
					Content:     string(content),
					IsHTML:      strings.Contains(strings.ToLower(partMediaType), "html"),
					IsText:      strings.Contains(strings.ToLower(partMediaType), "text"),
				}
				parts = append(parts, messagePart)
			}
		}
	} else {
		// Single part message
		content, err := io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body content: %w", err)
		}

		parts = []MessagePart{
			{
				ContentType: contentType,
				Content:     string(content),
				IsHTML:      strings.Contains(strings.ToLower(mediaType), "html"),
				IsText:      strings.Contains(strings.ToLower(mediaType), "text"),
			},
		}
	}

	return parts, nil
}

// buildRawHeaders reconstructs the raw header string
func buildRawHeaders(header mail.Header) string {
	var sb strings.Builder
	for key, values := range header {
		for _, value := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	return sb.String()
}

// GetAuthenticationResults extracts Authentication-Results headers
// If hostname is provided, only returns headers that begin with that hostname
func (e *EmailMessage) GetAuthenticationResults() []string {
	allResults := e.Header[textproto.CanonicalMIMEHeaderKey("Authentication-Results")]

	// If no hostname specified, return all results
	if hostname == "" {
		return allResults
	}

	// Filter results that begin with the specified hostname
	var filtered []string
	prefix := hostname + ";"
	for _, result := range allResults {
		// Trim whitespace and check if it starts with hostname;
		trimmed := strings.TrimSpace(result)
		if strings.HasPrefix(trimmed, prefix) {
			filtered = append(filtered, result)
		}
	}

	return filtered
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
		if values, ok := e.Header[headerName]; ok && len(values) > 0 {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					headers[headerName] = value
					break
				}
			}
		} else if value := e.Header.Get(headerName); value != "" {
			headers[headerName] = value
		}
	}

	return headers
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
