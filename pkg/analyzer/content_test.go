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
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

func TestNewContentAnalyzer(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "Default timeout",
			timeout:         0,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "Custom timeout",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewContentAnalyzer(tt.timeout)
			if analyzer.Timeout != tt.expectedTimeout {
				t.Errorf("Timeout = %v, want %v", analyzer.Timeout, tt.expectedTimeout)
			}
			if analyzer.httpClient == nil {
				t.Error("httpClient should not be nil")
			}
		})
	}
}

func TestExtractTextFromHTML(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		expectedText string
	}{
		{
			name:         "Simple text",
			html:         "<p>Hello World</p>",
			expectedText: "Hello World",
		},
		{
			name:         "Multiple elements",
			html:         "<div><h1>Title</h1><p>Paragraph</p></div>",
			expectedText: "TitleParagraph",
		},
		{
			name:         "With script tag",
			html:         "<p>Text</p><script>alert('hi')</script><p>More</p>",
			expectedText: "TextMore",
		},
		{
			name:         "With style tag",
			html:         "<p>Text</p><style>.class { color: red; }</style><p>More</p>",
			expectedText: "TextMore",
		},
		{
			name:         "Empty HTML",
			html:         "",
			expectedText: "",
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := analyzer.extractTextFromHTML(tt.html)
			if text != tt.expectedText {
				t.Errorf("extractTextFromHTML() = %q, want %q", text, tt.expectedText)
			}
		})
	}
}

func TestIsUnsubscribeLink(t *testing.T) {
	tests := []struct {
		name     string
		href     string
		linkText string
		expected bool
	}{
		{
			name:     "Unsubscribe in URL",
			href:     "https://example.com/unsubscribe?id=123",
			linkText: "Click here",
			expected: true,
		},
		{
			name:     "Unsubscribe in text",
			href:     "https://example.com/action?id=123",
			linkText: "Unsubscribe from this list",
			expected: true,
		},
		{
			name:     "Opt-out in URL",
			href:     "https://example.com/optout",
			linkText: "Click here",
			expected: true,
		},
		{
			name:     "Remove in text",
			href:     "https://example.com/action",
			linkText: "Remove me from list",
			expected: true,
		},
		{
			name:     "Normal link",
			href:     "https://example.com/article",
			linkText: "Read more",
			expected: false,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple text node for testing
			html := "<a href=\"" + tt.href + "\">" + tt.linkText + "</a>"
			doc, _ := parseHTML(html)
			linkNode := findFirstLink(doc)

			if linkNode == nil {
				t.Fatal("Failed to parse test HTML")
			}

			result := analyzer.isUnsubscribeLink(tt.href, linkNode)
			if result != tt.expected {
				t.Errorf("isUnsubscribeLink(%q, %q) = %v, want %v", tt.href, tt.linkText, result, tt.expected)
			}
		})
	}
}

func TestIsSuspiciousURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Normal HTTPS URL",
			url:      "https://example.com/page",
			expected: false,
		},
		{
			name:     "URL with IP address",
			url:      "https://192.168.1.1/page",
			expected: true,
		},
		{
			name:     "URL with IPv6",
			url:      "https://[2001:db8::1]/page",
			expected: true,
		},
		{
			name:     "URL shortener - bit.ly",
			url:      "https://bit.ly/abc123",
			expected: true,
		},
		{
			name:     "URL shortener - tinyurl",
			url:      "https://tinyurl.com/abc123",
			expected: true,
		},
		{
			name:     "Excessive subdomains",
			url:      "https://a.b.c.d.e.example.com/page",
			expected: true,
		},
		{
			name:     "URL with @ (phishing)",
			url:      "https://user@example.com/page",
			expected: true,
		},
		{
			name:     "Normal subdomain",
			url:      "https://mail.example.com/page",
			expected: false,
		},
		{
			name:     "Mailto with @ symbol",
			url:      "mailto:support@example.com",
			expected: false,
		},
		{
			name:     "Mailto with multiple @ symbols",
			url:      "mailto:user@subdomain@example.com",
			expected: false,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := parseURL(tt.url)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			result := analyzer.isSuspiciousURL(tt.url, parsedURL)
			if result != tt.expected {
				t.Errorf("isSuspiciousURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "IPv4 address",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "IPv4 with port",
			host:     "192.168.1.1:8080",
			expected: true,
		},
		{
			name:     "IPv6 address",
			host:     "2001:db8::1",
			expected: true,
		},
		{
			name:     "Domain name",
			host:     "example.com",
			expected: false,
		},
		{
			name:     "Subdomain",
			host:     "mail.example.com",
			expected: false,
		},
		{
			name:     "Localhost",
			host:     "localhost",
			expected: false,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.isIPAddress(tt.host)
			if result != tt.expected {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestCalculateTextPlainConsistency(t *testing.T) {
	tests := []struct {
		name             string
		plainText        string
		htmlText         string
		expectedMinRatio float32
		expectedMaxRatio float32
	}{
		{
			name:             "Identical content",
			plainText:        "Hello World Test",
			htmlText:         "<p>Hello World Test</p>",
			expectedMinRatio: 0.8,
			expectedMaxRatio: 1.0,
		},
		{
			name:             "Similar content",
			plainText:        "Hello World",
			htmlText:         "<p>Hello World Extra</p>",
			expectedMinRatio: 0.3,
			expectedMaxRatio: 0.8,
		},
		{
			name:             "Different content",
			plainText:        "Completely different",
			htmlText:         "<p>Nothing alike here</p>",
			expectedMinRatio: 0.0,
			expectedMaxRatio: 0.3,
		},
		{
			name:             "Empty plain text",
			plainText:        "",
			htmlText:         "<p>Some text</p>",
			expectedMinRatio: 0.0,
			expectedMaxRatio: 0.0,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := analyzer.calculateTextPlainConsistency(tt.plainText, tt.htmlText)
			if ratio < tt.expectedMinRatio || ratio > tt.expectedMaxRatio {
				t.Errorf("calculateTextPlainConsistency() = %v, want between %v and %v",
					ratio, tt.expectedMinRatio, tt.expectedMaxRatio)
			}
		})
	}
}

func TestNormalizeText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Uppercase to lowercase",
			input:    "Hello WORLD",
			expected: "hello world",
		},
		{
			name:     "Multiple spaces",
			input:    "Hello    World",
			expected: "hello world",
		},
		{
			name:     "Tabs and newlines",
			input:    "Hello\t\nWorld",
			expected: "hello world",
		},
		{
			name:     "Leading and trailing spaces",
			input:    "  Hello World  ",
			expected: "hello world",
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.normalizeText(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeText(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAnalyzeContent_HTMLParsing(t *testing.T) {
	tests := []struct {
		name         string
		email        *EmailMessage
		expectValid  bool
		expectLinks  int
		expectImages int
	}{
		{
			name: "Valid HTML with links and images",
			email: &EmailMessage{
				Header: make(mail.Header),
				Parts: []MessagePart{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content: `
							<html>
								<body>
									<p>Hello World</p>
									<a href="https://example.com">Link</a>
									<img src="https://example.com/image.jpg" alt="Test">
								</body>
							</html>
						`,
					},
				},
			},
			expectValid:  true,
			expectLinks:  1,
			expectImages: 1,
		},
		{
			name: "Multiple links",
			email: &EmailMessage{
				Header: make(mail.Header),
				Parts: []MessagePart{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content: `
							<html>
								<body>
									<a href="https://example.com">Link 1</a>
									<a href="https://example.org">Link 2</a>
									<a href="https://example.net">Link 3</a>
								</body>
							</html>
						`,
					},
				},
			},
			expectValid:  true,
			expectLinks:  3,
			expectImages: 0,
		},
		{
			name: "Plain text only",
			email: &EmailMessage{
				Header: make(mail.Header),
				Parts: []MessagePart{
					{
						ContentType: "text/plain",
						IsText:      true,
						Content:     "Plain text email",
					},
				},
			},
			expectValid:  false,
			expectLinks:  0,
			expectImages: 0,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := analyzer.AnalyzeContent(tt.email)

			if results == nil {
				t.Fatal("Expected results, got nil")
			}

			if results.HTMLValid != tt.expectValid {
				t.Errorf("HTMLValid = %v, want %v", results.HTMLValid, tt.expectValid)
			}

			if len(results.Links) != tt.expectLinks {
				t.Errorf("Got %d links, want %d", len(results.Links), tt.expectLinks)
			}

			if len(results.Images) != tt.expectImages {
				t.Errorf("Got %d images, want %d", len(results.Images), tt.expectImages)
			}
		})
	}
}

func TestAnalyzeContent_UnsubscribeDetection(t *testing.T) {
	tests := []struct {
		name              string
		html              string
		expectUnsubscribe bool
		expectCount       int
	}{
		{
			name: "With unsubscribe link",
			html: `<html><body>
				<p>Email content</p>
				<a href="https://example.com/unsubscribe">Unsubscribe</a>
			</body></html>`,
			expectUnsubscribe: true,
			expectCount:       1,
		},
		{
			name: "Multiple unsubscribe links",
			html: `<html><body>
				<a href="https://example.com/unsubscribe">Unsubscribe</a>
				<a href="https://example.com/optout">Opt out</a>
			</body></html>`,
			expectUnsubscribe: true,
			expectCount:       2,
		},
		{
			name: "No unsubscribe link",
			html: `<html><body>
				<p>Email content</p>
				<a href="https://example.com/article">Read more</a>
			</body></html>`,
			expectUnsubscribe: false,
			expectCount:       0,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: make(mail.Header),
				Parts: []MessagePart{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content:     tt.html,
					},
				},
			}

			results := analyzer.AnalyzeContent(email)

			if results.HasUnsubscribe != tt.expectUnsubscribe {
				t.Errorf("HasUnsubscribe = %v, want %v", results.HasUnsubscribe, tt.expectUnsubscribe)
			}

			if len(results.UnsubscribeLinks) != tt.expectCount {
				t.Errorf("Got %d unsubscribe links, want %d", len(results.UnsubscribeLinks), tt.expectCount)
			}
		})
	}
}

func TestAnalyzeContent_ImageAltAttributes(t *testing.T) {
	tests := []struct {
		name          string
		html          string
		expectImages  int
		expectWithAlt int
	}{
		{
			name: "Images with alt",
			html: `<html><body>
				<img src="image1.jpg" alt="Description 1">
				<img src="image2.jpg" alt="Description 2">
			</body></html>`,
			expectImages:  2,
			expectWithAlt: 2,
		},
		{
			name: "Images without alt",
			html: `<html><body>
				<img src="image1.jpg">
				<img src="image2.jpg">
			</body></html>`,
			expectImages:  2,
			expectWithAlt: 0,
		},
		{
			name: "Mixed images",
			html: `<html><body>
				<img src="image1.jpg" alt="Description">
				<img src="image2.jpg">
			</body></html>`,
			expectImages:  2,
			expectWithAlt: 1,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: make(mail.Header),
				Parts: []MessagePart{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content:     tt.html,
					},
				},
			}

			results := analyzer.AnalyzeContent(email)

			if len(results.Images) != tt.expectImages {
				t.Errorf("Got %d images, want %d", len(results.Images), tt.expectImages)
			}

			withAlt := 0
			for _, img := range results.Images {
				if img.HasAlt {
					withAlt++
				}
			}

			if withAlt != tt.expectWithAlt {
				t.Errorf("Got %d images with alt, want %d", withAlt, tt.expectWithAlt)
			}
		})
	}
}

// Helper functions for testing

func parseHTML(htmlStr string) (*html.Node, error) {
	return html.Parse(strings.NewReader(htmlStr))
}

func findFirstLink(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "a" {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if result := findFirstLink(c); result != nil {
			return result
		}
	}
	return nil
}

func parseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}

func TestHasDomainMisalignment(t *testing.T) {
	tests := []struct {
		name     string
		href     string
		linkText string
		expected bool
		reason   string
	}{
		// Phishing cases - should return true
		{
			name:     "Obvious phishing - different domains",
			href:     "https://evil.com/page",
			linkText: "Click here to verify your paypal.com account",
			expected: true,
			reason:   "Link text shows 'paypal.com' but URL points to 'evil.com'",
		},
		{
			name:     "Domain in link text differs from URL",
			href:     "http://attacker.net",
			linkText: "Visit google.com for more info",
			expected: true,
			reason:   "Link text shows 'google.com' but URL points to 'attacker.net'",
		},
		{
			name:     "URL shown in text differs from actual URL",
			href:     "https://phishing-site.xyz/login",
			linkText: "https://www.bank.example.com/secure",
			expected: true,
			reason:   "Full URL in text doesn't match actual destination",
		},
		{
			name:     "Similar but different domain",
			href:     "https://paypa1.com/login",
			linkText: "Login to your paypal.com account",
			expected: true,
			reason:   "Typosquatting: 'paypa1.com' vs 'paypal.com'",
		},
		{
			name:     "Subdomain spoofing",
			href:     "https://paypal.com.evil.com/login",
			linkText: "Verify your paypal.com account",
			expected: true,
			reason:   "Domain is 'evil.com', not 'paypal.com'",
		},
		{
			name:     "Multiple domains in text, none match",
			href:     "https://badsite.com",
			linkText: "Transfer from bank.com to paypal.com",
			expected: true,
			reason:   "Neither 'bank.com' nor 'paypal.com' matches 'badsite.com'",
		},

		// Legitimate cases - should return false
		{
			name:     "Exact domain match",
			href:     "https://example.com/page",
			linkText: "Visit example.com for more information",
			expected: false,
			reason:   "Domains match exactly",
		},
		{
			name:     "Legitimate subdomain",
			href:     "https://mail.google.com/inbox",
			linkText: "Check your google.com email",
			expected: false,
			reason:   "Subdomain of the mentioned domain",
		},
		{
			name:     "www prefix variation",
			href:     "https://www.example.com/page",
			linkText: "Visit example.com",
			expected: false,
			reason:   "www prefix is acceptable variation",
		},
		{
			name:     "Generic link text - click here",
			href:     "https://anywhere.com",
			linkText: "click here",
			expected: false,
			reason:   "Generic text doesn't contain a domain",
		},
		{
			name:     "Generic link text - read more",
			href:     "https://example.com/article",
			linkText: "Read more",
			expected: false,
			reason:   "Generic text doesn't contain a domain",
		},
		{
			name:     "Generic link text - learn more",
			href:     "https://example.com/info",
			linkText: "Learn More",
			expected: false,
			reason:   "Generic text doesn't contain a domain (case insensitive)",
		},
		{
			name:     "No domain in link text",
			href:     "https://example.com/page",
			linkText: "Click to continue",
			expected: false,
			reason:   "Link text has no domain reference",
		},
		{
			name:     "Short link text",
			href:     "https://example.com",
			linkText: "Go",
			expected: false,
			reason:   "Text too short to contain meaningful domain",
		},
		{
			name:     "Empty link text",
			href:     "https://example.com",
			linkText: "",
			expected: false,
			reason:   "Empty text cannot contain domain",
		},
		{
			name:     "Mailto link - matching domain",
			href:     "mailto:support@example.com",
			linkText: "Email support@example.com",
			expected: false,
			reason:   "Mailto email matches text email",
		},
		{
			name:     "Mailto link - domain mismatch (phishing)",
			href:     "mailto:attacker@evil.com",
			linkText: "Contact support@paypal.com for help",
			expected: true,
			reason:   "Mailto domain 'evil.com' doesn't match text domain 'paypal.com'",
		},
		{
			name:     "Mailto link - generic text",
			href:     "mailto:info@example.com",
			linkText: "Contact us",
			expected: false,
			reason:   "Generic text without domain reference",
		},
		{
			name:     "Mailto link - same domain different user",
			href:     "mailto:sales@example.com",
			linkText: "Email support@example.com",
			expected: false,
			reason:   "Both emails share the same domain",
		},
		{
			name:     "Mailto link - text shows only domain",
			href:     "mailto:info@example.com",
			linkText: "Write to example.com",
			expected: false,
			reason:   "Text domain matches mailto domain",
		},
		{
			name:     "Mailto link - domain in text doesn't match",
			href:     "mailto:scam@phishing.net",
			linkText: "Reply to customer-service@amazon.com",
			expected: true,
			reason:   "Mailto domain 'phishing.net' doesn't match 'amazon.com' in text",
		},
		{
			name:     "Tel link",
			href:     "tel:+1234567890",
			linkText: "Call example.com support",
			expected: false,
			reason:   "Non-HTTP(S) links are excluded",
		},
		{
			name:     "Same base domain with different subdomains",
			href:     "https://www.example.com/page",
			linkText: "Visit blog.example.com",
			expected: false,
			reason:   "Both share same base domain 'example.com'",
		},
		{
			name:     "URL with path matches domain in text",
			href:     "https://example.com/section/page",
			linkText: "Go to example.com",
			expected: false,
			reason:   "Domain matches, path doesn't matter",
		},
		{
			name:     "Generic text - subscribe",
			href:     "https://newsletter.example.com/signup",
			linkText: "Subscribe",
			expected: false,
			reason:   "Generic call-to-action text",
		},
		{
			name:     "Generic text - unsubscribe",
			href:     "https://example.com/unsubscribe?id=123",
			linkText: "Unsubscribe",
			expected: false,
			reason:   "Generic unsubscribe text",
		},
		{
			name:     "Generic text - download",
			href:     "https://files.example.com/document.pdf",
			linkText: "Download",
			expected: false,
			reason:   "Generic action text",
		},
		{
			name:     "Descriptive text without domain",
			href:     "https://shop.example.com/products",
			linkText: "View our latest products",
			expected: false,
			reason:   "No domain mentioned in text",
		},

		// Edge cases
		{
			name:     "Domain-like text but not valid domain",
			href:     "https://example.com",
			linkText: "Save up to 50.00 dollars",
			expected: false,
			reason:   "50.00 looks like domain but isn't",
		},
		{
			name:     "Text with http prefix matching domain",
			href:     "https://example.com/page",
			linkText: "Visit http://example.com",
			expected: false,
			reason:   "Domains match despite different protocols in display",
		},
		{
			name:     "Port in URL should not affect matching",
			href:     "https://example.com:8080/page",
			linkText: "Go to example.com",
			expected: false,
			reason:   "Port number doesn't affect domain matching",
		},
		{
			name:     "Whitespace in link text",
			href:     "https://example.com",
			linkText: "  example.com  ",
			expected: false,
			reason:   "Whitespace should be trimmed",
		},
		{
			name:     "Multiple spaces in generic text",
			href:     "https://example.com",
			linkText: "click  here",
			expected: false,
			reason:   "Generic text with extra spaces",
		},
		{
			name:     "Anchor fragment in URL",
			href:     "https://example.com/page#section",
			linkText: "example.com section",
			expected: false,
			reason:   "Fragment doesn't affect domain matching",
		},
		{
			name:     "Query parameters in URL",
			href:     "https://example.com/page?utm_source=email",
			linkText: "Visit example.com",
			expected: false,
			reason:   "Query params don't affect domain matching",
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.hasDomainMisalignment(tt.href, tt.linkText)
			if result != tt.expected {
				t.Errorf("hasDomainMisalignment(%q, %q) = %v, want %v\nReason: %s",
					tt.href, tt.linkText, result, tt.expected, tt.reason)
			}
		})
	}
}
