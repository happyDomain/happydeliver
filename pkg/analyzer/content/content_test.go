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

package content

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"golang.org/x/net/html"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
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
			analyzer := NewAnalyzer(tt.timeout)
			if analyzer.Timeout != tt.expectedTimeout {
				t.Errorf("Timeout = %v, want %v", analyzer.Timeout, tt.expectedTimeout)
			}
			if analyzer.prober == nil {
				t.Error("the analyzer has nothing to fetch the message's URLs with")
			}
		})
	}
}

func TestExtractTextFromNode(t *testing.T) {
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
			expectedText: "Title Paragraph",
		},
		{
			name:         "With script tag",
			html:         "<p>Text</p><script>alert('hi')</script><p>More</p>",
			expectedText: "Text More",
		},
		{
			name:         "With style tag",
			html:         "<p>Text</p><style>.class { color: red; }</style><p>More</p>",
			expectedText: "Text More",
		},
		{
			name:         "Empty HTML",
			html:         "",
			expectedText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := html.Parse(strings.NewReader(tt.html))
			if err != nil {
				t.Fatalf("html.Parse() error = %v", err)
			}

			if text := extractTextFromNode(doc); text != tt.expectedText {
				t.Errorf("extractTextFromNode() = %q, want %q", text, tt.expectedText)
			}
		})
	}
}

// TestIsUnsubscribeLink exercises isUnsubscribeLink. A link counts as an
// unsubscribe link if its href exactly matches one of the URLs advertised in
// the List-Unsubscribe header, or if either the href or the visible link
// text contains one of a large multilingual keyword list, case-insensitively
// ("unsubscribe", "opt-out", "remove", "abmelden", "désabonner", ...) — a
// match in either place is sufficient. The one override: a href containing
// an unreplaced template placeholder (see TestIsTemplatePlaceholderURL) is
// never counted, even if it also contains "unsubscribe" literally, since it
// isn't a working link.
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
		// Multilingual keyword detection - URL path
		{
			name:     "German abmelden in URL",
			href:     "https://example.com/abmelden?id=42",
			linkText: "Click here",
			expected: true,
		},
		{
			name:     "French se-desabonner slug in URL (no accent/space - not detected by keyword)",
			href:     "https://example.com/se-desabonner?id=42",
			linkText: "Click here",
			expected: false,
		},
		// Multilingual keyword detection - link text
		{
			name:     "German Abmelden in link text",
			href:     "https://example.com/manage?id=42&lang=de",
			linkText: "Abmelden",
			expected: true,
		},
		{
			name:     "French Se désabonner in link text",
			href:     "https://example.com/manage?id=42&lang=fr",
			linkText: "Se désabonner",
			expected: true,
		},
		{
			name:     "Russian Отписаться in link text",
			href:     "https://example.com/manage?id=42&lang=ru",
			linkText: "Отписаться",
			expected: true,
		},
		{
			name:     "Chinese 退订 in link text",
			href:     "https://example.com/manage?id=42&lang=zh",
			linkText: "退订",
			expected: true,
		},
		{
			name:     "Japanese 登録を取り消す in link text",
			href:     "https://example.com/manage?id=42&lang=ja",
			linkText: "登録を取り消す",
			expected: true,
		},
		{
			name:     "Korean 구독 해지 in link text",
			href:     "https://example.com/manage?id=42&lang=ko",
			linkText: "구독 해지",
			expected: true,
		},
		{
			name:     "Dutch Uitschrijven in link text",
			href:     "https://example.com/manage?id=42&lang=nl",
			linkText: "Uitschrijven",
			expected: true,
		},
		{
			name:     "Polish Odsubskrybuj in link text",
			href:     "https://example.com/manage?id=42&lang=pl",
			linkText: "Odsubskrybuj",
			expected: true,
		},
		{
			name:     "Turkish Üyeliği sonlandır in link text",
			href:     "https://example.com/manage?id=42&lang=tr",
			linkText: "Üyeliği sonlandır",
			expected: true,
		},
		// Unreplaced template placeholders must NOT count as unsubscribe methods
		{
			name:     "Curly brace template placeholder",
			href:     "{unsubscribe}",
			linkText: "Unsubscribe",
			expected: false,
		},
		{
			name:     "Double curly brace template placeholder",
			href:     "{{unsubscribe_url}}",
			linkText: "Unsubscribe",
			expected: false,
		},
		{
			name:     "Mailchimp merge tag placeholder",
			href:     "*|UNSUB|*",
			linkText: "Unsubscribe here",
			expected: false,
		},
	}

	analyzer := NewAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple text node for testing
			html := "<a href=\"" + tt.href + "\">" + tt.linkText + "</a>"
			doc, _ := parseHTML(html)
			linkNode := findFirstLink(doc)

			if linkNode == nil {
				t.Fatal("Failed to parse test HTML")
			}

			result := analyzer.isUnsubscribeLink(tt.href, linkNode, nil)
			if result != tt.expected {
				t.Errorf("isUnsubscribeLink(%q, %q) = %v, want %v", tt.href, tt.linkText, result, tt.expected)
			}
		})
	}
}

func TestAnalyzeContent_HTMLParsing(t *testing.T) {
	tests := []struct {
		name         string
		email        *mailmsg.Message
		expectValid  bool
		expectLinks  int
		expectImages int
	}{
		{
			name: "Valid HTML with links and images",
			email: &mailmsg.Message{
				Header: make(mail.Header),
				Parts: []mailmsg.Part{
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
			email: &mailmsg.Message{
				Header: make(mail.Header),
				Parts: []mailmsg.Part{
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
			email: &mailmsg.Message{
				Header: make(mail.Header),
				Parts: []mailmsg.Part{
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

	analyzer := NewAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := analyzer.Analyze(tt.email)

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

	analyzer := NewAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: make(mail.Header),
				Parts: []mailmsg.Part{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content:     tt.html,
					},
				},
			}

			results := analyzer.Analyze(email)

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

	analyzer := NewAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &mailmsg.Message{
				Header: make(mail.Header),
				Parts: []mailmsg.Part{
					{
						ContentType: "text/html",
						IsHTML:      true,
						Content:     tt.html,
					},
				},
			}

			results := analyzer.Analyze(email)

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
			href:     "https://evil.example.net/page",
			linkText: "Click here to verify your bank.example.org account",
			expected: true,
			reason:   "Link text shows 'bank.example.org' but URL points to 'evil.example.net'",
		},
		{
			name:     "Domain in link text differs from URL",
			href:     "http://attacker.example.net",
			linkText: "Visit shop.example.org for more info",
			expected: true,
			reason:   "Link text shows 'shop.example.org' but URL points to 'attacker.example.net'",
		},
		{
			name:     "URL shown in text differs from actual URL",
			href:     "https://phishing-site.example/login",
			linkText: "https://www.bank.example.com/secure",
			expected: true,
			reason:   "Full URL in text doesn't match actual destination",
		},
		{
			name:     "Similar but different domain",
			href:     "https://bank.exarnple.example/login",
			linkText: "Login to your bank.example.com account",
			expected: true,
			reason:   "Typosquatting: 'exarnple.example' vs 'example.com'",
		},
		{
			name:     "Subdomain spoofing",
			href:     "https://bank.example.com.evil.example.net/login",
			linkText: "Verify your bank.example.com account",
			expected: true,
			reason:   "Domain is 'evil.example.net', not 'bank.example.com'",
		},
		{
			name:     "Multiple domains in text, none match",
			href:     "https://badsite.example.net",
			linkText: "Transfer from bank.example.org to wallet.example.org",
			expected: true,
			reason:   "Neither 'bank.example.org' nor 'wallet.example.org' matches 'badsite.example.net'",
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
			href:     "https://mail.example.com/inbox",
			linkText: "Check your example.com email",
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
			href:     "https://anywhere.example.net",
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
			href:     "mailto:attacker@evil.example.net",
			linkText: "Contact support@bank.example.org for help",
			expected: true,
			reason:   "Mailto domain 'evil.example.net' doesn't match text domain 'bank.example.org'",
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
			href:     "mailto:scam@phishing.example.net",
			linkText: "Reply to customer-service@shop.example.org",
			expected: true,
			reason:   "Mailto domain 'phishing.example.net' doesn't match 'shop.example.org' in text",
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

		// Prose that merely looks like a domain: a file name, or a full stop
		// with no space after it, must never be read as an advertised domain.
		{
			name:     "File name in link text",
			href:     "https://t.example-mail.com/abc",
			linkText: "Télécharger la facture.pdf",
			expected: false,
			reason:   "'.pdf' is not a TLD: the text advertises no domain at all",
		},
		{
			name:     "Archive file name in link text",
			href:     "https://t.example-mail.com/abc",
			linkText: "Votre rapport annuel 2024.zip",
			expected: false,
			reason:   "'.zip' is a TLD but ends a file name here",
		},
		{
			name:     "Missing space after full stop",
			href:     "https://t.example-mail.com/abc",
			linkText: "Commandez maintenant.Livraison offerte",
			expected: false,
			reason:   "'.livraison' is not a TLD: this is a typo, not a domain",
		},
		{
			name:     "Missing space before a word that is a ccTLD",
			href:     "https://t.example-mail.com/abc",
			linkText: "Commandez maintenant.Il ne reste que 2 jours",
			expected: false,
			reason:   "'.il' is a real ccTLD, but the capital says this is a full stop",
		},
		{
			name:     "Domain glued to a longer word",
			href:     "https://t.example-mail.com/abc",
			linkText: "voir photo1example.com2 ici",
			expected: false,
			reason:   "The token is not delimited, so it advertises nothing",
		},

		// Look-alikes that share a suffix with the real domain: comparing
		// anything but the registrable domain lets them through.
		{
			name:     "Text domain is a suffix of the destination",
			href:     "https://fakeexample.com/login",
			linkText: "Log in on example.com",
			expected: true,
			reason:   "'fakeexample.com' merely ends with 'example.com', it is another domain",
		},
		{
			name:     "Different domains under a multi-level suffix",
			href:     "https://evil.co.uk/login",
			linkText: "Log in on example.co.uk",
			expected: true,
			reason:   "Sharing 'co.uk' does not make two domains the same party",
		},
		{
			name:     "Subdomain under a multi-level suffix",
			href:     "https://links.example.co.uk/x",
			linkText: "Visit example.co.uk",
			expected: false,
			reason:   "Same registrable domain 'example.co.uk'",
		},
		{
			name:     "Text domain under a private suffix",
			href:     "https://evil.example.net/login",
			linkText: "Read the guide on docs.example.github.io",
			expected: true,
			reason:   "A host under a private suffix is still an advertised domain",
		},
		{
			name:     "Sibling hosts under a private suffix",
			href:     "https://evil.github.io/login",
			linkText: "Read the guide on docs.github.io",
			expected: true,
			reason:   "'github.io' is a suffix: two names under it are two parties",
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

		// Internationalised domains: the same host has two spellings, and the
		// message is read on where it goes, not on which of the two it used.
		{
			name:     "Host advertised in Unicode, linked in punycode",
			href:     "https://xn--xample-9ua.org/login",
			linkText: "Connectez-vous sur éxample.org",
			expected: false,
			reason:   "'éxample.org' and 'xn--xample-9ua.org' are the same host written twice",
		},
		{
			name:     "Host advertised in punycode, linked in Unicode",
			href:     "https://éxample.org/login",
			linkText: "Connectez-vous sur xn--xample-9ua.org",
			expected: false,
			reason:   "Same host again, the two spellings the other way round",
		},
		{
			name:     "Non-Latin host advertised and linked",
			href:     "https://пример.example.com/page",
			linkText: "Rendez-vous sur пример.example.com",
			expected: false,
			reason:   "A host in another script matches itself once both sides are in A-labels",
		},
		{
			name:     "Unicode host advertised, another domain linked",
			href:     "https://example.com/login",
			linkText: "Connectez-vous sur éxample.org",
			expected: true,
			reason:   "The text names a host in Unicode that is not where the link goes",
		},
		{
			name:     "Unicode look-alike linked, plain host advertised",
			href:     "https://xn--xample-9ua.org/login",
			linkText: "Connectez-vous sur example.org",
			expected: true,
			reason:   "The link goes to a look-alike of the domain its text advertises",
		},
	}

	analyzer := NewAnalyzer(5 * time.Second)

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

// TestIsTemplatePlaceholderURL exercises isTemplatePlaceholderURL against
// templatePlaceholderRegex; see that regex's doc comment in content.go for
// the full grammar (curly/dollar/percent/bracket tags, Mailchimp merge tags,
// URL-encoded curly braces) and why percent-encoded octets like "%C3%A9" or
// "%E2%80%A6" are deliberately not mistaken for a "%tag%" placeholder.
func TestIsTemplatePlaceholderURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{name: "Single curly braces", url: "{unsubscribe}", expected: true},
		{name: "Double curly braces", url: "{{unsubscribe_url}}", expected: true},
		{name: "Dollar braces", url: "${unsubscribe}", expected: true},
		{name: "Mailchimp merge tag", url: "*|UNSUB|*", expected: true},
		{name: "Percent tag", url: "%unsubscribe%", expected: true},
		{name: "Double percent tag", url: "%%unsubscribe%%", expected: true},
		{name: "Square bracket tag", url: "[unsubscribe]", expected: true},
		{name: "URL-encoded curly braces", url: "https://example.com/u/%7Btoken%7D", expected: true},
		{name: "Placeholder embedded in URL", url: "https://example.com/unsub?id={{recipient_id}}", expected: true},
		{name: "Normal https URL", url: "https://example.com/unsubscribe?id=123", expected: false},
		{name: "Normal URL with percent-encoded space", url: "https://example.com/path%20name", expected: false},
		{name: "Percent-encoded accented char (é)", url: "https://example.com/caf%C3%A9/unsubscribe", expected: false},
		{name: "Percent-encoded UTF-8 ellipsis", url: "https://example.com/path?q=%E2%80%A6", expected: false},
		{name: "Percent-encoded Cyrillic", url: "https://example.com/r?u=%D0%BF%D1%80%D0%B8%D0%B2", expected: false},
		{name: "Adjacent percent-encoded octets (all hex)", url: "https://example.com/%aa%bb", expected: false},
		{name: "Percent escape then literal hex letters", url: "https://example.com/x%def%20y", expected: false},
		{name: "Short percent tag with non-hex letter", url: "%id%", expected: true},
		{name: "Percent tag as whole query value", url: "https://example.com/track?click=%CLICKID%&x=1", expected: true},
		{name: "Percent tag as path segment", url: "https://example.com/unsub/%TOKEN%/confirm", expected: true},
		{name: "Doubly percent-encoded URL with domain text between octets", url: "https://example.com/redirect?U=https%3A%2F%2Fwww.example.org%2Fpath%2Fpage%3Fref_%3Dabc123", expected: false},
		{name: "Mailto URL", url: "mailto:unsubscribe@example.com", expected: false},
		{name: "IPv6 URL (square brackets, not a tag)", url: "http://[::1]/unsubscribe", expected: false},
		{name: "IPv6 URL with hex-letter host", url: "http://[fe80::1]/unsubscribe", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTemplatePlaceholderURL(tt.url); got != tt.expected {
				t.Errorf("isTemplatePlaceholderURL(%q) = %v, want %v", tt.url, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeLinkOffline_TemplatePlaceholderIsInvalid(t *testing.T) {
	check := analyzeLinkOffline("{unsubscribe}")
	if check.Valid {
		t.Errorf("analyzeLinkOffline(%q).Valid = true, want false", "{unsubscribe}")
	}
	if check.Error == "" {
		t.Errorf("analyzeLinkOffline(%q).Error is empty, want a template placeholder error", "{unsubscribe}")
	}
}

func TestGenerateContentAnalysis_TemplateLinkNotUnsubscribe(t *testing.T) {
	analyzer := NewAnalyzer(5 * time.Second)

	results := &Results{
		HTMLContent:    "<html><body><a href=\"{unsubscribe}\">Unsubscribe</a></body></html>",
		Links:          []LinkCheck{{URL: "{unsubscribe}", Valid: false, IsTemplate: true, IsSafe: true, Error: "template"}},
		HasUnsubscribe: false,
	}

	analysis := analyzer.analysisOf(results)

	// The link must be reported as broken, not valid
	if analysis.Links == nil || len(*analysis.Links) != 1 {
		t.Fatalf("expected 1 link in analysis, got %v", analysis.Links)
	}
	if (*analysis.Links)[0].Status != model.LinkCheckStatusBroken {
		t.Errorf("template link status = %q, want %q", (*analysis.Links)[0].Status, model.LinkCheckStatusBroken)
	}

	// It must not be counted as an unsubscribe method
	if analysis.UnsubscribeMethods != nil && slices.Contains(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsLink) {
		t.Errorf("template link wrongly counted as an unsubscribe method: %v", *analysis.UnsubscribeMethods)
	}

	// An unreplaced template issue must be reported
	foundIssue := false
	if analysis.HtmlIssues != nil {
		for _, issue := range *analysis.HtmlIssues {
			if issue.Type == model.IssueTypeUnreplacedTemplate {
				foundIssue = true
			}
		}
	}
	if !foundIssue {
		t.Errorf("expected an unreplaced_template content issue, got %v", analysis.HtmlIssues)
	}
}

// A body that could not be read through to its end must not be credited with a
// perfect plain-text/HTML consistency: its parts are the ones that arrived, not
// the ones that were sent. Here the announced boundary never appears, so no part
// is found at all, which used to look exactly like a plain single-part message.
func TestAnalyzeContentIncompleteBodyNotPerfectRatio(t *testing.T) {
	raw := "From: sender@example.com\r\n" +
		"To: recipient@example.org\r\n" +
		"Subject: Test\r\n" +
		"Content-Type: multipart/alternative; boundary=\"never-appears\"\r\n" +
		"\r\n" +
		"<html><body>Hello</body></html>\r\n"

	email, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("mailmsg.Parse() error = %v", err)
	}
	if !email.BodyIncomplete {
		t.Fatalf("BodyIncomplete = false, want true for a boundary that never appears")
	}

	analyzer := NewAnalyzer(0)
	results := analyzer.Analyze(email)
	if results.TextAlternative != textAltUnknown {
		t.Errorf("TextAlternative = %s, want unknown for an unreadable body", results.TextAlternative)
	}
	if !results.BodyTruncated {
		t.Errorf("BodyTruncated = false, want true so the parts read as unknown rather than as a failure")
	}

	// The truncation must be told, not silently folded into the score.
	analysis := analyzer.analysisOf(results)
	found := false
	if analysis.HtmlIssues != nil {
		for _, issue := range *analysis.HtmlIssues {
			if issue.Type == model.IssueTypeTruncatedBody {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected a truncated_body content issue, got %v", analysis.HtmlIssues)
	}
}

// The consistency criterion a truncated body cannot answer is dropped from the
// total rather than failed: the message loses no point for bytes that went
// missing on their way to us.
func TestCalculateContentScoreTruncatedBodyDropsConsistency(t *testing.T) {
	analyzer := NewAnalyzer(0)

	complete := Results{
		HTMLValid:       true,
		TextContent:     "Hello",
		HTMLContent:     "<html><body>Hello</body></html>",
		TextAlternative: textAltOK,
	}
	want, _ := analyzer.scoreOf(&complete)

	// The same message, read from a body that stopped short: no counterpart to
	// compare the HTML against, hence no verdict.
	truncated := complete
	truncated.TextAlternative = textAltUnknown
	truncated.BodyTruncated = true
	got, _ := analyzer.scoreOf(&truncated)

	if got != want {
		t.Errorf("Score() = %d for a truncated body, want %d, the score of the same message read whole", got, want)
	}

	// A message that did arrive whole and genuinely lacks consistency still
	// loses those points: the exemption is about what we could not read.
	inconsistent := complete
	inconsistent.TextAlternative = textAltStale
	if score, _ := analyzer.scoreOf(&inconsistent); score >= want {
		t.Errorf("Score() = %d for a complete body with no consistency, want less than %d", score, want)
	}
}

// A tracking pixel is told apart from a picture by what it is drawn as: one
// pixel wide and high, in attributes or in style, or hidden altogether.
func TestIsTrackingPixel(t *testing.T) {
	tests := []struct {
		name string
		img  string
		want bool
	}{
		{"attributes 1x1", `<img src="https://example.com/o.gif" width="1" height="1">`, true},
		{"attributes 0x0", `<img src="https://example.com/o.gif" width="0" height="0">`, true},
		{"style 1px", `<img src="https://example.com/o.gif" style="width:1px;height:1px">`, true},
		{"style with spaces and case", `<img src="https://example.com/o.gif" style="Width: 1PX ; Height : 1px">`, true},
		{"display none", `<img src="https://example.com/o.gif" style="display:none">`, true},
		{"visibility hidden", `<img src="https://example.com/o.gif" style="visibility: hidden">`, true},
		{"hidden attribute", `<img src="https://example.com/o.gif" hidden>`, true},
		{"one pixel high banner", `<img src="https://example.com/rule.gif" width="600" height="1">`, false},
		{"no dimensions", `<img src="https://example.com/logo.png">`, false},
		{"logo", `<img src="https://example.com/logo.png" width="200" height="50" alt="Logo">`, false},
		{"percent width", `<img src="https://example.com/logo.png" style="width:100%">`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTML(tt.img)
			if err != nil {
				t.Fatalf("parseHTML() error = %v", err)
			}
			var node *html.Node
			var find func(*html.Node)
			find = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "img" {
					node = n
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					find(c)
				}
			}
			find(doc)
			if node == nil {
				t.Fatalf("no <img> in %q", tt.img)
			}

			if got := isTrackingPixel(node); got != tt.want {
				t.Errorf("isTrackingPixel(%s) = %v, want %v", tt.img, got, tt.want)
			}
		})
	}
}

// A tracking pixel has no alt text and shows nothing, and the message is
// judged on neither: the pixel is reported for what it is, then left out of
// the images the recipient is meant to see.
func TestAnalyzeContent_TrackingPixelNotAnImageIssue(t *testing.T) {
	// The pixel answers, as a real one does: what is tested is how it is
	// graded, not whether it loads.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	analyzer := newProbingTestAnalyzer(5 * time.Second)

	email := &mailmsg.Message{
		Header: make(mail.Header),
		Parts: []mailmsg.Part{
			{
				ContentType: "text/html",
				IsHTML:      true,
				Content: `<html><body><p>Hello there</p>
					<img src="` + server.URL + `/open.gif" width="1" height="1">
				</body></html>`,
			},
		},
	}

	results := analyzer.Analyze(email)
	if len(results.Images) != 1 || !results.Images[0].IsTrackingPixel {
		t.Fatalf("Images = %+v, want one tracking pixel", results.Images)
	}
	if results.ImageTextRatio != 0 {
		t.Errorf("ImageTextRatio = %v, want 0: a pixel is not a picture", results.ImageTextRatio)
	}

	analysis := analyzer.analysisOf(results)
	if img := (*analysis.Images)[0]; img.IsTrackingPixel == nil || !*img.IsTrackingPixel {
		t.Errorf("reported image = %+v, want it flagged as a tracking pixel", img)
	}
	if analysis.HtmlIssues != nil {
		for _, issue := range *analysis.HtmlIssues {
			if issue.Type == model.IssueTypeMissingAlt {
				t.Errorf("got a missing_alt issue for a tracking pixel: %s", issue.Message)
			}
		}
	}

	// The pixel costs what a described picture at the same address would,
	// which is to say nothing for its missing alt text.
	score, _ := analyzer.scoreOf(results)
	results.Images[0].IsTrackingPixel = false
	results.Images[0].HasAlt = true
	described, _ := analyzer.scoreOf(results)
	if score != described {
		t.Errorf("Score() = %d with a tracking pixel, want %d, the score of a described picture", score, described)
	}
}

// An image without alt text costs its share of the images criterion, over a
// count of at least five: one undescribed picture among few is three points
// short, not fifteen, and a message whose every picture is undescribed still
// loses the criterion once there are five of them.
func TestScoreImageShareFloor(t *testing.T) {
	analyzer := NewAnalyzer(0)

	// A message answering every criterion, so that the points lost are read
	// on the scale they are written on.
	score := func(images []ImageCheck) int {
		got, _ := analyzer.scoreOf(&Results{HTMLValid: true, TextContent: "hello", TextAlternative: textAltOK, Images: images})
		return got
	}

	described := ImageCheck{Src: "https://example.com/a.png", HasAlt: true, AltText: "A"}
	undescribed := ImageCheck{Src: "https://example.com/b.png"}

	perfect := score([]ImageCheck{described})

	tests := []struct {
		name   string
		images []ImageCheck
		lost   int
	}{
		{"one image, undescribed", []ImageCheck{undescribed}, 3},
		{"two images, one undescribed", []ImageCheck{described, undescribed}, 3},
		{"two images, both undescribed", []ImageCheck{undescribed, undescribed}, 6},
		{"five images, all undescribed", []ImageCheck{undescribed, undescribed, undescribed, undescribed, undescribed}, 15},
		{"ten images, five undescribed", append([]ImageCheck{undescribed, undescribed, undescribed, undescribed, undescribed}, described, described, described, described, described), 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := perfect - score(tt.images); got != tt.lost {
				t.Errorf("lost %d points, want %d", got, tt.lost)
			}
		})
	}
}

// TestWithoutSentencePunctuation takes the prose off the end of a URL written
// in a sentence, and leaves a URL what is its own.
func TestWithoutSentencePunctuation(t *testing.T) {
	tests := map[string]string{
		"https://example.com/x.":         "https://example.com/x",
		"https://example.com/x?a=1!?":    "https://example.com/x?a=1",
		"https://example.com/x).":        "https://example.com/x",
		"https://example.com/x.)":        "https://example.com/x",
		"https://example.com/(x)":        "https://example.com/(x)",
		"https://example.com/(x).":       "https://example.com/(x)",
		"https://example.com/x":          "https://example.com/x",
		"https://example.com/\"quoted\"": "https://example.com/\"quoted",
	}

	for rawURL, want := range tests {
		if got := withoutSentencePunctuation(rawURL); got != want {
			t.Errorf("withoutSentencePunctuation(%q) = %q, want %q", rawURL, got, want)
		}
	}
}

// TestContentCriteriaSumToTheScale holds the score to the scale it is
// expressed on: a criterion added without taking its weight from another would
// otherwise quietly make a hundred mean something else, and the penalties the
// checks deduct are expressed in points of that hundred.
func TestContentCriteriaSumToTheScale(t *testing.T) {
	total := 0
	seen := make(map[string]bool, len(contentCriteria))

	for i, criterion := range contentCriteria {
		if criterion.Name == "" {
			t.Errorf("criterion %d has no name", i)
		}
		if seen[criterion.Name] {
			t.Errorf("criterion %q is weighed twice", criterion.Name)
		}
		seen[criterion.Name] = true

		if criterion.Weight <= 0 {
			t.Errorf("criterion %q weighs %d, so nothing it judges counts", criterion.Name, criterion.Weight)
		}
		total += criterion.Weight
	}

	if total != 100 {
		t.Errorf("the criteria weigh %d in all, want 100", total)
	}
}

// TestAWithdrawnCriterionIsNotFailed pins how a criterion that cannot be
// judged is handled: it leaves the scale, and the message is graded on what
// was readable. Failing it instead would charge the sender for bytes that
// never arrived.
func TestAWithdrawnCriterionIsNotFailed(t *testing.T) {
	analyzer := NewAnalyzer(time.Second)

	whole := &Results{HTMLValid: true, TextContent: "hello", TextAlternative: textAltOK}
	cut := &Results{HTMLValid: true, TextContent: "hello", BodyTruncated: true}

	wholeScore, _ := analyzer.scoreOf(whole)
	cutScore, _ := analyzer.scoreOf(cut)

	if wholeScore != 100 {
		t.Fatalf("a message answering every criterion scored %d, want 100", wholeScore)
	}
	if cutScore != 100 {
		t.Errorf("a message whose body was cut short scored %d on the criteria it could still answer, want 100", cutScore)
	}
}

// A truncated body must not collect the "no links, no images" credits either:
// crediting a message for content it does not appear to have is rewarding an
// absence of evidence, not an absence of links or images. It used to come out
// around 80/100, no worse than a genuinely empty, fully-read message.
func TestAnalyzeContent_IncompleteBodyIsNotScoredAsClean(t *testing.T) {
	analyzer := NewAnalyzer(5 * time.Second)

	incomplete := analyzer.Analyze(&mailmsg.Message{
		Header:         make(mail.Header),
		BodyIncomplete: true,
	})
	empty := analyzer.Analyze(&mailmsg.Message{
		Header: make(mail.Header),
	})

	if incomplete.TextAlternative != textAltUnknown {
		t.Errorf("TextAlternative = %s, want unknown for a body that could not be read", incomplete.TextAlternative)
	}
	if empty.TextAlternative != textAltUnknown {
		t.Errorf("TextAlternative = %s, want unknown for a message carrying no part at all: there is nothing to compare, which is not the same as two parts that agree", empty.TextAlternative)
	}

	incompleteScore, _ := analyzer.scoreOf(incomplete)
	emptyScore, _ := analyzer.scoreOf(empty)
	if incompleteScore >= emptyScore {
		t.Errorf("Unreadable body scored %d, no better than a readable empty one at %d", incompleteScore, emptyScore)
	}
}

// htmlResults reads a one-part HTML message, which is what the markup walk is
// given in production. Nothing is fetched: the fixtures below carry no link
// and no image.
func htmlResults(t *testing.T, body string) *Results {
	t.Helper()

	return NewAnalyzer(time.Second).Analyze(&mailmsg.Message{
		Header: make(mail.Header),
		Parts:  []mailmsg.Part{{ContentType: "text/html", IsHTML: true, Content: body}},
	})
}

func TestAnalyzeLinkOffline_URLThatDoesNotParse(t *testing.T) {
	check := analyzeLinkOffline("http://exa mple.com/")

	if check.Valid || check.Error == "" {
		t.Errorf("analyzeLinkOffline of a URL that does not parse = %+v, want it invalid with a reason", check)
	}
}

// TestAnalysisLinkStatus pins the status a link is reported under, from what
// fetching it turned up.
func TestAnalysisLinkStatus(t *testing.T) {
	analyzer := NewAnalyzer(5 * time.Second)

	loop := LinkHTTPFinding{Kind: LinkHTTPRedirectLoop}

	tests := []struct {
		name string
		link LinkCheck
		want model.LinkCheckStatus
	}{
		{"answers", LinkCheck{URL: "https://example.com/", Valid: true, IsSafe: true, probedURL: probedURL{Status: 200}}, model.LinkCheckStatusValid},
		{"not found", LinkCheck{URL: "https://example.com/", Valid: true, IsSafe: true, probedURL: probedURL{Status: 404}}, model.LinkCheckStatusBroken},
		{"redirects forever", LinkCheck{URL: "https://example.com/", Valid: true, IsSafe: true, probedURL: probedURL{HTTPFindings: []LinkHTTPFinding{loop}}}, model.LinkCheckStatusBroken},
		{"suspicious", LinkCheck{URL: "https://example.com/", Valid: true, IsSafe: false, probedURL: probedURL{Status: 200}}, model.LinkCheckStatusSuspicious},
		{"could not be verified", LinkCheck{URL: "https://example.com/", Valid: true, IsSafe: true, Warning: "Could not verify link"}, model.LinkCheckStatusTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzer.analysisOf(&Results{HTMLContent: "<p>x</p>", Links: []LinkCheck{tt.link}})

			if analysis.Links == nil || len(*analysis.Links) != 1 {
				t.Fatalf("expected 1 link in analysis, got %v", analysis.Links)
			}
			if got := (*analysis.Links)[0].Status; got != tt.want {
				t.Errorf("link status = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestHarmfulHTMLFindsTheMarkupClientsBlock covers the tags the check exists to
// spot. Each of them is either refused outright by mail clients or a phishing
// vector, so a message carrying one renders short of what its sender wrote,
// and this check is the only thing standing between that and a clean report.
//
// The expectations quote the markup the finding is asked to name, not the whole
// sentence it writes: the wording is for a reader and free to change, while
// naming the offending tag and what it pointed at is the finding itself.
func TestHarmfulHTMLFindsTheMarkupClientsBlock(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string // a fragment each expected issue must quote, in order
	}{
		{
			name: "markup a client renders as written draws nothing",
			body: `<html><body><p>Hello</p><b>World</b></body></html>`,
		},
		{
			name: "a script tag",
			body: `<html><body><script>alert(1)</script></body></html>`,
			want: []string{"<script>"},
		},
		{
			name: "an iframe, with what it would have loaded",
			body: `<html><body><iframe src="https://example.com/embed"></iframe></body></html>`,
			want: []string{"src='https://example.com/embed'"},
		},
		{
			name: "an iframe with nothing to load is still reported",
			body: `<html><body><iframe></iframe></body></html>`,
			want: []string{"<iframe>"},
		},
		{
			name: "the legacy embedding tags, each under its own name",
			body: `<html><body><object></object><embed><applet></applet></body></html>`,
			want: []string{"<object>", "<embed>", "<applet>"},
		},
		{
			name: "a form, with where it would have posted",
			body: `<html><body><form action="https://example.com/login"></form></body></html>`,
			want: []string{"action='https://example.com/login'"},
		},
		{
			name: "a base tag, which silently moves every relative URL",
			body: `<html><head><base href="https://example.com/"></head><body></body></html>`,
			want: []string{"href='https://example.com/'"},
		},
		{
			name: "a meta refresh, with the redirection it hides",
			body: `<html><head><meta http-equiv="refresh" content="0;url=https://example.com/"></head><body></body></html>`,
			want: []string{"content='0;url=https://example.com/'"},
		},
		{
			name: "a meta tag that redirects nothing is left alone",
			body: `<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head><body></body></html>`,
		},
		{
			name: "every offending tag of one message is reported, in the order it is written",
			body: `<html><head><base href="https://example.com/"></head><body><script></script><form></form></body></html>`,
			want: []string{"<base>", "<script>", "<form>"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues, _ := reading.Run(context.Background(), []contentCheck{harmfulHTMLCheck},
				htmlResults(t, test.body).checkInput())

			if len(issues) != len(test.want) {
				t.Fatalf("the check reported %d issue(s), want %d: %v", len(issues), len(test.want), issues)
			}
			for i, fragment := range test.want {
				if !strings.Contains(issues[i].Message, fragment) {
					t.Errorf("issue %d reads %q, want it to quote %q", i, issues[i].Message, fragment)
				}
			}
		})
	}
}

// TestHarmfulMarkupReachesTheReportAtAFlatRate follows what the check found all
// the way to the report. What is worth pinning here is the tariff: every tag is
// fatal to the same degree, and no amount of them may decide the grade on its
// own.
func TestHarmfulMarkupReachesTheReportAtAFlatRate(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		issues  int
		penalty int
	}{
		{
			name: "a message a client renders whole is charged nothing",
			body: `<html><body><p>Hello</p></body></html>`,
		},
		{
			name:    "one tag costs the flat rate",
			body:    `<html><body><script></script></body></html>`,
			issues:  1,
			penalty: 20,
		},
		{
			name:    "a second tag costs as much as the first",
			body:    `<html><body><script></script><iframe></iframe></body></html>`,
			issues:  2,
			penalty: 40,
		},
		{
			name:    "a message made of nothing else is still capped",
			body:    `<html><body><script></script><iframe></iframe><form></form><object></object></body></html>`,
			issues:  4,
			penalty: 40,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := htmlResults(t, test.body)

			issues, penalty := reading.Run(context.Background(), []contentCheck{harmfulHTMLCheck},
				results.checkInput())

			if len(issues) != test.issues {
				t.Fatalf("reported %d finding(s), want %d: %+v", len(issues), test.issues, issues)
			}
			if penalty != test.penalty {
				t.Errorf("charged %d point(s), want %d", penalty, test.penalty)
			}

			for _, issue := range issues {
				if issue.Type != model.IssueTypeDangerousHtml {
					t.Errorf("the finding is typed %q, want %q", issue.Type, model.IssueTypeDangerousHtml)
				}
				if issue.Severity != model.IssueSeverityCritical {
					t.Errorf("the finding is graded %q, want %q", issue.Severity, model.IssueSeverityCritical)
				}
				if issue.Advice == nil || *issue.Advice == "" {
					t.Error("the finding names a defect without saying what to do about it")
				}
			}
		})
	}
}

// TestHTMLRemarkOnlyNamesStylesheetsItCanFetch covers the other thing a reading
// of the markup gathers on its way: a remark about an external stylesheet. It
// is keyed on the URL it names, so a stylesheet designating nothing to fetch is
// worth no remark at all: there would be nothing for the spam filter's own
// reading of it to be recognised against.
func TestHTMLRemarkOnlyNamesStylesheetsItCanFetch(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string // the URL the remark must quote, or "" for no remark
	}{
		{
			name: "a stylesheet fetched over https",
			body: `<html><head><link rel="stylesheet" href="https://cdn.example.com/mail.css"></head><body></body></html>`,
			want: "https://cdn.example.com/mail.css",
		},
		{
			name: "the rel attribute is read whatever its case and company",
			body: `<html><head><link rel="Alternate StyleSheet" href="http://cdn.example.com/mail.css"></head><body></body></html>`,
			want: "http://cdn.example.com/mail.css",
		},
		{
			name: "a relative stylesheet designates nothing to fetch",
			body: `<html><head><link rel="stylesheet" href="/assets/mail.css"></head><body></body></html>`,
		},
		{
			name: "a stylesheet with no href at all",
			body: `<html><head><link rel="stylesheet"></head><body></body></html>`,
		},
		{
			name: "a link that is not a stylesheet is none of our business",
			body: `<html><head><link rel="canonical" href="https://example.com/page"></head><body></body></html>`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues, _ := reading.Run(context.Background(), []contentCheck{htmlRemarkCheck},
				htmlResults(t, test.body).checkInput())

			if test.want == "" {
				if len(issues) != 0 {
					t.Fatalf("the check remarked %v, want nothing", issues)
				}
				return
			}

			if len(issues) != 1 {
				t.Fatalf("the check left %d remark(s), want 1: %v", len(issues), issues)
			}
			if !strings.Contains(issues[0].Message, test.want) {
				t.Errorf("the remark reads %q, want it to quote %q", issues[0].Message, test.want)
			}
		})
	}
}
