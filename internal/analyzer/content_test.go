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

	"git.happydns.org/happyDeliver/internal/api"
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

func TestGenerateHTMLValidityCheck(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "Valid HTML",
			results: &ContentResults{
				HTMLValid: true,
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  0.2,
		},
		{
			name: "Invalid HTML",
			results: &ContentResults{
				HTMLValid:  false,
				HTMLErrors: []string{"Parse error"},
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateHTMLValidityCheck(tt.results)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
			if check.Category != api.Content {
				t.Errorf("Category = %v, want %v", check.Category, api.Content)
			}
		})
	}
}

func TestGenerateLinkChecks(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
		expectedScore  float32
	}{
		{
			name: "All links valid",
			results: &ContentResults{
				Links: []LinkCheck{
					{URL: "https://example.com", Valid: true, Status: 200},
					{URL: "https://example.org", Valid: true, Status: 200},
				},
			},
			expectedStatus: api.CheckStatusPass,
			expectedScore:  0.4,
		},
		{
			name: "Broken links",
			results: &ContentResults{
				Links: []LinkCheck{
					{URL: "https://example.com", Valid: true, Status: 404, Error: "Not found"},
				},
			},
			expectedStatus: api.CheckStatusFail,
			expectedScore:  0.0,
		},
		{
			name: "Links with warnings",
			results: &ContentResults{
				Links: []LinkCheck{
					{URL: "https://example.com", Valid: true, Warning: "Could not verify"},
				},
			},
			expectedStatus: api.CheckStatusWarn,
			expectedScore:  0.3,
		},
		{
			name:    "No links",
			results: &ContentResults{},
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.generateLinkChecks(tt.results)

			if tt.name == "No links" {
				if len(checks) != 0 {
					t.Errorf("Expected no checks, got %d", len(checks))
				}
				return
			}

			if len(checks) == 0 {
				t.Fatal("Expected at least one check")
			}

			check := checks[0]
			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", check.Score, tt.expectedScore)
			}
		})
	}
}

func TestGenerateImageChecks(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
	}{
		{
			name: "All images have alt",
			results: &ContentResults{
				Images: []ImageCheck{
					{Src: "img1.jpg", HasAlt: true, AltText: "Alt 1"},
					{Src: "img2.jpg", HasAlt: true, AltText: "Alt 2"},
				},
			},
			expectedStatus: api.CheckStatusPass,
		},
		{
			name: "No images have alt",
			results: &ContentResults{
				Images: []ImageCheck{
					{Src: "img1.jpg", HasAlt: false},
					{Src: "img2.jpg", HasAlt: false},
				},
			},
			expectedStatus: api.CheckStatusFail,
		},
		{
			name: "Some images have alt",
			results: &ContentResults{
				Images: []ImageCheck{
					{Src: "img1.jpg", HasAlt: true, AltText: "Alt 1"},
					{Src: "img2.jpg", HasAlt: false},
				},
			},
			expectedStatus: api.CheckStatusWarn,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.generateImageChecks(tt.results)

			if len(checks) == 0 {
				t.Fatal("Expected at least one check")
			}

			check := checks[0]
			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Category != api.Content {
				t.Errorf("Category = %v, want %v", check.Category, api.Content)
			}
		})
	}
}

func TestGenerateUnsubscribeCheck(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
	}{
		{
			name: "Has unsubscribe link",
			results: &ContentResults{
				HasUnsubscribe:   true,
				UnsubscribeLinks: []string{"https://example.com/unsubscribe"},
			},
			expectedStatus: api.CheckStatusPass,
		},
		{
			name:           "No unsubscribe link",
			results:        &ContentResults{},
			expectedStatus: api.CheckStatusWarn,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateUnsubscribeCheck(tt.results)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
			if check.Category != api.Content {
				t.Errorf("Category = %v, want %v", check.Category, api.Content)
			}
		})
	}
}

func TestGenerateTextConsistencyCheck(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
	}{
		{
			name: "High consistency",
			results: &ContentResults{
				TextPlainRatio: 0.8,
			},
			expectedStatus: api.CheckStatusPass,
		},
		{
			name: "Low consistency",
			results: &ContentResults{
				TextPlainRatio: 0.1,
			},
			expectedStatus: api.CheckStatusWarn,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateTextConsistencyCheck(tt.results)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
		})
	}
}

func TestGenerateImageRatioCheck(t *testing.T) {
	tests := []struct {
		name           string
		results        *ContentResults
		expectedStatus api.CheckStatus
	}{
		{
			name: "Reasonable ratio",
			results: &ContentResults{
				ImageTextRatio: 3.0,
				Images:         []ImageCheck{{}, {}, {}},
			},
			expectedStatus: api.CheckStatusPass,
		},
		{
			name: "High ratio",
			results: &ContentResults{
				ImageTextRatio: 7.0,
				Images:         make([]ImageCheck, 7),
			},
			expectedStatus: api.CheckStatusWarn,
		},
		{
			name: "Excessive ratio",
			results: &ContentResults{
				ImageTextRatio: 15.0,
				Images:         make([]ImageCheck, 15),
			},
			expectedStatus: api.CheckStatusFail,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := analyzer.generateImageRatioCheck(tt.results)

			if check.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", check.Status, tt.expectedStatus)
			}
		})
	}
}

func TestGenerateSuspiciousURLCheck(t *testing.T) {
	results := &ContentResults{
		SuspiciousURLs: []string{
			"https://bit.ly/abc123",
			"https://192.168.1.1/page",
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)
	check := analyzer.generateSuspiciousURLCheck(results)

	if check.Status != api.CheckStatusWarn {
		t.Errorf("Status = %v, want %v", check.Status, api.CheckStatusWarn)
	}
	if check.Category != api.Content {
		t.Errorf("Category = %v, want %v", check.Category, api.Content)
	}
	if !strings.Contains(check.Message, "2") {
		t.Error("Message should mention the count of suspicious URLs")
	}
}

func TestGetContentScore(t *testing.T) {
	tests := []struct {
		name     string
		results  *ContentResults
		minScore float32
		maxScore float32
	}{
		{
			name:     "Nil results",
			results:  nil,
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name: "Perfect content",
			results: &ContentResults{
				HTMLValid:      true,
				Links:          []LinkCheck{{Valid: true, Status: 200}},
				Images:         []ImageCheck{{HasAlt: true}},
				HasUnsubscribe: true,
				TextPlainRatio: 0.8,
				ImageTextRatio: 3.0,
			},
			minScore: 1.8,
			maxScore: 2.0,
		},
		{
			name: "Poor content",
			results: &ContentResults{
				HTMLValid:      false,
				Links:          []LinkCheck{{Valid: true, Status: 404}},
				Images:         []ImageCheck{{HasAlt: false}},
				HasUnsubscribe: false,
				TextPlainRatio: 0.1,
				ImageTextRatio: 15.0,
				SuspiciousURLs: []string{"url1", "url2"},
			},
			minScore: 0.0,
			maxScore: 0.5,
		},
		{
			name: "Average content",
			results: &ContentResults{
				HTMLValid:      true,
				Links:          []LinkCheck{{Valid: true, Status: 200}},
				Images:         []ImageCheck{{HasAlt: true}},
				HasUnsubscribe: false,
				TextPlainRatio: 0.5,
				ImageTextRatio: 4.0,
			},
			minScore: 1.0,
			maxScore: 1.8,
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.GetContentScore(tt.results)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("GetContentScore() = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
			}

			// Ensure score is capped at 2.0
			if score > 2.0 {
				t.Errorf("Score %v exceeds maximum of 2.0", score)
			}

			// Ensure score is not negative
			if score < 0.0 {
				t.Errorf("Score %v is negative", score)
			}
		})
	}
}

func TestGenerateContentChecks(t *testing.T) {
	tests := []struct {
		name      string
		results   *ContentResults
		minChecks int
	}{
		{
			name:      "Nil results",
			results:   nil,
			minChecks: 0,
		},
		{
			name: "Complete results",
			results: &ContentResults{
				HTMLValid:      true,
				Links:          []LinkCheck{{Valid: true}},
				Images:         []ImageCheck{{HasAlt: true}},
				HasUnsubscribe: true,
				TextContent:    "Plain text",
				HTMLContent:    "<p>HTML text</p>",
				ImageTextRatio: 3.0,
			},
			minChecks: 5, // HTML, Links, Images, Unsubscribe, Text consistency, Image ratio
		},
		{
			name: "With suspicious URLs",
			results: &ContentResults{
				HTMLValid:      true,
				SuspiciousURLs: []string{"url1"},
			},
			minChecks: 3, // HTML, Unsubscribe, Suspicious URLs
		},
	}

	analyzer := NewContentAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := analyzer.GenerateContentChecks(tt.results)

			if len(checks) < tt.minChecks {
				t.Errorf("Got %d checks, want at least %d", len(checks), tt.minChecks)
			}

			// Verify all checks have the Content category
			for _, check := range checks {
				if check.Category != api.Content {
					t.Errorf("Check %s has category %v, want %v", check.Name, check.Category, api.Content)
				}
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
