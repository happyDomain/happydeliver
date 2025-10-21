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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"git.happydns.org/happyDeliver/internal/api"
	"golang.org/x/net/html"
)

// ContentAnalyzer analyzes email content (HTML, links, images)
type ContentAnalyzer struct {
	Timeout    time.Duration
	httpClient *http.Client
}

// NewContentAnalyzer creates a new content analyzer with configurable timeout
func NewContentAnalyzer(timeout time.Duration) *ContentAnalyzer {
	if timeout == 0 {
		timeout = 10 * time.Second // Default timeout
	}
	return &ContentAnalyzer{
		Timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// ContentResults represents content analysis results
type ContentResults struct {
	HTMLValid        bool
	HTMLErrors       []string
	Links            []LinkCheck
	Images           []ImageCheck
	HasUnsubscribe   bool
	UnsubscribeLinks []string
	TextContent      string
	HTMLContent      string
	TextPlainRatio   float32 // Ratio of plain text to HTML consistency
	ImageTextRatio   float32 // Ratio of images to text
	SuspiciousURLs   []string
	ContentIssues    []string
}

// LinkCheck represents a link validation result
type LinkCheck struct {
	URL     string
	Valid   bool
	Status  int
	Error   string
	IsSafe  bool
	Warning string
}

// ImageCheck represents an image validation result
type ImageCheck struct {
	Src      string
	HasAlt   bool
	AltText  string
	Valid    bool
	Error    string
	IsBroken bool
}

// AnalyzeContent performs content analysis on email message
func (c *ContentAnalyzer) AnalyzeContent(email *EmailMessage) *ContentResults {
	results := &ContentResults{}

	// Get HTML and text parts
	htmlParts := email.GetHTMLParts()
	textParts := email.GetTextParts()

	// Analyze HTML parts
	if len(htmlParts) > 0 {
		for _, part := range htmlParts {
			c.analyzeHTML(part.Content, results)
		}
	}

	// Analyze text parts
	if len(textParts) > 0 {
		for _, part := range textParts {
			results.TextContent += part.Content
		}
	}

	// Check plain text/HTML consistency
	if len(htmlParts) > 0 && len(textParts) > 0 {
		results.TextPlainRatio = c.calculateTextPlainConsistency(results.TextContent, results.HTMLContent)
	}

	return results
}

// analyzeHTML parses and analyzes HTML content
func (c *ContentAnalyzer) analyzeHTML(htmlContent string, results *ContentResults) {
	results.HTMLContent = htmlContent

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		results.HTMLValid = false
		results.HTMLErrors = append(results.HTMLErrors, fmt.Sprintf("Failed to parse HTML: %v", err))
		return
	}

	results.HTMLValid = true

	// Traverse HTML tree
	c.traverseHTML(doc, results)

	// Calculate image-to-text ratio
	if results.HTMLContent != "" {
		textLength := len(c.extractTextFromHTML(htmlContent))
		imageCount := len(results.Images)
		if textLength > 0 {
			results.ImageTextRatio = float32(imageCount) / float32(textLength) * 1000 // Images per 1000 chars
		}
	}
}

// traverseHTML recursively traverses HTML nodes
func (c *ContentAnalyzer) traverseHTML(n *html.Node, results *ContentResults) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			// Extract and validate links
			href := c.getAttr(n, "href")
			if href != "" {
				// Check for unsubscribe links
				if c.isUnsubscribeLink(href, n) {
					results.HasUnsubscribe = true
					results.UnsubscribeLinks = append(results.UnsubscribeLinks, href)
				}

				// Validate link
				linkCheck := c.validateLink(href)
				results.Links = append(results.Links, linkCheck)

				// Check for suspicious URLs
				if !linkCheck.IsSafe {
					results.SuspiciousURLs = append(results.SuspiciousURLs, href)
				}
			}

		case "img":
			// Extract and validate images
			src := c.getAttr(n, "src")
			alt := c.getAttr(n, "alt")

			imageCheck := ImageCheck{
				Src:     src,
				HasAlt:  alt != "",
				AltText: alt,
				Valid:   src != "",
			}

			if src == "" {
				imageCheck.Error = "Image missing src attribute"
			}

			results.Images = append(results.Images, imageCheck)
		}
	}

	// Traverse children
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		c.traverseHTML(child, results)
	}
}

// getAttr gets an attribute value from an HTML node
func (c *ContentAnalyzer) getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// isUnsubscribeLink checks if a link is an unsubscribe link
func (c *ContentAnalyzer) isUnsubscribeLink(href string, node *html.Node) bool {
	// Check href for unsubscribe keywords
	lowerHref := strings.ToLower(href)
	unsubKeywords := []string{"unsubscribe", "opt-out", "optout", "remove", "list-unsubscribe"}
	for _, keyword := range unsubKeywords {
		if strings.Contains(lowerHref, keyword) {
			return true
		}
	}

	// Check link text for unsubscribe keywords
	text := c.getNodeText(node)
	lowerText := strings.ToLower(text)
	for _, keyword := range unsubKeywords {
		if strings.Contains(lowerText, keyword) {
			return true
		}
	}

	return false
}

// getNodeText extracts text content from a node
func (c *ContentAnalyzer) getNodeText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var text string
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		text += c.getNodeText(child)
	}
	return text
}

// validateLink validates a URL and checks if it's accessible
func (c *ContentAnalyzer) validateLink(urlStr string) LinkCheck {
	check := LinkCheck{
		URL:    urlStr,
		IsSafe: true,
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		check.Valid = false
		check.Error = fmt.Sprintf("Invalid URL: %v", err)
		return check
	}

	// Check URL safety
	if c.isSuspiciousURL(urlStr, parsedURL) {
		check.IsSafe = false
		check.Warning = "URL appears suspicious (obfuscated, shortened, or unusual)"
	}

	// Only check HTTP/HTTPS links
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		check.Valid = true
		return check
	}

	// Check if link is accessible (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		check.Valid = false
		check.Error = fmt.Sprintf("Failed to create request: %v", err)
		return check
	}

	// Set a reasonable user agent
	req.Header.Set("User-Agent", "HappyDeliver/1.0 (Email Deliverability Tester)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Don't fail on timeout/connection errors for external links
		// Just mark as warning
		check.Valid = true
		check.Status = 0
		check.Warning = fmt.Sprintf("Could not verify link: %v", err)
		return check
	}
	defer resp.Body.Close()

	check.Status = resp.StatusCode
	check.Valid = true

	// Check for error status codes
	if resp.StatusCode >= 400 {
		check.Error = fmt.Sprintf("Link returns %d status", resp.StatusCode)
	}

	return check
}

// isSuspiciousURL checks if a URL looks suspicious
func (c *ContentAnalyzer) isSuspiciousURL(urlStr string, parsedURL *url.URL) bool {
	// Check for IP address instead of domain
	if c.isIPAddress(parsedURL.Host) {
		return true
	}

	// Check for URL shorteners (common ones)
	shorteners := []string{
		"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
		"buff.ly", "is.gd", "bl.ink", "short.io",
	}
	for _, shortener := range shorteners {
		if strings.Contains(strings.ToLower(parsedURL.Host), shortener) {
			return true
		}
	}

	// Check for excessive subdomains (possible obfuscation)
	parts := strings.Split(parsedURL.Host, ".")
	if len(parts) > 4 {
		return true
	}

	// Check for URL obfuscation techniques
	if strings.Count(urlStr, "@") > 0 { // @ in URL (possible phishing)
		return true
	}

	// Check for suspicious characters in domain
	if strings.ContainsAny(parsedURL.Host, "[]()<>") {
		return true
	}

	return false
}

// isIPAddress checks if a string is an IP address
func (c *ContentAnalyzer) isIPAddress(host string) bool {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Simple check for IPv4
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			// Check if all characters are digits
			for _, ch := range part {
				if !unicode.IsDigit(ch) {
					return false
				}
			}
		}
		return true
	}

	// Check for IPv6 (contains colons)
	if strings.Contains(host, ":") {
		return true
	}

	return false
}

// extractTextFromHTML extracts plain text from HTML
func (c *ContentAnalyzer) extractTextFromHTML(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return ""
	}

	var text strings.Builder
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
		// Skip script and style tags
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			extract(child)
		}
	}
	extract(doc)

	return text.String()
}

// calculateTextPlainConsistency compares plain text and HTML versions
func (c *ContentAnalyzer) calculateTextPlainConsistency(plainText, htmlText string) float32 {
	// Extract text from HTML
	htmlPlainText := c.extractTextFromHTML(htmlText)

	// Normalize both texts
	plainNorm := c.normalizeText(plainText)
	htmlNorm := c.normalizeText(htmlPlainText)

	// Calculate similarity using simple word overlap
	plainWords := strings.Fields(plainNorm)
	htmlWords := strings.Fields(htmlNorm)

	if len(plainWords) == 0 || len(htmlWords) == 0 {
		return 0.0
	}

	// Count common words
	commonWords := 0
	plainWordSet := make(map[string]bool)
	for _, word := range plainWords {
		plainWordSet[word] = true
	}

	for _, word := range htmlWords {
		if plainWordSet[word] {
			commonWords++
		}
	}

	// Calculate ratio (Jaccard similarity approximation)
	maxWords := len(plainWords)
	if len(htmlWords) > maxWords {
		maxWords = len(htmlWords)
	}

	if maxWords == 0 {
		return 0.0
	}

	return float32(commonWords) / float32(maxWords)
}

// normalizeText normalizes text for comparison
func (c *ContentAnalyzer) normalizeText(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove extra whitespace
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	return text
}

// GenerateContentAnalysis creates structured content analysis from results
func (c *ContentAnalyzer) GenerateContentAnalysis(results *ContentResults) *api.ContentAnalysis {
	if results == nil {
		return nil
	}

	analysis := &api.ContentAnalysis{
		HasHtml:            api.PtrTo(results.HTMLContent != ""),
		HasPlaintext:       api.PtrTo(results.TextContent != ""),
		HasUnsubscribeLink: api.PtrTo(results.HasUnsubscribe),
	}

	// Calculate text-to-image ratio (inverse of image-to-text)
	if len(results.Images) > 0 && results.HTMLContent != "" {
		textLen := float32(len(c.extractTextFromHTML(results.HTMLContent)))
		if textLen > 0 {
			ratio := textLen / float32(len(results.Images))
			analysis.TextToImageRatio = &ratio
		}
	}

	// Build HTML issues
	htmlIssues := []api.ContentIssue{}

	// Add HTML parsing errors
	if !results.HTMLValid && len(results.HTMLErrors) > 0 {
		for _, errMsg := range results.HTMLErrors {
			htmlIssues = append(htmlIssues, api.ContentIssue{
				Type:     api.BrokenHtml,
				Severity: api.ContentIssueSeverityHigh,
				Message:  errMsg,
				Advice:   api.PtrTo("Fix HTML structure errors to improve email rendering across clients"),
			})
		}
	}

	// Add missing alt text issues
	if len(results.Images) > 0 {
		missingAltCount := 0
		for _, img := range results.Images {
			if !img.HasAlt {
				missingAltCount++
			}
		}
		if missingAltCount > 0 {
			htmlIssues = append(htmlIssues, api.ContentIssue{
				Type:     api.MissingAlt,
				Severity: api.ContentIssueSeverityMedium,
				Message:  fmt.Sprintf("%d image(s) missing alt attributes", missingAltCount),
				Advice:   api.PtrTo("Add descriptive alt text to all images for better accessibility and deliverability"),
			})
		}
	}

	// Add excessive images issue
	if results.ImageTextRatio > 10.0 {
		htmlIssues = append(htmlIssues, api.ContentIssue{
			Type:     api.ExcessiveImages,
			Severity: api.ContentIssueSeverityMedium,
			Message:  "Email is excessively image-heavy",
			Advice:   api.PtrTo("Reduce the number of images relative to text content"),
		})
	}

	// Add suspicious URL issues
	for _, suspURL := range results.SuspiciousURLs {
		htmlIssues = append(htmlIssues, api.ContentIssue{
			Type:     api.SuspiciousLink,
			Severity: api.ContentIssueSeverityHigh,
			Message:  "Suspicious URL detected",
			Location: &suspURL,
			Advice:   api.PtrTo("Avoid URL shorteners, IP addresses, and obfuscated URLs in emails"),
		})
	}

	if len(htmlIssues) > 0 {
		analysis.HtmlIssues = &htmlIssues
	}

	// Convert links
	if len(results.Links) > 0 {
		links := make([]api.LinkCheck, 0, len(results.Links))
		for _, link := range results.Links {
			status := api.Valid
			if link.Status >= 400 {
				status = api.Broken
			} else if !link.IsSafe {
				status = api.Suspicious
			} else if link.Warning != "" {
				status = api.Timeout
			}

			apiLink := api.LinkCheck{
				Url:    link.URL,
				Status: status,
			}

			if link.Status > 0 {
				apiLink.HttpCode = api.PtrTo(link.Status)
			}

			// Check if it's a URL shortener
			parsedURL, err := url.Parse(link.URL)
			if err == nil {
				isShortened := c.isSuspiciousURL(link.URL, parsedURL)
				apiLink.IsShortened = api.PtrTo(isShortened)
			}

			links = append(links, apiLink)
		}
		analysis.Links = &links
	}

	// Convert images
	if len(results.Images) > 0 {
		images := make([]api.ImageCheck, 0, len(results.Images))
		for _, img := range results.Images {
			apiImg := api.ImageCheck{
				HasAlt: img.HasAlt,
			}
			if img.Src != "" {
				apiImg.Src = &img.Src
			}
			if img.AltText != "" {
				apiImg.AltText = &img.AltText
			}
			// Simple heuristic: tracking pixels are typically 1x1
			apiImg.IsTrackingPixel = api.PtrTo(false)

			images = append(images, apiImg)
		}
		analysis.Images = &images
	}

	// Unsubscribe methods
	if results.HasUnsubscribe {
		methods := []api.ContentAnalysisUnsubscribeMethods{api.Link}
		analysis.UnsubscribeMethods = &methods
	}

	return analysis
}

// CalculateContentScore calculates the content score (0-20 points)
func (c *ContentAnalyzer) CalculateContentScore(results *ContentResults) int {
	if results == nil {
		return 0
	}

	var score int = 0

	// HTML validity (10 points)
	if results.HTMLValid {
		score += 10
	}

	// Links (20 points)
	if len(results.Links) > 0 {
		brokenLinks := 0
		for _, link := range results.Links {
			if link.Status >= 400 {
				brokenLinks++
			}
		}
		if brokenLinks == 0 {
			score += 20
		}
	} else {
		// No links is neutral, give partial score
		score += 10
	}

	// Images (15 points)
	if len(results.Images) > 0 {
		noAltCount := 0
		for _, img := range results.Images {
			if !img.HasAlt {
				noAltCount++
			}
		}
		if noAltCount == 0 {
			score += 15
		} else if noAltCount < len(results.Images) {
			score += 7
		}
	} else {
		// No images is neutral
		score += 7
	}

	// Unsubscribe link (15 points)
	if results.HasUnsubscribe {
		score += 15
	}

	// Text consistency (15 points)
	if results.TextPlainRatio >= 0.3 {
		score += 15
	}

	// Image ratio (15 points)
	if results.ImageTextRatio <= 5.0 {
		score += 15
	} else if results.ImageTextRatio <= 10.0 {
		score += 7
	}

	// Penalize suspicious URLs (deduct up to 5 points)
	if len(results.SuspiciousURLs) > 0 {
		penalty := len(results.SuspiciousURLs)
		if penalty > 5.0 {
			penalty = 5
		}
		score -= penalty
	}

	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
