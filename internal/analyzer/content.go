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

// GenerateContentChecks generates check results for content analysis
func (c *ContentAnalyzer) GenerateContentChecks(results *ContentResults) []api.Check {
	var checks []api.Check

	if results == nil {
		return checks
	}

	// HTML validity check
	checks = append(checks, c.generateHTMLValidityCheck(results))

	// Link checks
	checks = append(checks, c.generateLinkChecks(results)...)

	// Image checks
	checks = append(checks, c.generateImageChecks(results)...)

	// Unsubscribe link check
	checks = append(checks, c.generateUnsubscribeCheck(results))

	// Text/HTML consistency check
	if results.TextContent != "" && results.HTMLContent != "" {
		checks = append(checks, c.generateTextConsistencyCheck(results))
	}

	// Image-to-text ratio check
	if len(results.Images) > 0 && results.HTMLContent != "" {
		checks = append(checks, c.generateImageRatioCheck(results))
	}

	// Suspicious URLs check
	if len(results.SuspiciousURLs) > 0 {
		checks = append(checks, c.generateSuspiciousURLCheck(results))
	}

	return checks
}

// generateHTMLValidityCheck creates a check for HTML validity
func (c *ContentAnalyzer) generateHTMLValidityCheck(results *ContentResults) api.Check {
	check := api.Check{
		Category: api.Content,
		Name:     "HTML Structure",
	}

	if !results.HTMLValid {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Medium)
		check.Message = "HTML structure is invalid"
		if len(results.HTMLErrors) > 0 {
			details := strings.Join(results.HTMLErrors, "; ")
			check.Details = &details
		}
		check.Advice = api.PtrTo("Fix HTML structure errors to improve email rendering")
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.2
		check.Severity = api.PtrTo(api.Info)
		check.Message = "HTML structure is valid"
		check.Advice = api.PtrTo("Your HTML is well-formed")
	}

	return check
}

// generateLinkChecks creates checks for links
func (c *ContentAnalyzer) generateLinkChecks(results *ContentResults) []api.Check {
	var checks []api.Check

	if len(results.Links) == 0 {
		return checks
	}

	// Count broken links
	brokenLinks := 0
	warningLinks := 0
	for _, link := range results.Links {
		if link.Status >= 400 {
			brokenLinks++
		} else if link.Warning != "" {
			warningLinks++
		}
	}

	check := api.Check{
		Category: api.Content,
		Name:     "Links",
	}

	if brokenLinks > 0 {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Severity = api.PtrTo(api.High)
		check.Message = fmt.Sprintf("Found %d broken link(s)", brokenLinks)
		check.Advice = api.PtrTo("Fix or remove broken links to improve deliverability")
		details := fmt.Sprintf("Total links: %d, Broken: %d", len(results.Links), brokenLinks)
		check.Details = &details
	} else if warningLinks > 0 {
		check.Status = api.CheckStatusWarn
		check.Score = 0.3
		check.Severity = api.PtrTo(api.Low)
		check.Message = fmt.Sprintf("Found %d link(s) that could not be verified", warningLinks)
		check.Advice = api.PtrTo("Review links that could not be verified")
		details := fmt.Sprintf("Total links: %d, Unverified: %d", len(results.Links), warningLinks)
		check.Details = &details
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.4
		check.Severity = api.PtrTo(api.Info)
		check.Message = fmt.Sprintf("All %d link(s) are valid", len(results.Links))
		check.Advice = api.PtrTo("Your links are working properly")
	}

	checks = append(checks, check)
	return checks
}

// generateImageChecks creates checks for images
func (c *ContentAnalyzer) generateImageChecks(results *ContentResults) []api.Check {
	var checks []api.Check

	if len(results.Images) == 0 {
		return checks
	}

	// Count images without alt text
	noAltCount := 0
	for _, img := range results.Images {
		if !img.HasAlt {
			noAltCount++
		}
	}

	check := api.Check{
		Category: api.Content,
		Name:     "Image Alt Attributes",
	}

	if noAltCount == len(results.Images) {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Medium)
		check.Message = "No images have alt attributes"
		check.Advice = api.PtrTo("Add alt text to all images for accessibility and deliverability")
		details := fmt.Sprintf("Images without alt: %d/%d", noAltCount, len(results.Images))
		check.Details = &details
	} else if noAltCount > 0 {
		check.Status = api.CheckStatusWarn
		check.Score = 0.2
		check.Severity = api.PtrTo(api.Low)
		check.Message = fmt.Sprintf("%d image(s) missing alt attributes", noAltCount)
		check.Advice = api.PtrTo("Add alt text to all images for better accessibility")
		details := fmt.Sprintf("Images without alt: %d/%d", noAltCount, len(results.Images))
		check.Details = &details
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.3
		check.Severity = api.PtrTo(api.Info)
		check.Message = "All images have alt attributes"
		check.Advice = api.PtrTo("Your images are properly tagged for accessibility")
	}

	checks = append(checks, check)
	return checks
}

// generateUnsubscribeCheck creates a check for unsubscribe links
func (c *ContentAnalyzer) generateUnsubscribeCheck(results *ContentResults) api.Check {
	check := api.Check{
		Category: api.Content,
		Name:     "Unsubscribe Link",
	}

	if !results.HasUnsubscribe {
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Low)
		check.Message = "No unsubscribe link found"
		check.Advice = api.PtrTo("Add an unsubscribe link for marketing emails (RFC 8058)")
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.3
		check.Severity = api.PtrTo(api.Info)
		check.Message = fmt.Sprintf("Found %d unsubscribe link(s)", len(results.UnsubscribeLinks))
		check.Advice = api.PtrTo("Your email includes an unsubscribe option")
	}

	return check
}

// generateTextConsistencyCheck creates a check for text/HTML consistency
func (c *ContentAnalyzer) generateTextConsistencyCheck(results *ContentResults) api.Check {
	check := api.Check{
		Category: api.Content,
		Name:     "Plain Text Consistency",
	}

	consistency := results.TextPlainRatio

	if consistency < 0.3 {
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Low)
		check.Message = "Plain text and HTML versions differ significantly"
		check.Advice = api.PtrTo("Ensure plain text and HTML versions convey the same content")
		details := fmt.Sprintf("Consistency: %.0f%%", consistency*100)
		check.Details = &details
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.3
		check.Severity = api.PtrTo(api.Info)
		check.Message = "Plain text and HTML versions are consistent"
		check.Advice = api.PtrTo("Your multipart email is well-structured")
		details := fmt.Sprintf("Consistency: %.0f%%", consistency*100)
		check.Details = &details
	}

	return check
}

// generateImageRatioCheck creates a check for image-to-text ratio
func (c *ContentAnalyzer) generateImageRatioCheck(results *ContentResults) api.Check {
	check := api.Check{
		Category: api.Content,
		Name:     "Image-to-Text Ratio",
	}

	ratio := results.ImageTextRatio

	// Flag if more than 1 image per 100 characters (very image-heavy)
	if ratio > 10.0 {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Severity = api.PtrTo(api.Medium)
		check.Message = "Email is excessively image-heavy"
		check.Advice = api.PtrTo("Reduce the number of images relative to text content")
		details := fmt.Sprintf("Images: %d, Ratio: %.2f images per 1000 chars", len(results.Images), ratio)
		check.Details = &details
	} else if ratio > 5.0 {
		check.Status = api.CheckStatusWarn
		check.Score = 0.2
		check.Severity = api.PtrTo(api.Low)
		check.Message = "Email has high image-to-text ratio"
		check.Advice = api.PtrTo("Consider adding more text content relative to images")
		details := fmt.Sprintf("Images: %d, Ratio: %.2f images per 1000 chars", len(results.Images), ratio)
		check.Details = &details
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 0.3
		check.Severity = api.PtrTo(api.Info)
		check.Message = "Image-to-text ratio is reasonable"
		check.Advice = api.PtrTo("Your content has a good balance of images and text")
		details := fmt.Sprintf("Images: %d, Ratio: %.2f images per 1000 chars", len(results.Images), ratio)
		check.Details = &details
	}

	return check
}

// generateSuspiciousURLCheck creates a check for suspicious URLs
func (c *ContentAnalyzer) generateSuspiciousURLCheck(results *ContentResults) api.Check {
	check := api.Check{
		Category: api.Content,
		Name:     "Suspicious URLs",
	}

	count := len(results.SuspiciousURLs)

	check.Status = api.CheckStatusWarn
	check.Score = 0.0
	check.Severity = api.PtrTo(api.Medium)
	check.Message = fmt.Sprintf("Found %d suspicious URL(s)", count)
	check.Advice = api.PtrTo("Avoid URL shorteners, IP addresses, and obfuscated URLs in emails")

	if count <= 3 {
		details := strings.Join(results.SuspiciousURLs, ", ")
		check.Details = &details
	} else {
		details := fmt.Sprintf("%s, and %d more", strings.Join(results.SuspiciousURLs[:3], ", "), count-3)
		check.Details = &details
	}

	return check
}

// GetContentScore calculates the content score (0-2 points)
func (c *ContentAnalyzer) GetContentScore(results *ContentResults) float32 {
	if results == nil {
		return 0.0
	}

	var score float32 = 0.0

	// HTML validity (0.2 points)
	if results.HTMLValid {
		score += 0.2
	}

	// Links (0.4 points)
	if len(results.Links) > 0 {
		brokenLinks := 0
		for _, link := range results.Links {
			if link.Status >= 400 {
				brokenLinks++
			}
		}
		if brokenLinks == 0 {
			score += 0.4
		}
	} else {
		// No links is neutral, give partial score
		score += 0.2
	}

	// Images (0.3 points)
	if len(results.Images) > 0 {
		noAltCount := 0
		for _, img := range results.Images {
			if !img.HasAlt {
				noAltCount++
			}
		}
		if noAltCount == 0 {
			score += 0.3
		} else if noAltCount < len(results.Images) {
			score += 0.15
		}
	} else {
		// No images is neutral
		score += 0.15
	}

	// Unsubscribe link (0.3 points)
	if results.HasUnsubscribe {
		score += 0.3
	}

	// Text consistency (0.3 points)
	if results.TextPlainRatio >= 0.3 {
		score += 0.3
	}

	// Image ratio (0.3 points)
	if results.ImageTextRatio <= 5.0 {
		score += 0.3
	} else if results.ImageTextRatio <= 10.0 {
		score += 0.15
	}

	// Penalize suspicious URLs (deduct up to 0.5 points)
	if len(results.SuspiciousURLs) > 0 {
		penalty := float32(len(results.SuspiciousURLs)) * 0.1
		if penalty > 0.5 {
			penalty = 0.5
		}
		score -= penalty
	}

	// Ensure score is between 0 and 2
	if score < 0 {
		score = 0
	}
	if score > 2.0 {
		score = 2.0
	}

	return score
}
