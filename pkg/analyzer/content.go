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
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// ContentAnalyzer analyzes email content (HTML, links, images)
type ContentAnalyzer struct {
	Timeout                time.Duration
	httpClient             *http.Client
	listUnsubscribeURLs    []string // URLs from List-Unsubscribe header
	hasOneClickUnsubscribe bool     // True if List-Unsubscribe-Post: List-Unsubscribe=One-Click
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
	IsMultipart      bool
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
	ContentIssues    []string
	HarmfullIssues   []string

	// BodyTruncated reports that the MIME body stopped short of its end, so the
	// parts analysed above are only the ones that arrived. What is missing from
	// them says nothing about the message that was sent, hence the criteria it
	// would have decided are dropped rather than failed.
	BodyTruncated bool
}

// templatePlaceholderRegex matches unreplaced templating tokens that remain when a
// merge field was not substituted before sending. It covers the common syntaxes:
//   - single/double curly braces: {unsubscribe}, {{unsubscribe_url}}
//   - dollar braces: ${unsubscribe}
//   - Mailchimp merge tags: *|UNSUB|*
//   - percent tags: %unsubscribe%, %%unsubscribe%%
//   - square bracket tags: [unsubscribe]
//   - URL-encoded curly braces: %7Bunsubscribe%7D
//
// The percent-tag alternative requires a non-hex character in the body (to tell
// "%unsubscribe%" apart from percent-encoded octets like "%C3%A9") and requires
// the "%" delimiters to sit on a URL boundary (start, end, or "?&=/#;,"), so text
// sitting between two unrelated "%XX" octets in a doubly-encoded URL (e.g. a
// redirect link with an encoded URL as its query value) isn't mistaken for a tag.
var templatePlaceholderRegex = regexp.MustCompile(`(?i)\{\{?[^{}]*\}?\}|\$\{[^}]*\}|\*\|[^|]*\|\*|(?:^|[?&=/#;,])%{1,2}[\w.\-]*[g-z_.\-][\w.\-]*%{1,2}(?:$|[?&=/#;,])|\[[a-z][\w.\-]*\]|%7b[^%]*%7d`)

// isTemplatePlaceholderURL reports whether a URL still contains an unreplaced
// templating placeholder, meaning the merge field was never substituted.
func isTemplatePlaceholderURL(urlStr string) bool {
	return templatePlaceholderRegex.MatchString(urlStr)
}

// HasPlaintext returns true if the email has plain text content
func (r *ContentResults) HasPlaintext() bool {
	return r.TextContent != ""
}

// LinkCheck represents a link validation result
type LinkCheck struct {
	URL        string
	Valid      bool
	Status     int
	Error      string
	IsSafe     bool
	Warning    string
	IsTemplate bool // URL still contains an unreplaced templating placeholder (e.g. "{unsubscribe}")
	// Suspicions lists the concrete reasons this URL was flagged, if any.
	// IsSafe is simply "no suspicion was found".
	Suspicions []URLSuspicion
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
	results := &ContentResults{BodyTruncated: email.BodyIncomplete}

	results.IsMultipart = len(email.Parts) > 1

	// Parse List-Unsubscribe header URLs for use in link detection
	c.listUnsubscribeURLs = email.GetListUnsubscribeURLs()

	// Check for one-click unsubscribe support
	listUnsubscribePost := email.Header.Get("List-Unsubscribe-Post")
	c.hasOneClickUnsubscribe = strings.EqualFold(strings.TrimSpace(listUnsubscribePost), "List-Unsubscribe=One-Click")

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
		// Extract and validate links from plain text
		c.analyzeTextLinks(results.TextContent, results)
	}

	// Check plain text/HTML consistency. A truncated body may look single-part
	// while it is not: a perfect ratio would then score the parts that never
	// arrived rather than the message that was sent. It is left at zero, which
	// CalculateContentScore and GenerateContentAnalysis read as "unknown" rather
	// than as a failure, BodyTruncated telling the two apart.
	if !results.BodyTruncated {
		if len(htmlParts) > 0 && len(textParts) > 0 {
			results.TextPlainRatio = c.calculateTextPlainConsistency(results.TextContent, results.HTMLContent)
		} else if !results.IsMultipart {
			results.TextPlainRatio = 1.0
		}
	}

	return results
}

// analyzeTextLinks extracts and validates URLs from plain text
func (c *ContentAnalyzer) analyzeTextLinks(textContent string, results *ContentResults) {
	// Regular expression to match URLs in plain text
	// Matches http://, https://, and www. URLs
	urlRegex := regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"{}|\\^\[\]` + "`" + `]+`)

	matches := urlRegex.FindAllString(textContent, -1)

	for _, match := range matches {
		// Normalize URL (add http:// if missing)
		urlStr := match
		if strings.HasPrefix(strings.ToLower(urlStr), "www.") {
			urlStr = "http://" + urlStr
		}

		// Check if this URL already exists in results.Links (from HTML analysis)
		exists := false
		for _, link := range results.Links {
			if link.URL == urlStr {
				exists = true
				break
			}
		}

		// Only validate if not already checked
		if !exists {
			results.Links = append(results.Links, c.validateLink(urlStr))
		}
	}
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

				// Check for domain misalignment (phishing detection)
				linkText := strings.TrimSpace(c.getNodeText(n))
				if c.hasDomainMisalignment(href, linkText) {
					linkCheck.Suspicions = append(linkCheck.Suspicions, URLSuspicion{
						Kind:     URLSuspicionDomainMisalignment,
						Severity: model.ContentIssueSeverityHigh,
						Message:  fmt.Sprintf("Link text advertises a domain that is not the destination: %q leads to %q", linkText, href),
						Advice:   "Make the visible text match the destination domain: a mismatch is the defining pattern of a phishing link and is scored as such by filters",
					})
					linkCheck.IsSafe = false
				}

				results.Links = append(results.Links, linkCheck)
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

		case "script":
			// JavaScript in emails is a security risk and typically blocked
			results.HarmfullIssues = append(results.HarmfullIssues, "Dangerous <script> tag detected - JavaScript is blocked by most email clients")

		case "iframe":
			// Iframes are security risks and blocked by most email clients
			src := c.getAttr(n, "src")
			issue := "Dangerous <iframe> tag detected"
			if src != "" {
				issue += fmt.Sprintf(" with src='%s'", src)
			}
			results.HarmfullIssues = append(results.HarmfullIssues, issue+" - iframes are blocked by most email clients")

		case "object", "embed", "applet":
			// Legacy embedding tags, security risks
			results.HarmfullIssues = append(results.HarmfullIssues, fmt.Sprintf("Dangerous <%s> tag detected - legacy embedding tags are security risks and blocked by email clients", n.Data))

		case "form":
			// Forms in emails can be phishing vectors
			action := c.getAttr(n, "action")
			issue := "Suspicious <form> tag detected"
			if action != "" {
				issue += fmt.Sprintf(" with action='%s'", action)
			}
			results.HarmfullIssues = append(results.HarmfullIssues, issue+" - forms can be phishing vectors and are often blocked")

		case "base":
			// Base tag can be used for phishing by redirecting relative URLs
			href := c.getAttr(n, "href")
			issue := "Potentially dangerous <base> tag detected"
			if href != "" {
				issue += fmt.Sprintf(" with href='%s'", href)
			}
			results.HarmfullIssues = append(results.HarmfullIssues, issue+" - can redirect all relative URLs")

		case "meta":
			// Check for suspicious meta redirects
			httpEquiv := c.getAttr(n, "http-equiv")
			if strings.ToLower(httpEquiv) == "refresh" {
				content := c.getAttr(n, "content")
				results.HarmfullIssues = append(results.HarmfullIssues, fmt.Sprintf("Suspicious <meta http-equiv='refresh'> tag detected with content='%s' - can be used for phishing redirects", content))
			}

		case "link":
			// Check for external stylesheet links (potential privacy/tracking concerns)
			rel := c.getAttr(n, "rel")
			href := c.getAttr(n, "href")
			if strings.Contains(strings.ToLower(rel), "stylesheet") && href != "" {
				if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
					results.ContentIssues = append(results.ContentIssues, fmt.Sprintf("External stylesheet link detected: %s - may cause rendering issues or privacy concerns", href))
				}
			}
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
	// An href with an unreplaced template placeholder (e.g. "{unsubscribe}") is not a
	// working link, so it must not count as a valid unsubscribe method even though it
	// literally contains the word "unsubscribe".
	if isTemplatePlaceholderURL(href) {
		return false
	}

	// First check: does the href match a URL from the List-Unsubscribe header?
	if slices.Contains(c.listUnsubscribeURLs, href) {
		return true
	}

	// Check href for unsubscribe keywords
	lowerHref := strings.ToLower(href)
	unsubKeywords := []string{"unsubscribe", "opt-out", "optout", "remove", "list-unsubscribe", "отписване", "desubscripció", "zrušit odběr", "dad-danysgrifio", "afmeld", "abmelden", "διαγραφή", "darse de baja", "poistu postituslistalta", "se désabonner", "ביטול רישום", "leiratkozás", "cancella iscrizione", "登録を取り消す", "구독 해지", "വരിക്കാരനല്ലാതാകുക", "uitschrijven", "meld av", "odsubskrybuj", "cancelar assinatura", "cancelar subscrição", "dezabonare", "отписаться", "avsluta prenumeration", "zrušiť odber", "odjava", "üyeliği sonlandır", "відписатися", "hủy đăng ký", "退订", "退訂"}
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

	// Detect unreplaced templating placeholders (e.g. "{unsubscribe}"). Such a URL
	// is not a real link: the merge field was never substituted before sending.
	if isTemplatePlaceholderURL(urlStr) {
		check.Valid = false
		check.IsTemplate = true
		check.Error = "URL contains an unreplaced template placeholder (merge field was not substituted before sending)"
		return check
	}

	// Collect every concrete reason this URL is suspicious.
	check.Suspicions = analyzeURLSuspicions(urlStr)
	check.IsSafe = len(check.Suspicions) == 0

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		check.Valid = false
		check.Error = fmt.Sprintf("Invalid URL: %v", err)
		return check
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
	req.Header.Set("User-Agent", "happyDeliver/1.0 (Email Deliverability Tester)")

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

// hasDomainMisalignment checks if the link text contains a different domain than the actual URL
// This is a common phishing technique (e.g., text shows "bank.example.com" but links to "evil.example.net")
func (c *ContentAnalyzer) hasDomainMisalignment(href, linkText string) bool {
	// Parse the actual URL
	parsedURL, err := url.Parse(href)
	if err != nil {
		return false
	}

	// Extract the actual destination domain/email based on scheme
	var actualDomain string

	switch parsedURL.Scheme {
	case "mailto":
		// Extract email address from mailto: URL
		// Format can be: mailto:user@example.com or mailto:user@example.com?subject=...
		mailtoAddr := parsedURL.Opaque

		// Remove query parameters if present
		if idx := strings.Index(mailtoAddr, "?"); idx != -1 {
			mailtoAddr = mailtoAddr[:idx]
		}

		mailtoAddr = strings.TrimSpace(strings.ToLower(mailtoAddr))

		// Extract domain from email address
		if idx := strings.Index(mailtoAddr, "@"); idx != -1 {
			actualDomain = mailtoAddr[idx+1:]
		} else {
			return false // Invalid mailto
		}
	case "http", "https":
		// Check if URL has a host
		if parsedURL.Host == "" {
			return false
		}

		// Hostname() drops the port and the brackets of an IPv6 literal, which
		// a manual cut at the last colon would slice in half.
		actualDomain = normalizeHostname(parsedURL.Hostname())
	default:
		// Skip checks for other URL schemes (tel, etc.)
		return false
	}

	// Capitalisation is kept: isMissingSpace needs it to tell a domain apart
	// from a full stop with no space after it ("maintenant.Il").
	linkText = strings.TrimSpace(linkText)

	// Skip if link text is empty, too short, or just generic text like "click here"
	if linkText == "" || len(linkText) < 4 {
		return false
	}

	if slices.Contains(genericLinkTexts, strings.ToLower(linkText)) {
		return false
	}

	// Replace email addresses with just their domain part to avoid false positives
	// e.g. "john.doe@example.com" → "example.com" so local-part dots don't look like domains
	linkText = emailAddrRegex.ReplaceAllString(linkText, "$1")

	textDomains := advertisedDomains(linkText)
	if len(textDomains) == 0 {
		return false
	}

	// Compare on registrable domains ("example.co.uk", not "co.uk"), so that any
	// subdomain of the advertised domain is accepted.
	actualRegistrable := getOrganizationalDomain(actualDomain)

	// Check each domain-like pattern found in the text
	for _, textDomain := range textDomains {
		if getOrganizationalDomain(textDomain) != actualRegistrable {
			return true // Domain mismatch detected!
		}
	}

	return false
}

// genericLinkTexts describe the action rather than the destination, and so
// never advertise a domain to compare the href against.
var genericLinkTexts = []string{
	"click here", "read more", "learn more", "download", "subscribe",
	"unsubscribe", "view online", "view in browser", "click", "here",
	"update", "verify", "confirm", "continue", "get started",
	// mailto-specific generic texts
	"email us", "contact us", "send email", "get in touch", "reach out",
	"contact", "email", "write to us",
}

// textDomainRegex matches a domain-like token inside a link text, preceded by a
// delimiter so a token glued to a longer word is not extracted. Group 1 is the
// scheme or "www." prefix, if any; group 2 the token itself.
var textDomainRegex = regexp.MustCompile(`(?i)(?:^|[^\w.\-])((?:https?://)?(?:www\.)?)((?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\.)+[a-z][a-z0-9\-]*)`)

// emailAddrRegex matches an email address; the captured group is its domain,
// which replaces the whole address so the local part's dots are not read as one.
var emailAddrRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})`)

// fileExtensionLabels are valid TLDs that, mid-sentence, far more likely end a
// file name ("report.zip") than name a domain.
var fileExtensionLabels = []string{"zip", "mov", "md", "sh", "ai", "ps", "pl", "py", "rs", "so", "cc"}

// advertisedDomains extracts, from the visible text of a link, the domains that
// text claims to lead to. A token only counts as a domain when it sits under a
// suffix the public suffix list knows: this is what tells "example.com" apart
// from a file name ("facture.pdf") or a missing space after a full stop
// ("maintenant.Livraison").
func advertisedDomains(linkText string) []string {
	matches := textDomainRegex.FindAllStringSubmatch(linkText, -1)
	domains := make([]string, 0, len(matches))

	for _, match := range matches {
		// A scheme or "www." prefix announces a URL; only bare tokens can still
		// turn out to be prose, so they alone go through the heuristics below.
		bare := match[1] == ""
		domain := strings.ToLower(match[2])

		if bare && isMissingSpace(match[2]) {
			continue
		}

		// A multi-label suffix ("github.io", "s3.amazonaws.com") comes from the
		// list's private section, which no prose lands on: accept it even
		// though PublicSuffix reports it as not ICANN-managed.
		suffix, icann := publicsuffix.PublicSuffix(domain)
		if !icann && !strings.Contains(suffix, ".") {
			continue
		}
		if bare && slices.Contains(fileExtensionLabels, suffix) {
			continue
		}

		domains = append(domains, domain)
	}

	return domains
}

// isMissingSpace reports whether a domain-like token is in fact two sentences
// glued together by a full stop with no space after it ("maintenant.Il"): the
// label after the dot starts with a capital while the one before it does not.
// Only meaningful on a bare token.
func isMissingSpace(token string) bool {
	labels := strings.Split(token, ".")
	if len(labels) < 2 {
		return false
	}

	previous, _ := utf8.DecodeRuneInString(labels[len(labels)-2])
	last, _ := utf8.DecodeRuneInString(labels[len(labels)-1])

	return unicode.IsUpper(last) && !unicode.IsUpper(previous)
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
			text.WriteString(" " + n.Data)
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

	return strings.TrimSpace(text.String())
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

	// Count common words by building sets
	plainWordSet := make(map[string]int)
	for _, word := range plainWords {
		plainWordSet[word]++
	}

	htmlWordSet := make(map[string]int)
	for _, word := range htmlWords {
		htmlWordSet[word]++
	}

	// Count matches: for each unique word, count minimum occurrences in both texts
	commonWords := 0
	for word, plainCount := range plainWordSet {
		if htmlCount, exists := htmlWordSet[word]; exists {
			// Count the minimum occurrences between both texts
			if plainCount < htmlCount {
				commonWords += plainCount
			} else {
				commonWords += htmlCount
			}
		}
	}

	// Calculate ratio using total words from both texts (union approach)
	// This provides a balanced measure: perfect match = 1.0, partial overlap = 0.3-0.8
	totalWords := len(plainWords) + len(htmlWords)
	if totalWords == 0 {
		return 0.0
	}

	// Divide by average word count for better scoring
	avgWords := float32(totalWords) / 2.0
	ratio := float32(commonWords) / avgWords

	// Cap at 1.0 for perfect matches
	if ratio > 1.0 {
		ratio = 1.0
	}

	return ratio
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
func (c *ContentAnalyzer) GenerateContentAnalysis(results *ContentResults) *model.ContentAnalysis {
	if results == nil {
		return nil
	}

	analysis := &model.ContentAnalysis{
		HasHtml:            utils.PtrTo(results.HTMLContent != ""),
		HasPlaintext:       utils.PtrTo(results.TextContent != ""),
		HasUnsubscribeLink: utils.PtrTo(results.HasUnsubscribe),
		UnsubscribeMethods: &[]model.ContentAnalysisUnsubscribeMethods{},
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
	htmlIssues := []model.ContentIssue{}

	// Report a truncated body first: it qualifies everything the analysis below
	// says about the content, which only ever saw the parts that arrived.
	if results.BodyTruncated {
		htmlIssues = append(htmlIssues, model.ContentIssue{
			Type:     model.ContentIssueTypeTruncatedBody,
			Severity: model.ContentIssueSeverityMedium,
			Message:  "The message body stops before its end: it was cut short in transit, or its MIME structure announces a part that never follows. Only the parts that arrived were analysed.",
			Advice:   utils.PtrTo("Check the message size against the limits of the relays it goes through, and that the MIME boundaries it declares are all closed"),
		})
	}

	// Add HTML parsing errors
	if !results.HTMLValid && len(results.HTMLErrors) > 0 {
		for _, errMsg := range results.HTMLErrors {
			htmlIssues = append(htmlIssues, model.ContentIssue{
				Type:     model.ContentIssueTypeBrokenHtml,
				Severity: model.ContentIssueSeverityHigh,
				Message:  errMsg,
				Advice:   utils.PtrTo("Fix HTML structure errors to improve email rendering across clients"),
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
			htmlIssues = append(htmlIssues, model.ContentIssue{
				Type:     model.ContentIssueTypeMissingAlt,
				Severity: model.ContentIssueSeverityMedium,
				Message:  fmt.Sprintf("%d image(s) missing alt attributes", missingAltCount),
				Advice:   utils.PtrTo("Add descriptive alt text to all images for better accessibility and deliverability"),
			})
		}
	}

	// Add excessive images issue
	if results.ImageTextRatio > 10.0 {
		htmlIssues = append(htmlIssues, model.ContentIssue{
			Type:     model.ContentIssueTypeExcessiveImages,
			Severity: model.ContentIssueSeverityMedium,
			Message:  "Email is excessively image-heavy",
			Advice:   utils.PtrTo("Reduce the number of images relative to text content"),
		})
	}

	// Add unreplaced template placeholder issues
	for _, link := range results.Links {
		if !link.IsTemplate {
			continue
		}
		location := link.URL
		htmlIssues = append(htmlIssues, model.ContentIssue{
			Type:     model.ContentIssueTypeUnreplacedTemplate,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Link contains an unreplaced template placeholder: %s", link.URL),
			Location: &location,
			Advice:   utils.PtrTo("Ensure all merge fields and template placeholders are substituted before sending"),
		})
	}

	// Add suspicious URL issues
	for _, link := range results.Links {
		for _, suspicion := range link.Suspicions {
			htmlIssues = append(htmlIssues, model.ContentIssue{
				Type:     model.ContentIssueTypeSuspiciousLink,
				Severity: suspicion.Severity,
				Message:  suspicion.Message,
				Location: &link.URL,
				Advice:   utils.PtrTo(suspicion.Advice),
			})
		}
	}

	// Add harmful HTML tag issues
	for _, harmfulIssue := range results.HarmfullIssues {
		htmlIssues = append(htmlIssues, model.ContentIssue{
			Type:     model.ContentIssueTypeDangerousHtml,
			Severity: model.ContentIssueSeverityCritical,
			Message:  harmfulIssue,
			Advice:   utils.PtrTo("Remove dangerous HTML tags like <script>, <iframe>, <object>, <embed>, <applet>, <form>, and <base> from email content"),
		})
	}

	// Add general content issues (like external stylesheets)
	for _, contentIssue := range results.ContentIssues {
		htmlIssues = append(htmlIssues, model.ContentIssue{
			Type:     model.ContentIssueTypeBrokenHtml,
			Severity: model.ContentIssueSeverityLow,
			Message:  contentIssue,
			Advice:   utils.PtrTo("Use inline CSS instead of external stylesheets for better email compatibility"),
		})
	}

	if len(htmlIssues) > 0 {
		analysis.HtmlIssues = &htmlIssues
	}

	// Convert links
	if len(results.Links) > 0 {
		links := make([]model.LinkCheck, 0, len(results.Links))
		for _, link := range results.Links {
			status := model.LinkCheckStatusValid
			if !link.Valid {
				// Link could not be parsed/validated (e.g. unreplaced template placeholder)
				status = model.LinkCheckStatusBroken
			} else if link.Status >= 400 {
				status = model.LinkCheckStatusBroken
			} else if !link.IsSafe {
				status = model.LinkCheckStatusSuspicious
			} else if link.Warning != "" {
				status = model.LinkCheckStatusTimeout
			}

			apiLink := model.LinkCheck{
				Url:    link.URL,
				Status: status,
			}

			if link.Status > 0 {
				apiLink.HttpCode = utils.PtrTo(link.Status)
			}

			// Check if it's a URL shortener
			apiLink.IsShortened = utils.PtrTo(slices.ContainsFunc(link.Suspicions, func(s URLSuspicion) bool {
				return s.Kind == URLSuspicionShortener
			}))

			links = append(links, apiLink)
		}
		analysis.Links = &links
	}

	// Convert images
	if len(results.Images) > 0 {
		images := make([]model.ImageCheck, 0, len(results.Images))
		for _, img := range results.Images {
			apiImg := model.ImageCheck{
				HasAlt: img.HasAlt,
			}
			if img.Src != "" {
				apiImg.Src = &img.Src
			}
			if img.AltText != "" {
				apiImg.AltText = &img.AltText
			}
			// Simple heuristic: tracking pixels are typically 1x1
			apiImg.IsTrackingPixel = utils.PtrTo(false)

			images = append(images, apiImg)
		}
		analysis.Images = &images
	}

	// Unsubscribe methods
	if results.HasUnsubscribe {
		*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsLink)
	}

	for _, url := range c.listUnsubscribeURLs {
		if strings.HasPrefix(url, "mailto:") {
			*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsMailto)
		} else if strings.HasPrefix(url, "http:") || strings.HasPrefix(url, "https:") {
			*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader)
		}
	}

	if slices.Contains(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader) && c.hasOneClickUnsubscribe {
		*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsOneClick)
	}

	return analysis
}

// CalculateContentScore calculates the content score (0-20 points)
func (c *ContentAnalyzer) CalculateContentScore(results *ContentResults) (int, string) {
	if results == nil {
		return 0, ""
	}

	var score int = 10

	// The points a flawless message can reach. A criterion the received bytes
	// cannot answer is subtracted from it instead of being refused, so that a
	// body cut short on its way does not cost the sender a grade.
	attainable := 100

	// HTML validity or text alone (10 points)
	if results.HTMLValid || (!results.IsMultipart && results.HasPlaintext()) {
		score += 10
	}

	// Requires plain text alternative (10 points)
	if results.HasPlaintext() {
		score += 10
	}

	// Links (25 points)
	if len(results.Links) > 0 {
		brokenLinks := 0
		for _, link := range results.Links {
			if link.Status >= 400 {
				brokenLinks++
			}
		}
		score += 20 * (len(results.Links) - brokenLinks) / len(results.Links)
		// Too much links, 10 points penalty
		if len(results.Links) > 30 {
			score -= 10
		}
	} else if results.BodyTruncated {
		// A truncated body cannot be credited for links it does not appear to
		// have: that would reward an absence of evidence, not an absence of links.
		attainable -= 25
	} else {
		// No links is better, less suspiscous
		score += 25
	}

	// Images (15 points)
	if len(results.Images) > 0 {
		noAltCount := 0
		for _, img := range results.Images {
			if !img.HasAlt {
				noAltCount++
			}
		}
		score += 15 * (len(results.Images) - noAltCount) / len(results.Images)
	} else if results.BodyTruncated {
		// Same caveat as the links above: a truncated body earns no credit for
		// images it does not appear to have.
		attainable -= 15
	} else {
		// No images is Ok
		score += 15
	}

	// Text consistency (15 points). A truncated body cannot be judged on it: the
	// plain text counterpart of the HTML may simply never have arrived. Drop the
	// criterion rather than award or refuse its points.
	if results.BodyTruncated {
		attainable -= 15
	} else if results.TextPlainRatio >= 0.3 {
		score += 15
	}

	// Image ratio (15 points)
	if results.ImageTextRatio <= 5.0 {
		score += 15
	} else if results.ImageTextRatio <= 10.0 {
		score += 7
	}

	// Bring the criteria that could be judged back onto the 0-100 scale, before
	// the penalties below, which are expressed in points of that scale.
	if attainable != 100 {
		score = score * 100 / attainable
	}

	// Penalize suspicious links, weighted by how serious each finding is
	suspicionPenalty := 0
	for _, link := range results.Links {
		for _, suspicion := range link.Suspicions {
			switch suspicion.Severity {
			case model.ContentIssueSeverityCritical, model.ContentIssueSeverityHigh:
				suspicionPenalty += 3
			case model.ContentIssueSeverityMedium:
				suspicionPenalty += 2
			default:
				suspicionPenalty++
			}
		}
	}
	score -= min(suspicionPenalty, 10)

	// Penalize harmful HTML tags (deduct 20 points per harmful tag, max 40 points)
	if len(results.HarmfullIssues) > 0 {
		score -= min(len(results.HarmfullIssues)*20, 40)
	}

	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score, ScoreToGrade(score)
}
