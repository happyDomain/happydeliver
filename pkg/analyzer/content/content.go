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
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/domainname"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/urlprobe"
)

// Analyzer analyzes email content (HTML, links, images)
type Analyzer struct {
	Timeout time.Duration

	// prober fetches the URLs the message carries and says what came back.
	// What that is worth is read here, from the findings the checks build on
	// top of it.
	prober *urlprobe.Prober

	// SkipProbes leaves every URL unfetched. It exists for the tests that must
	// produce the same report twice, whose fixtures point at domains nobody
	// controls; nothing else sets it.
	SkipProbes bool
}

// NewAnalyzer creates a new content analyzer with configurable timeout
func NewAnalyzer(timeout time.Duration) *Analyzer {
	if timeout == 0 {
		timeout = 10 * time.Second // Default timeout
	}
	return &Analyzer{Timeout: timeout, prober: urlprobe.New(timeout)}
}

// Results represents content analysis results
type Results struct {
	IsMultipart      bool
	HTMLValid        bool
	HTMLErrors       []string
	Links            []LinkCheck
	Images           []ImageCheck
	HasUnsubscribe   bool
	UnsubscribeLinks []string
	// UnsubscribeChecks reports what the URLs advertised in the
	// List-Unsubscribe header answered. They are kept apart from Links: they
	// are not part of the body, and they are probed under stricter rules.
	UnsubscribeChecks []LinkCheck
	// ListUnsubscribeURLs holds the URLs advertised in the List-Unsubscribe
	// header, and HasOneClickUnsubscribe whether the message also announces
	// RFC 8058 one-click. They describe this message, so they are read off it
	// once and carried here: the analyzer itself is shared by every analysis
	// running at the same time.
	ListUnsubscribeURLs    []string
	HasOneClickUnsubscribe bool
	TextContent            string
	HTMLContent            string
	// TextAlternative says how the plain text part stands to the HTML one:
	// saying the same thing, saying part of it, saying something else, or
	// standing in for it without carrying it. It is read once, when the
	// message is, so that the score and the report answer from one reading.
	TextAlternative textAltLevel
	ImageTextRatio  float32 // Ratio of images to text
	// UnprobedURLs counts the distinct URLs left unfetched because the message
	// carried more than one analysis may check.
	UnprobedURLs int

	// email is the message these results were read off, and htmlDocument the
	// tree its HTML part parsed into. The checks are handed both: a fact one of
	// them alone needs is read where it lies rather than added here, and the
	// document is parsed once for all of them.
	email        *mailmsg.Message
	htmlDocument *html.Node

	// Rspamd is what the spam filter of the receiving MTA said about this same
	// message, when it said anything. It is not produced here: the content
	// analysis borrows it so that the filter's observations about the content
	// reach the report as advice rather than as a table of symbols.
	//
	// It is attached before Read is asked anything, the checks reading it from
	// here like every other fact.
	Rspamd *model.RspamdResult

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
func (r *Results) HasPlaintext() bool {
	return r.TextContent != ""
}

// LinkCheck represents a link validation result
type LinkCheck struct {
	URL        string
	Valid      bool
	Error      string
	IsSafe     bool
	Warning    string
	IsTemplate bool // URL still contains an unreplaced templating placeholder (e.g. "{unsubscribe}")
	// InHTML and InText say which parts of the message wrote this destination.
	// One link is read once however many parts carry it, so the two are not
	// exclusive, and a link both parts write has both set. Keeping them is what
	// lets the parts be compared at all: the links themselves are gathered into
	// one list, and without this the second part to name a URL left no trace.
	InHTML bool
	InText bool
	// Suspicions lists the concrete reasons this URL was flagged, if any.
	// IsSafe is simply "no suspicion was found".
	Suspicions []URLSuspicion
	// probedURL reports what fetching the destination returned.
	probedURL
}

// ImageCheck represents an image validation result
type ImageCheck struct {
	Src      string
	HasAlt   bool
	AltText  string
	Valid    bool
	Error    string
	IsBroken bool
	// Suspicions lists the concrete reasons this image source was flagged.
	// Only the insecure-scheme check applies to an image: the other kinds
	// describe a destination a recipient may click, and an inline "data:"
	// image would be reported as an active scheme by all of them.
	Suspicions []URLSuspicion
	// probedURL reports what fetching the source returned, exactly as for a
	// link. An image is fetched the moment the message is opened, so a source
	// that does not answer is a hole in the rendering rather than a click that
	// fails.
	probedURL
}

// Analyze performs content analysis on email message
func (c *Analyzer) Analyze(email *mailmsg.Message) *Results {
	results := &Results{email: email, BodyTruncated: email.BodyIncomplete}

	results.IsMultipart = len(email.Parts) > 1

	// Parse List-Unsubscribe header URLs for use in link detection
	results.ListUnsubscribeURLs = email.GetListUnsubscribeURLs()

	// Check for one-click unsubscribe support
	listUnsubscribePost := email.Header.Get("List-Unsubscribe-Post")
	results.HasOneClickUnsubscribe = strings.EqualFold(strings.TrimSpace(listUnsubscribePost), "List-Unsubscribe=One-Click")

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

	// Everything above reads the message; this fetches what it points at, once
	// per distinct URL and several at a time.
	c.probeContentURLs(results)

	// Read the text part against the HTML one. The markup is compared as the
	// text it renders to, off the tree already parsed above rather than off a
	// second parse of its source.
	var htmlText string
	if results.htmlDocument != nil {
		htmlText = extractTextFromNode(results.htmlDocument)
	}
	results.TextAlternative = textAlternativeLevel(results.TextContent, htmlText, results.BodyTruncated)

	return results
}

// withoutSentencePunctuation takes off a URL written in prose the punctuation
// that ended the sentence rather than the address. "Voir https://example.com/x."
// carries a full stop no browser would follow, and keeping it would leave the
// plain text part naming a destination the HTML part does not.
//
// A closing bracket is only sentence punctuation when nothing opened it, since
// a URL may well carry a pair of its own.
func withoutSentencePunctuation(rawURL string) string {
	for {
		trimmed := strings.TrimRight(rawURL, ".,;:!?'\"")
		if last := len(trimmed) - 1; last >= 0 && trimmed[last] == ')' && !strings.Contains(trimmed, "(") {
			trimmed = trimmed[:last]
		}

		if trimmed == rawURL {
			return rawURL
		}
		rawURL = trimmed
	}
}

// textURLRegex matches the URLs a plain text part writes out: those naming
// their scheme, and those a reader recognises by the "www." their sender left
// the scheme off of. It stops at the characters no URL may carry unescaped, so
// that a link ends where the prose around it resumes.
var textURLRegex = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"{}|\\^\[\]` + "`" + `]+`)

// analyzeTextLinks extracts and validates URLs from plain text
func (c *Analyzer) analyzeTextLinks(textContent string, results *Results) {
	matches := textURLRegex.FindAllString(textContent, -1)

	for _, match := range matches {
		match = withoutSentencePunctuation(match)
		if match == "" {
			continue
		}

		// Normalize URL (add http:// if missing)
		urlStr := match
		schemeSynthesized := false
		if strings.HasPrefix(strings.ToLower(urlStr), "www.") {
			urlStr = "http://" + urlStr
			schemeSynthesized = true
		}

		// A URL the HTML already wrote is not read a second time, but it is
		// marked as written here too: that a destination appears in both parts
		// is exactly what comparing them needs to know, and skipping silently
		// used to lose it.
		exists := false
		for i, link := range results.Links {
			if link.URL == urlStr {
				results.Links[i].InText = true
				exists = true
				break
			}
		}

		if !exists {
			check := analyzeLinkOffline(urlStr)

			// The http: scheme of a bare "www.example.com" is ours, not the
			// sender's: reporting it as a plain-text link would be blaming
			// them for a choice they never wrote. That a text link carries no
			// scheme at all is a different matter, out of scope here.
			if schemeSynthesized {
				check.Suspicions = slices.DeleteFunc(check.Suspicions, func(s URLSuspicion) bool {
					return s.Kind == URLSuspicionInsecureScheme
				})
				check.IsSafe = len(check.Suspicions) == 0
			}

			check.InText = true
			results.Links = append(results.Links, check)
		}
	}
}

// analyzeHTML parses and analyzes HTML content
func (c *Analyzer) analyzeHTML(htmlContent string, results *Results) {
	results.HTMLContent = htmlContent

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		results.HTMLValid = false
		results.HTMLErrors = append(results.HTMLErrors, fmt.Sprintf("Failed to parse HTML: %v", err))
		return
	}

	results.HTMLValid = true
	results.htmlDocument = doc

	// Traverse HTML tree
	c.traverseHTML(doc, results)

	// Calculate image-to-text ratio
	if results.HTMLContent != "" {
		textLength := len(extractTextFromNode(doc))
		imageCount := len(results.Images)
		if textLength > 0 {
			results.ImageTextRatio = float32(imageCount) / float32(textLength) * 1000 // Images per 1000 chars
		}
	}
}

// traverseHTML recursively traverses HTML nodes
func (c *Analyzer) traverseHTML(n *html.Node, results *Results) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			// Extract and validate links
			// The spacing a template or a pretty-printer left around the
			// address is not part of it: kept, it passes every check that
			// trims before parsing and then fails the fetch itself.
			href := strings.TrimSpace(getAttrOf(n, "href"))
			if href != "" {
				// Check for unsubscribe links
				if c.isUnsubscribeLink(href, n, results.ListUnsubscribeURLs) {
					results.HasUnsubscribe = true
					results.UnsubscribeLinks = append(results.UnsubscribeLinks, href)
				}

				// Read the link. What it points at is fetched later, in one
				// pass over the whole message.
				linkCheck := analyzeLinkOffline(href)

				// Check for domain misalignment (phishing detection)
				linkText := strings.TrimSpace(c.getNodeText(n))
				if c.hasDomainMisalignment(href, linkText) {
					linkCheck.Suspicions = append(linkCheck.Suspicions, URLSuspicion{
						Kind:     URLSuspicionDomainMisalignment,
						Severity: model.IssueSeverityHigh,
						Message:  fmt.Sprintf("Link text advertises a domain that is not the destination: %q leads to %q", linkText, href),
						Advice:   "Make the visible text match the destination domain; filters score a mismatch as a phishing link",
					})
					linkCheck.IsSafe = false
				}

				linkCheck.InHTML = true
				results.Links = append(results.Links, linkCheck)
			}

		case "img":
			// Extract and validate images
			src := getAttrOf(n, "src")
			alt := getAttrOf(n, "alt")

			imageCheck := ImageCheck{
				Src:     src,
				HasAlt:  alt != "",
				AltText: alt,
				Valid:   src != "",
			}

			if suspicion := insecureSchemeSuspicion("Image", src); suspicion != nil {
				imageCheck.Suspicions = append(imageCheck.Suspicions, *suspicion)
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

// getAttrOf reads an attribute off a node, case-insensitively on the name.
//
// It is a function rather than a Analyzer method because the checks that
// read the tree afterwards have no analyzer: they are handed the document the
// analysis already parsed.
func getAttrOf(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}

	return ""
}

// isUnsubscribeLink checks if a link is an unsubscribe link
func (c *Analyzer) isUnsubscribeLink(href string, node *html.Node, listUnsubscribeURLs []string) bool {
	// An href with an unreplaced template placeholder (e.g. "{unsubscribe}") is not a
	// working link, so it must not count as a valid unsubscribe method even though it
	// literally contains the word "unsubscribe".
	if isTemplatePlaceholderURL(href) {
		return false
	}

	// First check: does the href match a URL from the List-Unsubscribe header?
	if slices.Contains(listUnsubscribeURLs, href) {
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
func (c *Analyzer) getNodeText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var text string
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		text += c.getNodeText(child)
	}
	return text
}

// analyzeLinkOffline reports everything a URL says about itself: an unreplaced
// merge field, the suspicions its text raises, and whether it parses at all.
// It touches no network, so it runs inside the HTML traversal, where fetching
// would serialize the whole analysis behind the slowest server.
func analyzeLinkOffline(urlStr string) LinkCheck {
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
	if _, err := url.Parse(urlStr); err != nil {
		check.Valid = false
		check.Error = fmt.Sprintf("Invalid URL: %v", err)
		return check
	}

	check.Valid = true

	return check
}

// hasDomainMisalignment checks if the link text contains a different domain than the actual URL
// This is a common phishing technique (e.g., text shows "bank.example.com" but links to "evil.example.net")
func (c *Analyzer) hasDomainMisalignment(href, linkText string) bool {
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
		actualDomain = domainname.HostOfURL(href)
		if actualDomain == "" {
			return false
		}
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
	actualRegistrable := domainname.Organizational(actualDomain)

	// Check each domain-like pattern found in the text
	for _, textDomain := range textDomains {
		if domainname.Organizational(textDomain) != actualRegistrable {
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
//
// A label is read in any script, not in ASCII alone: a domain shown in Unicode
// is a domain the reader is being sent to, and the one form in which a
// look-alike host is worth writing. Combining marks count inside a label so
// that an accented name decomposed by the client ("cafe" + U+0301) reads as
// the one label it is, and the delimiter excludes them all for the same
// reason: the token must still be glued to nothing.
var textDomainRegex = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}\p{M}_.\-])((?:https?://)?(?:www\.)?)((?:[\p{L}\p{N}](?:[-\p{L}\p{N}\p{M}]*[\p{L}\p{N}\p{M}])?\.)+\p{L}[\p{L}\p{N}\p{M}\-]*)`)

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
//
// Domains come back in their ASCII form, so that a text naming a host in
// Unicode and an href naming it in punycode are read as advertising the same
// destination, which they do.
func advertisedDomains(linkText string) []string {
	matches := textDomainRegex.FindAllStringSubmatch(linkText, -1)
	domains := make([]string, 0, len(matches))

	for _, match := range matches {
		// A scheme or "www." prefix announces a URL; only bare tokens can still
		// turn out to be prose, so they alone go through the heuristics below.
		bare := match[1] == ""

		if bare && isMissingSpace(match[2]) {
			continue
		}

		// In A-labels, the form the suffix list is written in and the form the
		// href will be compared in.
		domain := domainname.ASCII(match[2])

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

// extractTextFromNode reads the text of an already parsed tree, so that a
// caller holding the document does not parse its source a second time.
func extractTextFromNode(doc *html.Node) string {
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

// Analysis creates structured content analysis from results
func (c *Analyzer) Analysis(results *Results, read Reading) *model.ContentAnalysis {
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
	if len(results.Images) > 0 && results.htmlDocument != nil {
		textLen := float32(len(extractTextFromNode(results.htmlDocument)))
		if textLen > 0 {
			ratio := textLen / float32(len(results.Images))
			analysis.TextToImageRatio = &ratio
		}
	}

	// Every check of the registry reports here, in the order their findings
	// are read. What they cost is read by the score, from this same reading.
	htmlIssues := read.Issues

	if len(htmlIssues) > 0 {
		analysis.HtmlIssues = &htmlIssues
	}

	// Convert links
	if len(results.Links) > 0 {
		links := make([]model.LinkCheck, 0, len(results.Links))
		for _, link := range results.Links {
			var status model.LinkCheckStatus
			switch {
			case !link.Valid:
				// Link could not be parsed/validated (e.g. unreplaced template placeholder)
				status = model.LinkCheckStatusBroken
			case link.Status >= 400:
				status = model.LinkCheckStatusBroken
			case link.hasFinding(LinkHTTPRedirectLoop):
				// Redirections that never end leave the recipient with nothing,
				// exactly like a destination that does not exist.
				status = model.LinkCheckStatusBroken
			case !link.IsSafe:
				status = model.LinkCheckStatusSuspicious
			case link.Warning != "":
				status = model.LinkCheckStatusTimeout
			case len(link.RedirectChain) > excessiveRedirectHops:
				// One or two hops are how the ordinary web works (http: to
				// https:, apex to www, a click tracker). Calling those
				// "redirected" would put the label on half the legitimate
				// links and leave it meaning nothing.
				status = model.LinkCheckStatusRedirected
			default:
				status = model.LinkCheckStatusValid
			}

			apiLink := model.LinkCheck{
				Url:    link.URL,
				Status: status,
			}

			if link.Status > 0 {
				apiLink.HttpCode = utils.PtrTo(link.Status)
			}

			if len(link.RedirectChain) > 0 {
				apiLink.RedirectChain = utils.PtrTo(link.RedirectChain)
				// Where the chain ends is what the sender actually publishes,
				// and the one thing about a redirection worth reading first.
				apiLink.FinalUrl = utils.PtrTo(link.destination(link.URL))
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

			if img.Status > 0 {
				apiImg.HttpCode = utils.PtrTo(img.Status)
			}
			// An image is fetched on open, with no click involved: whether its
			// source answers is part of what the recipient will see.
			if urlprobe.Probeable(img.Src) {
				apiImg.IsBroken = utils.PtrTo(img.IsBroken)
			}

			images = append(images, apiImg)
		}
		analysis.Images = &images
	}

	// Unsubscribe methods
	if results.HasUnsubscribe {
		*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsLink)
	}

	for _, url := range results.ListUnsubscribeURLs {
		if strings.HasPrefix(url, "mailto:") {
			*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsMailto)
		} else if strings.HasPrefix(url, "http:") || strings.HasPrefix(url, "https:") {
			*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader)
		}
	}

	if slices.Contains(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader) && results.HasOneClickUnsubscribe {
		*analysis.UnsubscribeMethods = append(*analysis.UnsubscribeMethods, model.ContentAnalysisUnsubscribeMethodsOneClick)
	}

	return analysis
}
