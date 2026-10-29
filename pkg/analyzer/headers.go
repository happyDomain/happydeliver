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
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/domainname"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// HeaderAnalyzer analyzes email header quality and structure
type HeaderAnalyzer struct{}

// NewHeaderAnalyzer creates a new header analyzer
func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

// CalculateHeaderScore evaluates email structural quality from header analysis
func (h *HeaderAnalyzer) CalculateHeaderScore(analysis *model.HeaderAnalysis) (int, rune) {
	if analysis == nil || analysis.Headers == nil {
		return 0, ' '
	}

	score := 0
	maxGrade := 6
	headers := *analysis.Headers

	// RP and From alignment (25 points)
	alignmentScore, alignmentIssues := calculateAlignmentScore(analysis.DomainAlignment)
	score += alignmentScore
	if alignmentScore == 0 {
		// Bad domain alignment, cap grade to C
		maxGrade -= 2
	}
	if analysis.Issues == nil {
		analysis.Issues = &model.HeaderIssues{}
	}
	analysis.Issues.DomainAlignment = issueList(alignmentIssues)

	// Check required headers (RFC 5322) - 30 points
	requiredHeaders := []string{"from", "date", "message-id"}
	requiredCount := len(requiredHeaders)
	presentRequired := 0

	for _, headerName := range requiredHeaders {
		if check, exists := headers[headerName]; exists && check.Present {
			presentRequired++
		}
	}

	if presentRequired == requiredCount {
		score += 30
	} else {
		score += int(30 * (float32(presentRequired) / float32(requiredCount)))
		maxGrade = 1
	}

	// Check recommended headers (15 points)
	recommendedHeaders := []string{"subject", "to"}

	// Add reply-to when from is a no-reply address
	if h.isNoReplyAddress(headers["from"]) {
		recommendedHeaders = append(recommendedHeaders, "reply-to")
	}

	recommendedCount := len(recommendedHeaders)
	presentRecommended := 0

	for _, headerName := range recommendedHeaders {
		if check, exists := headers[headerName]; exists && check.Present {
			presentRecommended++
		}
	}
	score += presentRecommended * 15 / recommendedCount

	if presentRecommended < recommendedCount {
		maxGrade -= 1
	}

	// Check for proper MIME structure (20 points)
	if analysis.HasMimeStructure != nil && *analysis.HasMimeStructure {
		score += 20
	} else {
		maxGrade -= 1
	}

	// Check MIME-Version header (-5 points if present but not "1.0")
	if check, exists := headers["mime-version"]; exists && check.Present {
		if check.Valid != nil && !*check.Valid {
			score -= 5
		}
	}

	// Check Message-ID format (10 points)
	if check, exists := headers["message-id"]; exists && check.Present {
		// If Valid is set and true, award points
		if check.Valid != nil && *check.Valid {
			score += 10
		} else {
			maxGrade -= 1
		}
	} else {
		maxGrade -= 1
	}

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}
	grade := 'A' + max(6-maxGrade, 0)

	return score, rune(grade)
}

// stripCFWS removes the comments and the whitespace RFC 2045 section 4 allows
// between the tokens of a structured field such as MIME-Version, where mailers
// commonly name themselves: "1.0 (Mac OS X Mail 16.0 \(3864.700.51.1.1\))".
// Comments nest, and a backslash quotes the character that follows it.
func stripCFWS(value string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case depth > 0 && c == '\\':
			i++
		case c == '(':
			depth++
		case depth > 0 && c == ')':
			depth--
		case depth == 0 && c != ' ' && c != '\t' && c != '\r' && c != '\n':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isValidMessageID checks if a Message-ID has proper format
func (h *HeaderAnalyzer) isValidMessageID(messageID string) bool {
	// Basic check: should be in format <...@...>
	if !strings.HasPrefix(messageID, "<") || !strings.HasSuffix(messageID, ">") {
		return false
	}

	// Remove angle brackets
	messageID = strings.TrimPrefix(messageID, "<")
	messageID = strings.TrimSuffix(messageID, ">")

	// Should contain @ symbol
	if !strings.Contains(messageID, "@") {
		return false
	}

	parts := strings.Split(messageID, "@")
	if len(parts) != 2 {
		return false
	}

	// Both parts should be non-empty
	return len(parts[0]) > 0 && len(parts[1]) > 0
}

// parseEmailDate attempts to parse an email date string using common email date formats
// Returns the parsed time and an error if parsing fails
func (h *HeaderAnalyzer) parseEmailDate(dateStr string) (time.Time, error) {
	// Remove timezone name in parentheses if present
	dateStr = regexp.MustCompile(`\s*\([^)]+\)\s*$`).ReplaceAllString(strings.TrimSpace(dateStr), "")

	// Try parsing with common email date formats
	formats := []string{
		time.RFC1123Z, // "Mon, 02 Jan 2006 15:04:05 -0700"
		time.RFC1123,  // "Mon, 02 Jan 2006 15:04:05 MST"
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 -0700",
	}

	for _, format := range formats {
		if parsedTime, err := time.Parse(format, dateStr); err == nil {
			return parsedTime, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date string: %s", dateStr)
}

// isNoReplyAddress checks if a header check represents a no-reply email address
func (h *HeaderAnalyzer) isNoReplyAddress(headerCheck model.HeaderCheck) bool {
	if !headerCheck.Present || headerCheck.Value == nil {
		return false
	}

	value := strings.ToLower(*headerCheck.Value)
	noReplyPatterns := []string{
		"no-reply",
		"noreply",
		"ne-pas-repondre",
		"nepasrepondre",
	}

	for _, pattern := range noReplyPatterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}

	return false
}

// validateAddressHeader validates email address header using net/mail parser
// and returns the normalized address string in "Name <email>" format
func (h *HeaderAnalyzer) validateAddressHeader(value string) (string, error) {
	// Try to parse as a single address first
	if addr, err := mail.ParseAddress(value); err == nil {
		return h.formatAddress(addr), nil
	}

	// If single address parsing fails, try parsing as an address list
	// (for headers like To, Cc that can contain multiple addresses)
	if addrs, err := mail.ParseAddressList(value); err != nil {
		return "", err
	} else {
		// Join multiple addresses with ", "
		result := ""
		for i, addr := range addrs {
			if i > 0 {
				result += ", "
			}
			result += h.formatAddress(addr)
		}
		return result, nil
	}
}

// formatAddress formats a mail.Address as "Name <email>" or just "email" if no name
func (h *HeaderAnalyzer) formatAddress(addr *mail.Address) string {
	if addr.Name != "" {
		return fmt.Sprintf("%s <%s>", addr.Name, addr.Address)
	}
	return addr.Address
}

// GenerateHeaderAnalysis creates structured header analysis from email
func (h *HeaderAnalyzer) GenerateHeaderAnalysis(email *mailmsg.Message, authResults *model.AuthenticationResults) *model.HeaderAnalysis {
	if email == nil {
		return nil
	}

	analysis := &model.HeaderAnalysis{}

	// Check for proper MIME structure
	analysis.HasMimeStructure = utils.PtrTo(len(email.Parts) > 0)

	// Initialize headers map
	headers := make(map[string]model.HeaderCheck)

	// Check required headers
	requiredHeaders := []string{"From", "To", "Date", "Message-ID", "Subject"}
	for _, headerName := range requiredHeaders {
		check := h.checkHeader(email, headerName, "required")
		headers[strings.ToLower(headerName)] = *check
	}

	// Check recommended headers
	recommendedHeaders := []string{}
	if h.isNoReplyAddress(headers["from"]) {
		recommendedHeaders = append(recommendedHeaders, "reply-to")
	}
	for _, headerName := range recommendedHeaders {
		check := h.checkHeader(email, headerName, "recommended")
		headers[strings.ToLower(headerName)] = *check
	}

	// Check MIME-Version header (recommended but absence is not penalized)
	mimeVersionCheck := h.checkHeader(email, "MIME-Version", "recommended")
	headers[strings.ToLower("MIME-Version")] = *mimeVersionCheck

	// Check optional headers
	optionalHeaders := []string{"List-Unsubscribe", "List-Unsubscribe-Post"}
	for _, headerName := range optionalHeaders {
		check := h.checkHeader(email, headerName, "newsletter")
		headers[strings.ToLower(headerName)] = *check
	}

	analysis.Headers = &headers

	// Received chain
	receivedChain := h.parseReceivedChain(email)
	if len(receivedChain) > 0 {
		analysis.ReceivedChain = &receivedChain
	}

	// Domain alignment
	domainAlignment := h.analyzeDomainAlignment(email, authResults)
	if domainAlignment != nil {
		analysis.DomainAlignment = domainAlignment
	}

	// Header issues
	analysis.Issues = &model.HeaderIssues{
		Headers: issueList(h.findHeaderIssues(email)),
	}

	return analysis
}

// checkHeader checks if a header is present and valid
func (h *HeaderAnalyzer) checkHeader(email *mailmsg.Message, headerName string, importance string) *model.HeaderCheck {
	value := email.GetHeaderValue(headerName)
	present := email.HasHeader(headerName) && value != ""

	importanceEnum := model.HeaderCheckImportance(importance)
	check := &model.HeaderCheck{
		Present:    present,
		Importance: &importanceEnum,
	}

	if present {
		check.Value = &value

		// Validate specific headers
		valid := true
		var headerIssues []string

		switch headerName {
		case "Message-ID":
			if !h.isValidMessageID(value) {
				valid = false
				headerIssues = append(headerIssues, "Invalid Message-ID format (should be <id@domain>)")
			}
			if len(email.Header["Message-Id"]) > 1 {
				valid = false
				headerIssues = append(headerIssues, fmt.Sprintf("Multiple Message-ID headers found (%d); only one is allowed", len(email.Header["Message-Id"])))
			}
		case "Date":
			// Validate date format
			if _, err := h.parseEmailDate(value); err != nil {
				valid = false
				headerIssues = append(headerIssues, fmt.Sprintf("Invalid date format: %v", err))
			}
		case "Subject":
			// Report the text a mail client would show rather than the raw
			// "=?UTF-8?B?...?=" encoded words.
			if email.Subject != "" {
				check.Value = &email.Subject
			}
		case "MIME-Version":
			if stripCFWS(value) != "1.0" {
				valid = false
				headerIssues = append(headerIssues, fmt.Sprintf("MIME-Version should be '1.0', got '%s'", value))
			}
		case "From", "To", "Cc", "Bcc", "Reply-To", "Sender", "Resent-From", "Resent-To", "Return-Path":
			// Parse address header using net/mail and get normalized address
			if normalizedAddr, err := h.validateAddressHeader(value); err != nil {
				valid = false
				headerIssues = append(headerIssues, fmt.Sprintf("Invalid email address format: %v", err))
			} else {
				// Use the normalized address as the value
				check.Value = &normalizedAddr
			}
		}

		check.Valid = &valid
		if len(headerIssues) > 0 {
			check.Issues = &headerIssues
		}
	} else {
		valid := false
		check.Valid = &valid
		if importance == "required" {
			issues := []string{"Required header is missing"}
			check.Issues = &issues
		}
	}

	return check
}

// analyzeDomainAlignment checks domain alignment between headers and DKIM signatures
func (h *HeaderAnalyzer) analyzeDomainAlignment(email *mailmsg.Message, authResults *model.AuthenticationResults) *model.DomainAlignment {
	alignment := &model.DomainAlignment{
		Aligned:        utils.PtrTo(true),
		RelaxedAligned: utils.PtrTo(true),
	}

	// Extract From domain
	fromAddr := email.GetHeaderValue("From")
	if fromAddr != "" {
		domain := mailmsg.AddressDomain(fromAddr)
		if domain != "" {
			alignment.FromDomain = &domain
			// Extract organizational domain
			orgDomain := domainname.Organizational(domain)
			alignment.FromOrgDomain = &orgDomain
		}
	}

	// Extract Return-Path domain
	returnPath := email.GetHeaderValue("Return-Path")
	if returnPath != "" {
		domain := mailmsg.AddressDomain(returnPath)
		if domain != "" {
			alignment.ReturnPathDomain = &domain
			// Extract organizational domain
			orgDomain := domainname.Organizational(domain)
			alignment.ReturnPathOrgDomain = &orgDomain
		}
	}

	// Extract DKIM domains from authentication results
	var dkimDomains []model.DKIMDomainInfo
	if authResults != nil && authResults.Dkim != nil {
		for _, dkim := range *authResults.Dkim {
			if dkim.Domain != nil && *dkim.Domain != "" {
				domain := *dkim.Domain
				orgDomain := domainname.Organizational(domain)
				dkimDomains = append(dkimDomains, model.DKIMDomainInfo{
					Domain:    domain,
					OrgDomain: orgDomain,
				})
			}
		}
	}
	if len(dkimDomains) > 0 {
		alignment.DkimDomains = &dkimDomains
	}

	// Check alignment (strict and relaxed)
	// hasReturnPath and hasDKIM track whether we have these fields to check
	hasReturnPath := alignment.FromDomain != nil && alignment.ReturnPathDomain != nil
	hasDKIM := alignment.FromDomain != nil && len(dkimDomains) > 0

	// If neither Return-Path nor DKIM is present, keep default alignment (true)
	// Otherwise, at least one must be aligned for overall alignment to be true
	strictAligned := !hasReturnPath && !hasDKIM
	relaxedAligned := !hasReturnPath && !hasDKIM

	// Check Return-Path alignment
	rpStrictAligned := false
	rpRelaxedAligned := false
	if hasReturnPath {
		fromDomain := *alignment.FromDomain
		rpDomain := *alignment.ReturnPathDomain

		// Strict alignment: exact match (case-insensitive)
		rpStrictAligned = strings.EqualFold(fromDomain, rpDomain)

		// Relaxed alignment: organizational domain match
		var fromOrgDomain, rpOrgDomain string
		if alignment.FromOrgDomain != nil {
			fromOrgDomain = *alignment.FromOrgDomain
		}
		if alignment.ReturnPathOrgDomain != nil {
			rpOrgDomain = *alignment.ReturnPathOrgDomain
		}
		rpRelaxedAligned = strings.EqualFold(fromOrgDomain, rpOrgDomain)

		strictAligned = rpStrictAligned
		relaxedAligned = rpRelaxedAligned
	}

	// Check DKIM alignment
	dkimStrictAligned := false
	dkimRelaxedAligned := false
	if hasDKIM {
		fromDomain := *alignment.FromDomain
		var fromOrgDomain string
		if alignment.FromOrgDomain != nil {
			fromOrgDomain = *alignment.FromOrgDomain
		}

		for _, dkimDomain := range dkimDomains {
			// Check strict alignment for this DKIM signature
			if strings.EqualFold(fromDomain, dkimDomain.Domain) {
				dkimStrictAligned = true
			}

			// Check relaxed alignment for this DKIM signature
			if strings.EqualFold(fromOrgDomain, dkimDomain.OrgDomain) {
				dkimRelaxedAligned = true
			}
		}

		// Overall alignment requires at least one method (Return-Path OR DKIM) to be aligned
		// For DMARC compliance, at least one of SPF or DKIM must be aligned
		if dkimStrictAligned {
			strictAligned = true
		}
		if dkimRelaxedAligned {
			relaxedAligned = true
		}
	}

	*alignment.Aligned = strictAligned
	*alignment.RelaxedAligned = relaxedAligned

	return alignment
}

// calculateAlignmentScore scores, out of 25 points of the header score,
// whether the domains authenticating the message align with the From domain,
// which DMARC needs of one of them at least. The issues say what each costs,
// along with a method that does not align while the other does, which costs
// nothing but leaves DMARC resting on one leg.
func calculateAlignmentScore(alignment *model.DomainAlignment) (int, []model.Issue) {
	c := checkScore{score: 25}

	if alignment == nil || alignment.Aligned == nil || alignment.RelaxedAligned == nil {
		c.cap(0, newIssue(model.IssueTypeDomainMisaligned, model.IssueSeverityHigh, "",
			"The domains authenticating the message could not be compared with the From domain, so DMARC alignment is unknown.",
			""))
		return c.score, c.issues
	}

	from := utils.Deref(alignment.FromDomain)
	fromOrg := utils.Deref(alignment.FromOrgDomain)
	rp := utils.Deref(alignment.ReturnPathDomain)
	var dkimDomains, dkimAligned []string
	if alignment.DkimDomains != nil {
		for _, d := range *alignment.DkimDomains {
			dkimDomains = append(dkimDomains, d.Domain)
			if strings.EqualFold(d.OrgDomain, fromOrg) {
				dkimAligned = append(dkimAligned, d.Domain)
			}
		}
	}
	rpAligned := rp != "" && strings.EqualFold(utils.Deref(alignment.ReturnPathOrgDomain), fromOrg)

	switch {
	case !*alignment.RelaxedAligned:
		var neither []string
		if rp != "" {
			neither = append(neither, fmt.Sprintf("the Return-Path domain (%s)", rp))
		}
		if len(dkimDomains) > 0 {
			neither = append(neither, fmt.Sprintf("the DKIM signing domains (%s)", strings.Join(dkimDomains, ", ")))
		}
		c.cap(0, newIssue(model.IssueTypeDomainMisaligned, model.IssueSeverityHigh, from,
			fmt.Sprintf("Neither %s shares the organizational domain of the From address (%s), so DMARC cannot pass.", strings.Join(neither, " nor "), from),
			"Have your email provider sign with DKIM for your own domain (a CNAME or TXT record they give you), or use a Return-Path on a subdomain of yours."))
		return c.score, c.issues

	case !*alignment.Aligned:
		c.cap(20, newIssue(model.IssueTypeDomainRelaxedAligned, model.IssueSeverityLow, from,
			fmt.Sprintf("No authenticating domain is exactly %s, only within its organizational domain (%s): a DMARC policy requiring strict alignment (aspf=s, adkim=s) would fail.", from, fromOrg),
			fmt.Sprintf("Sign with DKIM for %s itself, or use it as the Return-Path domain.", from)))
	}

	// One method aligns: the other does not have to, but DMARC then rests on it alone.
	if rp != "" && !rpAligned {
		c.note(newIssue(model.IssueTypeReturnPathMisaligned, model.IssueSeverityInfo, rp,
			fmt.Sprintf("The Return-Path domain (%s) does not share the organizational domain of %s: SPF does not count toward DMARC, which rests on DKIM alone.", rp, from),
			fmt.Sprintf("Use a Return-Path on a subdomain of %s; providers call it a custom bounce or MAIL FROM domain.", fromOrg)))
	}
	if len(dkimDomains) > 0 && len(dkimAligned) == 0 {
		c.note(newIssue(model.IssueTypeDkimMisaligned, model.IssueSeverityInfo, strings.Join(dkimDomains, ", "),
			fmt.Sprintf("No DKIM signature is made for %s or a domain sharing its organizational domain: DMARC rests on SPF alone, which breaks when the message is forwarded.", from),
			"Have your email provider sign with DKIM for your own domain (a CNAME or TXT record they give you)."))
	}

	return c.score, c.issues
}

// findHeaderIssues identifies issues with headers, each located at the
// header it is about. They are not charged one by one: the header score
// weighs what is present rather than what is wrong.
func (h *HeaderAnalyzer) findHeaderIssues(email *mailmsg.Message) []model.Issue {
	var issues []model.Issue

	// Check for missing required headers
	requiredHeaders := []string{"From", "Date", "Message-ID"}
	for _, header := range requiredHeaders {
		if !email.HasHeader(header) || email.GetHeaderValue(header) == "" {
			issues = append(issues, newIssue(model.IssueTypeMissingHeader, model.IssueSeverityCritical, header,
				fmt.Sprintf("Required header '%s' is missing", header),
				fmt.Sprintf("Add the %s header to ensure RFC 5322 compliance", header)))
		}
	}

	// Check Message-ID format
	messageID := email.GetHeaderValue("Message-ID")
	if messageID != "" && !h.isValidMessageID(messageID) {
		issues = append(issues, newIssue(model.IssueTypeInvalidMessageId, model.IssueSeverityMedium, "Message-ID",
			"Message-ID format is invalid",
			"Use proper Message-ID format: <unique-id@domain.com>"))
	}

	// Check for fake reply/forward: Subject has Re:/Fwd: prefix but no thread headers
	// email.Subject is the RFC 2047 decoded form: a "Re:" written inside an
	// encoded word is invisible in the raw header value.
	subject := email.Subject
	if subject == "" {
		subject = email.GetHeaderValue("Subject")
	}
	if h.hasReplyPrefix(subject) && !email.HasHeader("References") && !email.HasHeader("In-Reply-To") {
		issues = append(issues, newIssue(model.IssueTypeReplyWithoutReferences, model.IssueSeverityHigh, "Subject",
			"Subject indicates a reply or forward but no References or In-Reply-To header is present",
			"Remove the Re:/Fwd: prefix from the subject, or add References/In-Reply-To headers if this is a genuine reply"))
	}

	return issues
}

// hasReplyPrefix reports whether a subject line starts with a reply or forward prefix.
func (h *HeaderAnalyzer) hasReplyPrefix(subject string) bool {
	// Normalize: collapse leading whitespace and make comparison case-insensitive
	s := strings.ToLower(strings.TrimSpace(subject))

	prefixes := []string{
		"re:",   // English / universal
		"fwd:",  // English forward
		"fw:",   // English forward (short)
		"aw:",   // German Antwort
		"wg:",   // German Weitergeleitet
		"sv:",   // Scandinavian Svar
		"vs:",   // Finnish Vastaus / Norwegian
		"ref:",  // Some clients
		"rép:",  // French Réponse
		"tr:",   // French Transfert
		"odp:",  // Polish Odpowiedź
		"ynt:",  // Turkish Yanıt
		"res:",  // Portuguese/Spanish Resposta/Respuesta
		"enc:",  // Spanish Enviado/Reenviado
		"vl:",   // Dutch Verwijzing
		"antw:", // Dutch Antwoord
		"rv:",   // Norwegian/Swedish
	}

	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// parseReceivedChain extracts the chain of Received headers from an email
func (h *HeaderAnalyzer) parseReceivedChain(email *mailmsg.Message) []model.ReceivedHop {
	if email == nil || email.Header == nil {
		return nil
	}

	receivedHeaders := email.Header["Received"]
	if len(receivedHeaders) == 0 {
		return nil
	}

	var chain []model.ReceivedHop

	for _, receivedValue := range receivedHeaders {
		hop := h.parseReceivedHeader(receivedValue)
		if hop != nil {
			chain = append(chain, *hop)
		}
	}

	return chain
}

// parseReceivedHeader parses a single Received header value
func (h *HeaderAnalyzer) parseReceivedHeader(receivedValue string) *model.ReceivedHop {
	hop := &model.ReceivedHop{}

	// Normalize whitespace - Received headers can span multiple lines
	normalized := strings.Join(strings.Fields(receivedValue), " ")

	// Check if this is a "by-first" header (e.g., "by hostname (Postfix, from userid...)")
	// vs standard "from-first" header (e.g., "from hostname ... by hostname")
	isByFirst := regexp.MustCompile(`^by\s+`).MatchString(strings.TrimSpace(normalized))

	// Extract "from" field - only if not in "by-first" format
	// Avoid matching "from" inside parentheses after "by"
	if !isByFirst {
		fromRegex := regexp.MustCompile(`(?i)^from\s+([^\s(]+)`)
		if matches := fromRegex.FindStringSubmatch(normalized); len(matches) > 1 {
			from := matches[1]
			hop.From = &from
		}
	}

	// Extract "by" field
	byRegex := regexp.MustCompile(`(?i)by\s+([^\s(]+)`)
	if matches := byRegex.FindStringSubmatch(normalized); len(matches) > 1 {
		by := matches[1]
		hop.By = &by
	}

	// Extract "with" field (protocol) - must come after "by" and before "id" or "for"
	// This ensures we get the mail transfer protocol, not other "with" occurrences
	// Avoid matching "with" inside parentheses (like in TLS details)
	withRegex := regexp.MustCompile(`(?i)by\s+[^\s(]+[^;]*?\s+with\s+([A-Z0-9]+)(?:\s|;)`)
	if matches := withRegex.FindStringSubmatch(normalized); len(matches) > 1 {
		with := matches[1]
		hop.With = &with
	}

	// Extract "id" field - should come after "with" or "by", not inside parentheses
	// Match pattern: "id <value>" where value doesn't contain parentheses or semicolons
	idRegex := regexp.MustCompile(`(?i)\s+id\s+([^\s;()]+)`)
	if matches := idRegex.FindStringSubmatch(normalized); len(matches) > 1 {
		id := matches[1]
		hop.Id = &id
	}

	// Extract IP address from parentheses after "from"
	// Pattern: from hostname (anything [IPv4/IPv6])
	ipRegex := regexp.MustCompile(`\[([^\]]+)\]`)
	if matches := ipRegex.FindStringSubmatch(normalized); len(matches) > 1 {
		ipStr := matches[1]

		// Handle IPv6: prefix (some MTAs include this)
		ipStr = strings.TrimPrefix(ipStr, "IPv6:")

		// Check if it's a valid IP (IPv4 or IPv6)
		if net.ParseIP(ipStr) != nil {
			hop.Ip = &ipStr

			// Perform reverse DNS lookup
			if reverseNames, err := net.LookupAddr(ipStr); err == nil && len(reverseNames) > 0 {
				// Remove trailing dot from PTR record
				reverse := strings.TrimSuffix(reverseNames[0], ".")
				hop.Reverse = &reverse
			}
		}
	}

	// Extract timestamp - usually at the end after semicolon
	// Common formats: "for <...>; Tue, 15 Oct 2024 12:34:56 +0000 (UTC)"
	timestampRegex := regexp.MustCompile(`;\s*(.+)$`)
	if matches := timestampRegex.FindStringSubmatch(normalized); len(matches) > 1 {
		timestampStr := strings.TrimSpace(matches[1])

		// Use the dedicated date parsing function
		if parsedTime, err := h.parseEmailDate(timestampStr); err == nil {
			hop.Timestamp = &parsedTime
		}
	}

	// Extract TLS details from the Received header parentheticals
	// (e.g. "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) ...)")
	hop.Tls = parseReceivedTLS(normalized)

	return hop
}

// parseReceivedTLS extracts TLS connection details from a normalized Received header value.
// Returns nil when the hop was not encrypted (no TLS version/cipher found).
func parseReceivedTLS(normalized string) *model.TLSInfo {
	tls := &model.TLSInfo{}
	found := false

	// TLS protocol version, e.g. "using TLSv1.3"
	if matches := regexp.MustCompile(`(?i)using\s+(TLSv[0-9.]+|SSLv[0-9.]+)`).FindStringSubmatch(normalized); len(matches) > 1 {
		tls.Version = &matches[1]
		found = true
	}

	// Cipher suite, e.g. "with cipher TLS_AES_256_GCM_SHA384"
	if matches := regexp.MustCompile(`(?i)with cipher\s+([A-Za-z0-9_-]+)`).FindStringSubmatch(normalized); len(matches) > 1 {
		tls.Cipher = &matches[1]
		found = true
	}

	// Cipher strength, e.g. "(256/256 bits)"
	if matches := regexp.MustCompile(`\((\d+)/\d+ bits\)`).FindStringSubmatch(normalized); len(matches) > 1 {
		if bits, err := strconv.Atoi(matches[1]); err == nil {
			tls.Bits = &bits
		}
	}

	if !found {
		return nil
	}

	// Certificate verification status. Postfix emits "(verified OK)" when the peer
	// certificate was trusted, "(not verified)" otherwise. "No client certificate
	// requested" leaves the field unset (trust is simply not applicable).
	if regexp.MustCompile(`(?i)verified OK`).MatchString(normalized) {
		tls.Verified = utils.PtrTo(true)
	} else if regexp.MustCompile(`(?i)not verified`).MatchString(normalized) {
		tls.Verified = utils.PtrTo(false)
	}

	return tls
}
