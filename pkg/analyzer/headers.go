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
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"git.happydns.org/happyDeliver/internal/api"
)

// HeaderAnalyzer analyzes email header quality and structure
type HeaderAnalyzer struct{}

// NewHeaderAnalyzer creates a new header analyzer
func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

// CalculateHeaderScore evaluates email structural quality from header analysis
func (h *HeaderAnalyzer) CalculateHeaderScore(analysis *api.HeaderAnalysis) (int, rune) {
	if analysis == nil || analysis.Headers == nil {
		return 0, ' '
	}

	score := 0
	maxGrade := 6
	headers := *analysis.Headers

	// RP and From alignment (20 points)
	if analysis.DomainAlignment.Aligned != nil && *analysis.DomainAlignment.Aligned {
		score += 20
	} else if analysis.DomainAlignment.RelaxedAligned != nil && *analysis.DomainAlignment.RelaxedAligned {
		score += 15
	} else {
		maxGrade -= 2
	}

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

	// Check recommended headers (20 points)
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
	score += presentRecommended * 20 / recommendedCount

	if presentRecommended < recommendedCount {
		maxGrade -= 1
	}

	// Check for proper MIME structure (20 points)
	if analysis.HasMimeStructure != nil && *analysis.HasMimeStructure {
		score += 20
	} else {
		maxGrade -= 1
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

// isNoReplyAddress checks if a header check represents a no-reply email address
func (h *HeaderAnalyzer) isNoReplyAddress(headerCheck api.HeaderCheck) bool {
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

// GenerateHeaderAnalysis creates structured header analysis from email
func (h *HeaderAnalyzer) GenerateHeaderAnalysis(email *EmailMessage) *api.HeaderAnalysis {
	if email == nil {
		return nil
	}

	analysis := &api.HeaderAnalysis{}

	// Check for proper MIME structure
	analysis.HasMimeStructure = api.PtrTo(len(email.Parts) > 0)

	// Initialize headers map
	headers := make(map[string]api.HeaderCheck)

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
	domainAlignment := h.analyzeDomainAlignment(email)
	if domainAlignment != nil {
		analysis.DomainAlignment = domainAlignment
	}

	// Header issues
	issues := h.findHeaderIssues(email)
	if len(issues) > 0 {
		analysis.Issues = &issues
	}

	return analysis
}

// checkHeader checks if a header is present and valid
func (h *HeaderAnalyzer) checkHeader(email *EmailMessage, headerName string, importance string) *api.HeaderCheck {
	value := email.GetHeaderValue(headerName)
	present := email.HasHeader(headerName) && value != ""

	importanceEnum := api.HeaderCheckImportance(importance)
	check := &api.HeaderCheck{
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
		case "Date":
			// Could add date validation here
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

// analyzeDomainAlignment checks domain alignment between headers
func (h *HeaderAnalyzer) analyzeDomainAlignment(email *EmailMessage) *api.DomainAlignment {
	alignment := &api.DomainAlignment{
		Aligned:        api.PtrTo(true),
		RelaxedAligned: api.PtrTo(true),
	}

	// Extract From domain
	fromAddr := email.GetHeaderValue("From")
	if fromAddr != "" {
		domain := h.extractDomain(fromAddr)
		if domain != "" {
			alignment.FromDomain = &domain
			// Extract organizational domain
			orgDomain := h.getOrganizationalDomain(domain)
			alignment.FromOrgDomain = &orgDomain
		}
	}

	// Extract Return-Path domain
	returnPath := email.GetHeaderValue("Return-Path")
	if returnPath != "" {
		domain := h.extractDomain(returnPath)
		if domain != "" {
			alignment.ReturnPathDomain = &domain
			// Extract organizational domain
			orgDomain := h.getOrganizationalDomain(domain)
			alignment.ReturnPathOrgDomain = &orgDomain
		}
	}

	// Check alignment (strict and relaxed)
	issues := []string{}
	if alignment.FromDomain != nil && alignment.ReturnPathDomain != nil {
		fromDomain := *alignment.FromDomain
		rpDomain := *alignment.ReturnPathDomain

		// Strict alignment: exact match (case-insensitive)
		strictAligned := strings.EqualFold(fromDomain, rpDomain)

		// Relaxed alignment: organizational domain match
		var fromOrgDomain, rpOrgDomain string
		if alignment.FromOrgDomain != nil {
			fromOrgDomain = *alignment.FromOrgDomain
		}
		if alignment.ReturnPathOrgDomain != nil {
			rpOrgDomain = *alignment.ReturnPathOrgDomain
		}
		relaxedAligned := strings.EqualFold(fromOrgDomain, rpOrgDomain)

		*alignment.Aligned = strictAligned
		*alignment.RelaxedAligned = relaxedAligned

		if !strictAligned {
			if relaxedAligned {
				issues = append(issues, fmt.Sprintf("Return-Path domain (%s) does not exactly match From domain (%s), but satisfies relaxed alignment (organizational domain: %s)", rpDomain, fromDomain, fromOrgDomain))
			} else {
				issues = append(issues, fmt.Sprintf("Return-Path domain (%s) does not match From domain (%s) - neither strict nor relaxed alignment", rpDomain, fromDomain))
			}
		}
	}

	if len(issues) > 0 {
		alignment.Issues = &issues
	}

	return alignment
}

// extractDomain extracts domain from email address
func (h *HeaderAnalyzer) extractDomain(emailAddr string) string {
	// Remove angle brackets if present
	emailAddr = strings.Trim(emailAddr, "<> ")

	// Find @ symbol
	atIndex := strings.LastIndex(emailAddr, "@")
	if atIndex == -1 {
		return ""
	}

	domain := emailAddr[atIndex+1:]
	// Remove any trailing >
	domain = strings.TrimRight(domain, ">")

	return domain
}

// getOrganizationalDomain extracts the organizational domain from a fully qualified domain name
// using the Public Suffix List (PSL) to correctly handle multi-level TLDs.
// For example: mail.example.com -> example.com, mail.example.co.uk -> example.co.uk
func (h *HeaderAnalyzer) getOrganizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Use golang.org/x/net/publicsuffix to get the eTLD+1 (organizational domain)
	// This correctly handles cases like .co.uk, .com.au, etc.
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to simple two-label extraction if PSL lookup fails
		labels := strings.Split(domain, ".")
		if len(labels) <= 2 {
			return domain
		}
		return strings.Join(labels[len(labels)-2:], ".")
	}

	return etldPlusOne
}

// findHeaderIssues identifies issues with headers
func (h *HeaderAnalyzer) findHeaderIssues(email *EmailMessage) []api.HeaderIssue {
	var issues []api.HeaderIssue

	// Check for missing required headers
	requiredHeaders := []string{"From", "Date", "Message-ID"}
	for _, header := range requiredHeaders {
		if !email.HasHeader(header) || email.GetHeaderValue(header) == "" {
			issues = append(issues, api.HeaderIssue{
				Header:   header,
				Severity: api.HeaderIssueSeverityCritical,
				Message:  fmt.Sprintf("Required header '%s' is missing", header),
				Advice:   api.PtrTo(fmt.Sprintf("Add the %s header to ensure RFC 5322 compliance", header)),
			})
		}
	}

	// Check Message-ID format
	messageID := email.GetHeaderValue("Message-ID")
	if messageID != "" && !h.isValidMessageID(messageID) {
		issues = append(issues, api.HeaderIssue{
			Header:   "Message-ID",
			Severity: api.HeaderIssueSeverityMedium,
			Message:  "Message-ID format is invalid",
			Advice:   api.PtrTo("Use proper Message-ID format: <unique-id@domain.com>"),
		})
	}

	return issues
}

// parseReceivedChain extracts the chain of Received headers from an email
func (h *HeaderAnalyzer) parseReceivedChain(email *EmailMessage) []api.ReceivedHop {
	if email == nil || email.Header == nil {
		return nil
	}

	receivedHeaders := email.Header["Received"]
	if len(receivedHeaders) == 0 {
		return nil
	}

	var chain []api.ReceivedHop

	for _, receivedValue := range receivedHeaders {
		hop := h.parseReceivedHeader(receivedValue)
		if hop != nil {
			chain = append(chain, *hop)
		}
	}

	return chain
}

// parseReceivedHeader parses a single Received header value
func (h *HeaderAnalyzer) parseReceivedHeader(receivedValue string) *api.ReceivedHop {
	hop := &api.ReceivedHop{}

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

		// Remove timezone name in parentheses if present
		timestampStr = regexp.MustCompile(`\s*\([^)]+\)\s*$`).ReplaceAllString(timestampStr, "")

		// Try parsing with common email date formats
		formats := []string{
			time.RFC1123Z, // "Mon, 02 Jan 2006 15:04:05 -0700"
			time.RFC1123,  // "Mon, 02 Jan 2006 15:04:05 MST"
			"Mon, 2 Jan 2006 15:04:05 -0700",
			"Mon, 2 Jan 2006 15:04:05 MST",
			"2 Jan 2006 15:04:05 -0700",
		}

		for _, format := range formats {
			if parsedTime, err := time.Parse(format, timestampStr); err == nil {
				hop.Timestamp = &parsedTime
				break
			}
		}
	}

	return hop
}
