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
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// HeaderAnalyzer analyzes email header quality and structure
type HeaderAnalyzer struct{}

// NewHeaderAnalyzer creates a new header analyzer
func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

// CalculateHeaderScore evaluates email structural quality from header analysis
func (h *HeaderAnalyzer) CalculateHeaderScore(analysis *api.HeaderAnalysis) int {
	if analysis == nil || analysis.Headers == nil {
		return 0
	}

	score := 0
	headers := *analysis.Headers

	// Check required headers (RFC 5322) - 40 points
	requiredHeaders := []string{"from", "date", "message-id"}
	requiredCount := len(requiredHeaders)
	presentRequired := 0

	for _, headerName := range requiredHeaders {
		if check, exists := headers[headerName]; exists && check.Present {
			presentRequired++
		}
	}

	if presentRequired == requiredCount {
		score += 40
	} else {
		score += int(40 * (float32(presentRequired) / float32(requiredCount)))
	}

	// Check recommended headers (30 points)
	recommendedHeaders := []string{"subject", "to", "reply-to"}
	recommendedCount := len(recommendedHeaders)
	presentRecommended := 0

	for _, headerName := range recommendedHeaders {
		if check, exists := headers[headerName]; exists && check.Present {
			presentRecommended++
		}
	}
	score += int(30 * (float32(presentRecommended) / float32(recommendedCount)))

	// Check for proper MIME structure (20 points)
	if analysis.HasMimeStructure != nil && *analysis.HasMimeStructure {
		score += 20
	}

	// Check Message-ID format (10 points)
	if check, exists := headers["message-id"]; exists && check.Present {
		// If Valid is set and true, award points
		if check.Valid != nil && *check.Valid {
			score += 10
		}
	}

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}

	return score
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
	recommendedHeaders := []string{"Reply-To", "Return-Path"}
	for _, headerName := range recommendedHeaders {
		check := h.checkHeader(email, headerName, "recommended")
		headers[strings.ToLower(headerName)] = *check
	}

	// Check optional headers
	optionalHeaders := []string{"List-Unsubscribe", "List-Unsubscribe-Post", "Precedence"}
	for _, headerName := range optionalHeaders {
		check := h.checkHeader(email, headerName, "optional")
		headers[strings.ToLower(headerName)] = *check
	}

	analysis.Headers = &headers

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
		Aligned: api.PtrTo(true),
	}

	// Extract From domain
	fromAddr := email.GetHeaderValue("From")
	if fromAddr != "" {
		domain := h.extractDomain(fromAddr)
		if domain != "" {
			alignment.FromDomain = &domain
		}
	}

	// Extract Return-Path domain
	returnPath := email.GetHeaderValue("Return-Path")
	if returnPath != "" {
		domain := h.extractDomain(returnPath)
		if domain != "" {
			alignment.ReturnPathDomain = &domain
		}
	}

	// Check alignment
	issues := []string{}
	if alignment.FromDomain != nil && alignment.ReturnPathDomain != nil {
		if *alignment.FromDomain != *alignment.ReturnPathDomain {
			*alignment.Aligned = false
			issues = append(issues, "Return-Path domain does not match From domain")
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
