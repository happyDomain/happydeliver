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

// calculateHeaderScore evaluates email structural quality
func (h *HeaderAnalyzer) calculateHeaderScore(email *EmailMessage) int {
	if email == nil {
		return 0
	}

	score := 0
	requiredHeaders := 0
	presentHeaders := 0

	// Check required headers (RFC 5322)
	headers := map[string]bool{
		"From":       false,
		"Date":       false,
		"Message-ID": false,
	}

	for header := range headers {
		requiredHeaders++
		if email.HasHeader(header) && email.GetHeaderValue(header) != "" {
			headers[header] = true
			presentHeaders++
		}
	}

	// Score based on required headers (40 points)
	if presentHeaders == requiredHeaders {
		score += 40
	} else {
		score += int(40 * (float32(presentHeaders) / float32(requiredHeaders)))
	}

	// Check recommended headers (30 points)
	recommendedHeaders := []string{"Subject", "To", "Reply-To"}
	recommendedPresent := 0
	for _, header := range recommendedHeaders {
		if email.HasHeader(header) && email.GetHeaderValue(header) != "" {
			recommendedPresent++
		}
	}
	score += int(30 * (float32(recommendedPresent) / float32(len(recommendedHeaders))))

	// Check for proper MIME structure (20 points)
	if len(email.Parts) > 0 {
		score += 20
	}

	// Check Message-ID format (10 point)
	if messageID := email.GetHeaderValue("Message-ID"); messageID != "" {
		if h.isValidMessageID(messageID) {
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

// GenerateHeaderChecks creates checks for email header quality
func (h *HeaderAnalyzer) GenerateHeaderChecks(email *EmailMessage) []api.Check {
	var checks []api.Check

	if email == nil {
		return checks
	}

	// Required headers check
	checks = append(checks, h.generateRequiredHeadersCheck(email))

	// Recommended headers check
	checks = append(checks, h.generateRecommendedHeadersCheck(email))

	// Message-ID check
	checks = append(checks, h.generateMessageIDCheck(email))

	// MIME structure check
	checks = append(checks, h.generateMIMEStructureCheck(email))

	return checks
}

// generateRequiredHeadersCheck checks for required RFC 5322 headers
func (h *HeaderAnalyzer) generateRequiredHeadersCheck(email *EmailMessage) api.Check {
	check := api.Check{
		Category: api.Headers,
		Name:     "Required Headers",
	}

	requiredHeaders := []string{"From", "Date", "Message-ID"}
	missing := []string{}

	for _, header := range requiredHeaders {
		if !email.HasHeader(header) || email.GetHeaderValue(header) == "" {
			missing = append(missing, header)
		}
	}

	if len(missing) == 0 {
		check.Status = api.CheckStatusPass
		check.Score = 4.0
		check.Grade = ScoreToCheckGrade((4.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = "All required headers are present"
		check.Advice = api.PtrTo("Your email has proper RFC 5322 headers")
	} else {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		check.Message = fmt.Sprintf("Missing required header(s): %s", strings.Join(missing, ", "))
		check.Advice = api.PtrTo("Add all required headers to ensure email deliverability")
		details := fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
		check.Details = &details
	}

	return check
}

// generateRecommendedHeadersCheck checks for recommended headers
func (h *HeaderAnalyzer) generateRecommendedHeadersCheck(email *EmailMessage) api.Check {
	check := api.Check{
		Category: api.Headers,
		Name:     "Recommended Headers",
	}

	recommendedHeaders := []string{"Subject", "To", "Reply-To"}
	missing := []string{}

	for _, header := range recommendedHeaders {
		if !email.HasHeader(header) || email.GetHeaderValue(header) == "" {
			missing = append(missing, header)
		}
	}

	if len(missing) == 0 {
		check.Status = api.CheckStatusPass
		check.Score = 30
		check.Grade = ScoreToCheckGrade((3.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = "All recommended headers are present"
		check.Advice = api.PtrTo("Your email includes all recommended headers")
	} else if len(missing) < len(recommendedHeaders) {
		check.Status = api.CheckStatusWarn
		check.Score = 15
		check.Grade = ScoreToCheckGrade((1.5 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Message = fmt.Sprintf("Missing some recommended header(s): %s", strings.Join(missing, ", "))
		check.Advice = api.PtrTo("Consider adding recommended headers for better deliverability")
		details := fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
		check.Details = &details
	} else {
		check.Status = api.CheckStatusWarn
		check.Score = 0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Message = "Missing all recommended headers"
		check.Advice = api.PtrTo("Add recommended headers (Subject, To, Reply-To) for better email presentation")
	}

	return check
}

// generateMessageIDCheck validates Message-ID header
func (h *HeaderAnalyzer) generateMessageIDCheck(email *EmailMessage) api.Check {
	check := api.Check{
		Category: api.Headers,
		Name:     "Message-ID Format",
	}

	messageID := email.GetHeaderValue("Message-ID")

	if messageID == "" {
		check.Status = api.CheckStatusFail
		check.Score = 0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Message = "Message-ID header is missing"
		check.Advice = api.PtrTo("Add a unique Message-ID header to your email")
	} else if !h.isValidMessageID(messageID) {
		check.Status = api.CheckStatusWarn
		check.Score = 5
		check.Grade = ScoreToCheckGrade((0.5 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Message = "Message-ID format is invalid"
		check.Advice = api.PtrTo("Use proper Message-ID format: <unique-id@domain.com>")
		check.Details = &messageID
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 10
		check.Grade = ScoreToCheckGrade((1.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = "Message-ID is properly formatted"
		check.Advice = api.PtrTo("Your Message-ID follows RFC 5322 standards")
		check.Details = &messageID
	}

	return check
}

// generateMIMEStructureCheck validates MIME structure
func (h *HeaderAnalyzer) generateMIMEStructureCheck(email *EmailMessage) api.Check {
	check := api.Check{
		Category: api.Headers,
		Name:     "MIME Structure",
	}

	if len(email.Parts) == 0 {
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Message = "No MIME parts detected"
		check.Advice = api.PtrTo("Consider using multipart MIME for better compatibility")
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 2.0
		check.Grade = ScoreToCheckGrade((2.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = fmt.Sprintf("Proper MIME structure with %d part(s)", len(email.Parts))
		check.Advice = api.PtrTo("Your email has proper MIME structure")

		// Add details about parts
		partTypes := []string{}
		for _, part := range email.Parts {
			if part.ContentType != "" {
				partTypes = append(partTypes, part.ContentType)
			}
		}
		if len(partTypes) > 0 {
			details := fmt.Sprintf("Parts: %s", strings.Join(partTypes, ", "))
			check.Details = &details
		}
	}

	return check
}
