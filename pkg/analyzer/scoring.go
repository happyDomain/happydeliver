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
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

// ScoreToGrade converts a percentage score (0-100) to a letter grade
func ScoreToGrade(score float32) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 85:
		return "B"
	case score >= 75:
		return "C"
	case score >= 65:
		return "D"
	case score >= 50:
		return "E"
	default:
		return "F"
	}
}

// ScoreToCheckGrade converts a percentage score to an api.CheckGrade
func ScoreToCheckGrade(score float32) api.CheckGrade {
	return api.CheckGrade(ScoreToGrade(score))
}

// ScoreToReportGrade converts a percentage score to an api.ReportGrade
func ScoreToReportGrade(score float32) api.ReportGrade {
	return api.ReportGrade(ScoreToGrade(score))
}

// DeliverabilityScorer aggregates all analysis results and computes overall score
type DeliverabilityScorer struct{}

// NewDeliverabilityScorer creates a new deliverability scorer
func NewDeliverabilityScorer() *DeliverabilityScorer {
	return &DeliverabilityScorer{}
}

// ScoringResult represents the complete scoring result
type ScoringResult struct {
	OverallScore      float32
	Rating            string // Excellent, Good, Fair, Poor, Critical
	AuthScore         float32
	SpamScore         float32
	BlacklistScore    float32
	ContentScore      float32
	HeaderScore       float32
	Recommendations   []string
	CategoryBreakdown map[string]CategoryScore
}

// CategoryScore represents score breakdown for a category
type CategoryScore struct {
	Score      float32
	MaxScore   float32
	Percentage float32
	Status     string // Pass, Warn, Fail
}

// CalculateScore computes the overall deliverability score from all analyzers
func (s *DeliverabilityScorer) CalculateScore(
	authResults *api.AuthenticationResults,
	spamResult *SpamAssassinResult,
	rblResults *RBLResults,
	contentResults *ContentResults,
	email *EmailMessage,
) *ScoringResult {
	result := &ScoringResult{
		CategoryBreakdown: make(map[string]CategoryScore),
		Recommendations:   []string{},
	}

	// Calculate individual scores
	result.AuthScore = s.GetAuthenticationScore(authResults)

	spamAnalyzer := NewSpamAssassinAnalyzer()
	result.SpamScore = spamAnalyzer.GetSpamAssassinScore(spamResult)

	rblChecker := NewRBLChecker(10*time.Second, DefaultRBLs)
	result.BlacklistScore = rblChecker.GetBlacklistScore(rblResults)

	contentAnalyzer := NewContentAnalyzer(10 * time.Second)
	result.ContentScore = contentAnalyzer.GetContentScore(contentResults)

	// Calculate header quality score
	result.HeaderScore = s.calculateHeaderScore(email)

	// Calculate overall score (out of 100)
	result.OverallScore = result.AuthScore + result.SpamScore + result.BlacklistScore + result.ContentScore + result.HeaderScore

	// Ensure score is within bounds
	if result.OverallScore > 100.0 {
		result.OverallScore = 100.0
	}
	if result.OverallScore < 0.0 {
		result.OverallScore = 0.0
	}

	// Determine rating
	result.Rating = s.determineRating(result.OverallScore)

	// Build category breakdown
	result.CategoryBreakdown["Authentication"] = CategoryScore{
		Score:      result.AuthScore,
		MaxScore:   30.0,
		Percentage: result.AuthScore,
		Status:     s.getCategoryStatus(result.AuthScore, 30.0),
	}

	result.CategoryBreakdown["Spam Filters"] = CategoryScore{
		Score:      result.SpamScore,
		MaxScore:   20.0,
		Percentage: result.SpamScore,
		Status:     s.getCategoryStatus(result.SpamScore, 20.0),
	}

	result.CategoryBreakdown["Blacklists"] = CategoryScore{
		Score:      result.BlacklistScore,
		MaxScore:   20.0,
		Percentage: result.BlacklistScore,
		Status:     s.getCategoryStatus(result.BlacklistScore, 20.0),
	}

	result.CategoryBreakdown["Content Quality"] = CategoryScore{
		Score:      result.ContentScore,
		MaxScore:   20.0,
		Percentage: result.ContentScore,
		Status:     s.getCategoryStatus(result.ContentScore, 20.0),
	}

	result.CategoryBreakdown["Email Structure"] = CategoryScore{
		Score:      result.HeaderScore,
		MaxScore:   10.0,
		Percentage: result.HeaderScore,
		Status:     s.getCategoryStatus(result.HeaderScore, 10.0),
	}

	// Generate recommendations
	result.Recommendations = s.generateRecommendations(result)

	return result
}

// calculateHeaderScore evaluates email structural quality (0-10 points)
func (s *DeliverabilityScorer) calculateHeaderScore(email *EmailMessage) float32 {
	if email == nil {
		return 0.0
	}

	score := float32(0.0)
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

	// Score based on required headers (4 points)
	if presentHeaders == requiredHeaders {
		score += 4.0
	} else {
		score += 4.0 * (float32(presentHeaders) / float32(requiredHeaders))
	}

	// Check recommended headers (3 points)
	recommendedHeaders := []string{"Subject", "To", "Reply-To"}
	recommendedPresent := 0
	for _, header := range recommendedHeaders {
		if email.HasHeader(header) && email.GetHeaderValue(header) != "" {
			recommendedPresent++
		}
	}
	score += 3.0 * (float32(recommendedPresent) / float32(len(recommendedHeaders)))

	// Check for proper MIME structure (2 points)
	if len(email.Parts) > 0 {
		score += 2.0
	}

	// Check Message-ID format (1 point)
	if messageID := email.GetHeaderValue("Message-ID"); messageID != "" {
		if s.isValidMessageID(messageID) {
			score += 1.0
		}
	}

	// Ensure score doesn't exceed 10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}

// isValidMessageID checks if a Message-ID has proper format
func (s *DeliverabilityScorer) isValidMessageID(messageID string) bool {
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

// determineRating determines the rating based on overall score (0-100)
func (s *DeliverabilityScorer) determineRating(score float32) string {
	switch {
	case score >= 90.0:
		return "Excellent"
	case score >= 70.0:
		return "Good"
	case score >= 50.0:
		return "Fair"
	case score >= 30.0:
		return "Poor"
	default:
		return "Critical"
	}
}

// getCategoryStatus determines status for a category
func (s *DeliverabilityScorer) getCategoryStatus(score, maxScore float32) string {
	percentage := (score / maxScore) * 100

	switch {
	case percentage >= 80.0:
		return "Pass"
	case percentage >= 50.0:
		return "Warn"
	default:
		return "Fail"
	}
}

// generateRecommendations creates actionable recommendations based on scores
func (s *DeliverabilityScorer) generateRecommendations(result *ScoringResult) []string {
	var recommendations []string

	// Authentication recommendations (0-30 points)
	if result.AuthScore < 20.0 {
		recommendations = append(recommendations, "🔐 Improve email authentication by configuring SPF, DKIM, and DMARC records")
	} else if result.AuthScore < 30.0 {
		recommendations = append(recommendations, "🔐 Fine-tune your email authentication setup for optimal deliverability")
	}

	// Spam recommendations (0-20 points)
	if result.SpamScore < 10.0 {
		recommendations = append(recommendations, "⚠️  Reduce spam triggers by reviewing email content and avoiding spam-like patterns")
	} else if result.SpamScore < 15.0 {
		recommendations = append(recommendations, "⚠️  Monitor spam score and address any flagged content issues")
	}

	// Blacklist recommendations (0-20 points)
	if result.BlacklistScore < 10.0 {
		recommendations = append(recommendations, "🚫 Your IP is listed on blacklists - take immediate action to delist and improve sender reputation")
	} else if result.BlacklistScore < 20.0 {
		recommendations = append(recommendations, "🚫 Monitor your IP reputation and ensure clean sending practices")
	}

	// Content recommendations (0-20 points)
	if result.ContentScore < 10.0 {
		recommendations = append(recommendations, "📝 Improve email content quality: fix broken links, add alt text to images, and ensure proper HTML structure")
	} else if result.ContentScore < 15.0 {
		recommendations = append(recommendations, "📝 Enhance email content by optimizing images and ensuring text/HTML consistency")
	}

	// Header recommendations (0-10 points)
	if result.HeaderScore < 5.0 {
		recommendations = append(recommendations, "📧 Fix email structure by adding required headers (From, Date, Message-ID)")
	} else if result.HeaderScore < 10.0 {
		recommendations = append(recommendations, "📧 Improve email headers by ensuring all recommended fields are present")
	}

	// Overall recommendations based on rating
	if result.Rating == "Excellent" {
		recommendations = append(recommendations, "✅ Your email has excellent deliverability - maintain current practices")
	} else if result.Rating == "Critical" {
		recommendations = append(recommendations, "🆘 Critical issues detected - emails will likely be rejected or marked as spam")
	}

	return recommendations
}

// GenerateHeaderChecks creates checks for email header quality
func (s *DeliverabilityScorer) GenerateHeaderChecks(email *EmailMessage) []api.Check {
	var checks []api.Check

	if email == nil {
		return checks
	}

	// Required headers check
	checks = append(checks, s.generateRequiredHeadersCheck(email))

	// Recommended headers check
	checks = append(checks, s.generateRecommendedHeadersCheck(email))

	// Message-ID check
	checks = append(checks, s.generateMessageIDCheck(email))

	// MIME structure check
	checks = append(checks, s.generateMIMEStructureCheck(email))

	return checks
}

// generateRequiredHeadersCheck checks for required RFC 5322 headers
func (s *DeliverabilityScorer) generateRequiredHeadersCheck(email *EmailMessage) api.Check {
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
func (s *DeliverabilityScorer) generateRecommendedHeadersCheck(email *EmailMessage) api.Check {
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
		check.Score = 3.0
		check.Grade = ScoreToCheckGrade((3.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = "All recommended headers are present"
		check.Advice = api.PtrTo("Your email includes all recommended headers")
	} else if len(missing) < len(recommendedHeaders) {
		check.Status = api.CheckStatusWarn
		check.Score = 1.5
		check.Grade = ScoreToCheckGrade((1.5 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Message = fmt.Sprintf("Missing some recommended header(s): %s", strings.Join(missing, ", "))
		check.Advice = api.PtrTo("Consider adding recommended headers for better deliverability")
		details := fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
		check.Details = &details
	} else {
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Message = "Missing all recommended headers"
		check.Advice = api.PtrTo("Add recommended headers (Subject, To, Reply-To) for better email presentation")
	}

	return check
}

// generateMessageIDCheck validates Message-ID header
func (s *DeliverabilityScorer) generateMessageIDCheck(email *EmailMessage) api.Check {
	check := api.Check{
		Category: api.Headers,
		Name:     "Message-ID Format",
	}

	messageID := email.GetHeaderValue("Message-ID")

	if messageID == "" {
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Grade = ScoreToCheckGrade(0.0)
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Message = "Message-ID header is missing"
		check.Advice = api.PtrTo("Add a unique Message-ID header to your email")
	} else if !s.isValidMessageID(messageID) {
		check.Status = api.CheckStatusWarn
		check.Score = 0.5
		check.Grade = ScoreToCheckGrade((0.5 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Message = "Message-ID format is invalid"
		check.Advice = api.PtrTo("Use proper Message-ID format: <unique-id@domain.com>")
		check.Details = &messageID
	} else {
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Grade = ScoreToCheckGrade((1.0 / 10.0) * 100)
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Message = "Message-ID is properly formatted"
		check.Advice = api.PtrTo("Your Message-ID follows RFC 5322 standards")
		check.Details = &messageID
	}

	return check
}

// generateMIMEStructureCheck validates MIME structure
func (s *DeliverabilityScorer) generateMIMEStructureCheck(email *EmailMessage) api.Check {
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

// GetScoreSummary generates a human-readable summary of the score
func (s *DeliverabilityScorer) GetScoreSummary(result *ScoringResult) string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("Overall Score: %.1f/100 (%s) - Grade: %s\n\n", result.OverallScore, result.Rating, ScoreToGrade(result.OverallScore)))
	summary.WriteString("Category Breakdown:\n")
	summary.WriteString(fmt.Sprintf("  • Authentication:    %.1f/30.0 (%.0f%%) - %s\n",
		result.AuthScore, result.CategoryBreakdown["Authentication"].Percentage, result.CategoryBreakdown["Authentication"].Status))
	summary.WriteString(fmt.Sprintf("  • Spam Filters:      %.1f/20.0 (%.0f%%) - %s\n",
		result.SpamScore, result.CategoryBreakdown["Spam Filters"].Percentage, result.CategoryBreakdown["Spam Filters"].Status))
	summary.WriteString(fmt.Sprintf("  • Blacklists:        %.1f/20.0 (%.0f%%) - %s\n",
		result.BlacklistScore, result.CategoryBreakdown["Blacklists"].Percentage, result.CategoryBreakdown["Blacklists"].Status))
	summary.WriteString(fmt.Sprintf("  • Content Quality:   %.1f/20.0 (%.0f%%) - %s\n",
		result.ContentScore, result.CategoryBreakdown["Content Quality"].Percentage, result.CategoryBreakdown["Content Quality"].Status))
	summary.WriteString(fmt.Sprintf("  • Email Structure:   %.1f/10.0 (%.0f%%) - %s\n",
		result.HeaderScore, result.CategoryBreakdown["Email Structure"].Percentage, result.CategoryBreakdown["Email Structure"].Status))

	if len(result.Recommendations) > 0 {
		summary.WriteString("\nRecommendations:\n")
		for _, rec := range result.Recommendations {
			summary.WriteString(fmt.Sprintf("  %s\n", rec))
		}
	}

	return summary.String()
}

// GetAuthenticationScore calculates the authentication score (0-30 points)
func (s *DeliverabilityScorer) GetAuthenticationScore(results *api.AuthenticationResults) float32 {
	var score float32 = 0.0

	// SPF: 10 points for pass, 5 for neutral/softfail, 0 for fail
	if results.Spf != nil {
		switch results.Spf.Result {
		case api.AuthResultResultPass:
			score += 10.0
		case api.AuthResultResultNeutral, api.AuthResultResultSoftfail:
			score += 5.0
		}
	}

	// DKIM: 10 points for at least one pass
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		for _, dkim := range *results.Dkim {
			if dkim.Result == api.AuthResultResultPass {
				score += 10.0
				break
			}
		}
	}

	// DMARC: 10 points for pass
	if results.Dmarc != nil {
		switch results.Dmarc.Result {
		case api.AuthResultResultPass:
			score += 10.0
		}
	}

	// Cap at 30 points maximum
	if score > 30.0 {
		score = 30.0
	}

	return score
}
