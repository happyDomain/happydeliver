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
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// AuthenticationAnalyzer analyzes email authentication results
type AuthenticationAnalyzer struct{}

// NewAuthenticationAnalyzer creates a new authentication analyzer
func NewAuthenticationAnalyzer() *AuthenticationAnalyzer {
	return &AuthenticationAnalyzer{}
}

// AnalyzeAuthentication extracts and analyzes authentication results from email headers
func (a *AuthenticationAnalyzer) AnalyzeAuthentication(email *EmailMessage) *api.AuthenticationResults {
	results := &api.AuthenticationResults{}

	// Parse Authentication-Results headers
	authHeaders := email.GetAuthenticationResults()
	for _, header := range authHeaders {
		a.parseAuthenticationResultsHeader(header, results)
	}

	// If no Authentication-Results headers, try to parse legacy headers
	if results.Spf == nil {
		results.Spf = a.parseLegacySPF(email)
	}

	if results.Dkim == nil || len(*results.Dkim) == 0 {
		dkimResults := a.parseLegacyDKIM(email)
		if len(dkimResults) > 0 {
			results.Dkim = &dkimResults
		}
	}

	// Parse ARC headers if not already parsed from Authentication-Results
	if results.Arc == nil {
		results.Arc = a.parseARCHeaders(email)
	} else {
		// Enhance the ARC result with chain information from raw headers
		a.enhanceARCResult(email, results.Arc)
	}

	return results
}

// parseAuthenticationResultsHeader parses an Authentication-Results header
// Format: example.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com
func (a *AuthenticationAnalyzer) parseAuthenticationResultsHeader(header string, results *api.AuthenticationResults) {
	// Split by semicolon to get individual results
	parts := strings.Split(header, ";")
	if len(parts) < 2 {
		return
	}

	// Skip the authserv-id (first part)
	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}

		// Parse SPF
		if strings.HasPrefix(part, "spf=") {
			if results.Spf == nil {
				results.Spf = a.parseSPFResult(part)
			}
		}

		// Parse DKIM
		if strings.HasPrefix(part, "dkim=") {
			dkimResult := a.parseDKIMResult(part)
			if dkimResult != nil {
				if results.Dkim == nil {
					dkimList := []api.AuthResult{*dkimResult}
					results.Dkim = &dkimList
				} else {
					*results.Dkim = append(*results.Dkim, *dkimResult)
				}
			}
		}

		// Parse DMARC
		if strings.HasPrefix(part, "dmarc=") {
			if results.Dmarc == nil {
				results.Dmarc = a.parseDMARCResult(part)
			}
		}

		// Parse BIMI
		if strings.HasPrefix(part, "bimi=") {
			if results.Bimi == nil {
				results.Bimi = a.parseBIMIResult(part)
			}
		}

		// Parse ARC
		if strings.HasPrefix(part, "arc=") {
			if results.Arc == nil {
				results.Arc = a.parseARCResult(part)
			}
		}
	}
}

// parseSPFResult parses SPF result from Authentication-Results
// Example: spf=pass smtp.mailfrom=sender@example.com
func (a *AuthenticationAnalyzer) parseSPFResult(part string) *api.AuthResult {
	result := &api.AuthResult{}

	// Extract result (pass, fail, etc.)
	re := regexp.MustCompile(`spf=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.AuthResultResult(resultStr)
	}

	// Extract domain
	domainRe := regexp.MustCompile(`smtp\.mailfrom=([^\s;]+)`)
	if matches := domainRe.FindStringSubmatch(part); len(matches) > 1 {
		email := matches[1]
		// Extract domain from email
		if idx := strings.Index(email, "@"); idx != -1 {
			domain := email[idx+1:]
			result.Domain = &domain
		}
	}

	// Extract details
	if idx := strings.Index(part, "("); idx != -1 {
		endIdx := strings.Index(part[idx:], ")")
		if endIdx != -1 {
			details := strings.TrimSpace(part[idx+1 : idx+endIdx])
			result.Details = &details
		}
	}

	return result
}

// parseDKIMResult parses DKIM result from Authentication-Results
// Example: dkim=pass header.d=example.com header.s=selector1
func (a *AuthenticationAnalyzer) parseDKIMResult(part string) *api.AuthResult {
	result := &api.AuthResult{}

	// Extract result (pass, fail, etc.)
	re := regexp.MustCompile(`dkim=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.AuthResultResult(resultStr)
	}

	// Extract domain (header.d or d)
	domainRe := regexp.MustCompile(`(?:header\.)?d=([^\s;]+)`)
	if matches := domainRe.FindStringSubmatch(part); len(matches) > 1 {
		domain := matches[1]
		result.Domain = &domain
	}

	// Extract selector (header.s or s)
	selectorRe := regexp.MustCompile(`(?:header\.)?s=([^\s;]+)`)
	if matches := selectorRe.FindStringSubmatch(part); len(matches) > 1 {
		selector := matches[1]
		result.Selector = &selector
	}

	// Extract details
	if idx := strings.Index(part, "("); idx != -1 {
		endIdx := strings.Index(part[idx:], ")")
		if endIdx != -1 {
			details := strings.TrimSpace(part[idx+1 : idx+endIdx])
			result.Details = &details
		}
	}

	return result
}

// parseDMARCResult parses DMARC result from Authentication-Results
// Example: dmarc=pass action=none header.from=example.com
func (a *AuthenticationAnalyzer) parseDMARCResult(part string) *api.AuthResult {
	result := &api.AuthResult{}

	// Extract result (pass, fail, etc.)
	re := regexp.MustCompile(`dmarc=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.AuthResultResult(resultStr)
	}

	// Extract domain (header.from)
	domainRe := regexp.MustCompile(`header\.from=([^\s;]+)`)
	if matches := domainRe.FindStringSubmatch(part); len(matches) > 1 {
		domain := matches[1]
		result.Domain = &domain
	}

	// Extract details (action, policy, etc.)
	var detailsParts []string
	actionRe := regexp.MustCompile(`action=([^\s;]+)`)
	if matches := actionRe.FindStringSubmatch(part); len(matches) > 1 {
		detailsParts = append(detailsParts, fmt.Sprintf("action=%s", matches[1]))
	}

	if len(detailsParts) > 0 {
		details := strings.Join(detailsParts, " ")
		result.Details = &details
	}

	return result
}

// parseBIMIResult parses BIMI result from Authentication-Results
// Example: bimi=pass header.d=example.com header.selector=default
func (a *AuthenticationAnalyzer) parseBIMIResult(part string) *api.AuthResult {
	result := &api.AuthResult{}

	// Extract result (pass, fail, etc.)
	re := regexp.MustCompile(`bimi=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.AuthResultResult(resultStr)
	}

	// Extract domain (header.d or d)
	domainRe := regexp.MustCompile(`(?:header\.)?d=([^\s;]+)`)
	if matches := domainRe.FindStringSubmatch(part); len(matches) > 1 {
		domain := matches[1]
		result.Domain = &domain
	}

	// Extract selector (header.selector or selector)
	selectorRe := regexp.MustCompile(`(?:header\.)?selector=([^\s;]+)`)
	if matches := selectorRe.FindStringSubmatch(part); len(matches) > 1 {
		selector := matches[1]
		result.Selector = &selector
	}

	// Extract details
	if idx := strings.Index(part, "("); idx != -1 {
		endIdx := strings.Index(part[idx:], ")")
		if endIdx != -1 {
			details := strings.TrimSpace(part[idx+1 : idx+endIdx])
			result.Details = &details
		}
	}

	return result
}

// parseARCResult parses ARC result from Authentication-Results
// Example: arc=pass
func (a *AuthenticationAnalyzer) parseARCResult(part string) *api.ARCResult {
	result := &api.ARCResult{}

	// Extract result (pass, fail, none)
	re := regexp.MustCompile(`arc=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.ARCResultResult(resultStr)
	}

	// Extract details
	if idx := strings.Index(part, "("); idx != -1 {
		endIdx := strings.Index(part[idx:], ")")
		if endIdx != -1 {
			details := strings.TrimSpace(part[idx+1 : idx+endIdx])
			result.Details = &details
		}
	}

	return result
}

// parseARCHeaders parses ARC headers from email message
// ARC consists of three headers per hop: ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal
func (a *AuthenticationAnalyzer) parseARCHeaders(email *EmailMessage) *api.ARCResult {
	// Get all ARC-related headers
	arcAuthResults := email.Header[textprotoCanonical("ARC-Authentication-Results")]
	arcMessageSig := email.Header[textprotoCanonical("ARC-Message-Signature")]
	arcSeal := email.Header[textprotoCanonical("ARC-Seal")]

	// If no ARC headers present, return nil
	if len(arcAuthResults) == 0 && len(arcMessageSig) == 0 && len(arcSeal) == 0 {
		return nil
	}

	result := &api.ARCResult{
		Result: api.ARCResultResultNone,
	}

	// Count the ARC chain length (number of sets)
	chainLength := len(arcSeal)
	result.ChainLength = &chainLength

	// Validate the ARC chain
	chainValid := a.validateARCChain(arcAuthResults, arcMessageSig, arcSeal)
	result.ChainValid = &chainValid

	// Determine overall result
	if chainLength == 0 {
		result.Result = api.ARCResultResultNone
		details := "No ARC chain present"
		result.Details = &details
	} else if !chainValid {
		result.Result = api.ARCResultResultFail
		details := fmt.Sprintf("ARC chain validation failed (chain length: %d)", chainLength)
		result.Details = &details
	} else {
		result.Result = api.ARCResultResultPass
		details := fmt.Sprintf("ARC chain valid with %d intermediar%s", chainLength, pluralize(chainLength))
		result.Details = &details
	}

	return result
}

// enhanceARCResult enhances an existing ARC result with chain information
func (a *AuthenticationAnalyzer) enhanceARCResult(email *EmailMessage, arcResult *api.ARCResult) {
	if arcResult == nil {
		return
	}

	// Get ARC headers
	arcSeal := email.Header[textprotoCanonical("ARC-Seal")]
	arcMessageSig := email.Header[textprotoCanonical("ARC-Message-Signature")]
	arcAuthResults := email.Header[textprotoCanonical("ARC-Authentication-Results")]

	// Set chain length if not already set
	if arcResult.ChainLength == nil {
		chainLength := len(arcSeal)
		arcResult.ChainLength = &chainLength
	}

	// Validate chain if not already validated
	if arcResult.ChainValid == nil {
		chainValid := a.validateARCChain(arcAuthResults, arcMessageSig, arcSeal)
		arcResult.ChainValid = &chainValid
	}
}

// validateARCChain validates the ARC chain for completeness
// Each instance should have all three headers with matching instance numbers
func (a *AuthenticationAnalyzer) validateARCChain(arcAuthResults, arcMessageSig, arcSeal []string) bool {
	// All three header types should have the same count
	if len(arcAuthResults) != len(arcMessageSig) || len(arcAuthResults) != len(arcSeal) {
		return false
	}

	if len(arcSeal) == 0 {
		return true // No ARC chain is technically valid
	}

	// Extract instance numbers from each header type
	sealInstances := a.extractARCInstances(arcSeal)
	sigInstances := a.extractARCInstances(arcMessageSig)
	authInstances := a.extractARCInstances(arcAuthResults)

	// Check that all instance numbers match and are sequential starting from 1
	if len(sealInstances) != len(sigInstances) || len(sealInstances) != len(authInstances) {
		return false
	}

	// Verify instances are sequential from 1 to N
	for i := 1; i <= len(sealInstances); i++ {
		if !contains(sealInstances, i) || !contains(sigInstances, i) || !contains(authInstances, i) {
			return false
		}
	}

	return true
}

// extractARCInstances extracts instance numbers from ARC headers
func (a *AuthenticationAnalyzer) extractARCInstances(headers []string) []int {
	var instances []int
	re := regexp.MustCompile(`i=(\d+)`)

	for _, header := range headers {
		if matches := re.FindStringSubmatch(header); len(matches) > 1 {
			var instance int
			fmt.Sscanf(matches[1], "%d", &instance)
			instances = append(instances, instance)
		}
	}

	return instances
}

// contains checks if a slice contains an integer
func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// pluralize returns "y" or "ies" based on count
func pluralize(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
}

// parseLegacySPF attempts to parse SPF from Received-SPF header
func (a *AuthenticationAnalyzer) parseLegacySPF(email *EmailMessage) *api.AuthResult {
	receivedSPF := email.Header.Get("Received-SPF")
	if receivedSPF == "" {
		return nil
	}

	result := &api.AuthResult{}

	// Extract result (first word)
	parts := strings.Fields(receivedSPF)
	if len(parts) > 0 {
		resultStr := strings.ToLower(parts[0])
		result.Result = api.AuthResultResult(resultStr)
	}

	// Try to extract domain
	domainRe := regexp.MustCompile(`(?:envelope-from|sender)=([^\s;]+)`)
	if matches := domainRe.FindStringSubmatch(receivedSPF); len(matches) > 1 {
		email := matches[1]
		if idx := strings.Index(email, "@"); idx != -1 {
			domain := email[idx+1:]
			result.Domain = &domain
		}
	}

	return result
}

// parseLegacyDKIM attempts to parse DKIM from DKIM-Signature header
func (a *AuthenticationAnalyzer) parseLegacyDKIM(email *EmailMessage) []api.AuthResult {
	var results []api.AuthResult

	// Get all DKIM-Signature headers
	dkimHeaders := email.Header[textprotoCanonical("DKIM-Signature")]
	for _, dkimHeader := range dkimHeaders {
		result := api.AuthResult{
			Result: api.AuthResultResultNone, // We can't determine pass/fail from signature alone
		}

		// Extract domain (d=)
		domainRe := regexp.MustCompile(`d=([^\s;]+)`)
		if matches := domainRe.FindStringSubmatch(dkimHeader); len(matches) > 1 {
			domain := matches[1]
			result.Domain = &domain
		}

		// Extract selector (s=)
		selectorRe := regexp.MustCompile(`s=([^\s;]+)`)
		if matches := selectorRe.FindStringSubmatch(dkimHeader); len(matches) > 1 {
			selector := matches[1]
			result.Selector = &selector
		}

		details := "DKIM signature present (verification status unknown)"
		result.Details = &details

		results = append(results, result)
	}

	return results
}

// textprotoCanonical converts a header name to canonical form
func textprotoCanonical(s string) string {
	// Simple implementation - capitalize each word
	words := strings.Split(s, "-")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, "-")
}

// GetAuthenticationScore calculates the authentication score (0-3 points)
func (a *AuthenticationAnalyzer) GetAuthenticationScore(results *api.AuthenticationResults) float32 {
	var score float32 = 0.0

	// SPF: 1 point for pass, 0.5 for neutral/softfail, 0 for fail
	if results.Spf != nil {
		switch results.Spf.Result {
		case api.AuthResultResultPass:
			score += 1.0
		case api.AuthResultResultNeutral, api.AuthResultResultSoftfail:
			score += 0.5
		}
	}

	// DKIM: 1 point for at least one pass
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		for _, dkim := range *results.Dkim {
			if dkim.Result == api.AuthResultResultPass {
				score += 1.0
				break
			}
		}
	}

	// DMARC: 1 point for pass
	if results.Dmarc != nil {
		switch results.Dmarc.Result {
		case api.AuthResultResultPass:
			score += 1.0
		}
	}

	// Cap at 3 points maximum
	if score > 3.0 {
		score = 3.0
	}

	return score
}

// GenerateAuthenticationChecks generates check results for authentication
func (a *AuthenticationAnalyzer) GenerateAuthenticationChecks(results *api.AuthenticationResults) []api.Check {
	var checks []api.Check

	// SPF check
	if results.Spf != nil {
		check := a.generateSPFCheck(results.Spf)
		checks = append(checks, check)
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "SPF Record",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No SPF authentication result found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Ensure your MTA is configured to check SPF records"),
		})
	}

	// DKIM check
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		for i, dkim := range *results.Dkim {
			check := a.generateDKIMCheck(&dkim, i)
			checks = append(checks, check)
		}
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "DKIM Signature",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No DKIM signature found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Configure DKIM signing for your domain to improve deliverability"),
		})
	}

	// DMARC check
	if results.Dmarc != nil {
		check := a.generateDMARCCheck(results.Dmarc)
		checks = append(checks, check)
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "DMARC Policy",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No DMARC authentication result found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Implement DMARC policy for your domain"),
		})
	}

	// BIMI check (optional, informational only)
	if results.Bimi != nil {
		check := a.generateBIMICheck(results.Bimi)
		checks = append(checks, check)
	}

	// ARC check (optional, for forwarded emails)
	if results.Arc != nil {
		check := a.generateARCCheck(results.Arc)
		checks = append(checks, check)
	}

	return checks
}

func (a *AuthenticationAnalyzer) generateSPFCheck(spf *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "SPF Record",
	}

	switch spf.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "SPF validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your SPF record is properly configured")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "SPF validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		check.Advice = api.PtrTo("Fix your SPF record to authorize this sending server")
	case api.AuthResultResultSoftfail:
		check.Status = api.CheckStatusWarn
		check.Score = 0.5
		check.Message = "SPF validation softfail"
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Review your SPF record configuration")
	case api.AuthResultResultNeutral:
		check.Status = api.CheckStatusWarn
		check.Score = 0.5
		check.Message = "SPF validation neutral"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("Consider tightening your SPF policy")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("SPF validation result: %s", spf.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Review your SPF record configuration")
	}

	if spf.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *spf.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateDKIMCheck(dkim *api.AuthResult, index int) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     fmt.Sprintf("DKIM Signature #%d", index+1),
	}

	switch dkim.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "DKIM signature is valid"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your DKIM signature is properly configured")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "DKIM signature validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Check your DKIM keys and signing configuration")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("DKIM validation result: %s", dkim.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Ensure DKIM signing is enabled and configured correctly")
	}

	var detailsParts []string
	if dkim.Domain != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Domain: %s", *dkim.Domain))
	}
	if dkim.Selector != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Selector: %s", *dkim.Selector))
	}
	if len(detailsParts) > 0 {
		details := strings.Join(detailsParts, ", ")
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateDMARCCheck(dmarc *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "DMARC Policy",
	}

	switch dmarc.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "DMARC validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your DMARC policy is properly aligned")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "DMARC validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Ensure SPF or DKIM alignment with your From domain")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("DMARC validation result: %s", dmarc.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Configure DMARC policy for your domain")
	}

	if dmarc.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *dmarc.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateBIMICheck(bimi *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "BIMI (Brand Indicators)",
	}

	switch bimi.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 0.0 // BIMI doesn't contribute to score (branding feature)
		check.Message = "BIMI validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your brand logo is properly configured via BIMI")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = "BIMI validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("BIMI is optional but can improve brand recognition. Ensure DMARC is enforced (p=quarantine or p=reject) and configure a valid BIMI record")
	default:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = fmt.Sprintf("BIMI validation result: %s", bimi.Result)
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("BIMI is optional. Consider implementing it to display your brand logo in supported email clients")
	}

	if bimi.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *bimi.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateARCCheck(arc *api.ARCResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "ARC (Authenticated Received Chain)",
	}

	switch arc.Result {
	case api.ARCResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 0.0 // ARC doesn't contribute to score (informational for forwarding)
		check.Message = "ARC chain validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("ARC preserves authentication results through email forwarding. Your email passed through intermediaries while maintaining authentication")
	case api.ARCResultResultFail:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = "ARC chain validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("The ARC chain is broken or invalid. This may indicate issues with email forwarding intermediaries")
	default:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = "No ARC chain present"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("ARC is not present. This is normal for emails sent directly without forwarding through mailing lists or other intermediaries")
	}

	// Build details
	var detailsParts []string
	if arc.ChainLength != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Chain length: %d", *arc.ChainLength))
	}
	if arc.ChainValid != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Chain valid: %v", *arc.ChainValid))
	}
	if arc.Details != nil {
		detailsParts = append(detailsParts, *arc.Details)
	}

	if len(detailsParts) > 0 {
		details := strings.Join(detailsParts, ", ")
		check.Details = &details
	}

	return check
}
