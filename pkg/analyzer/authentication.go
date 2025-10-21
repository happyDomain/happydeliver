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
	"slices"
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

	result.Details = api.PtrTo(strings.TrimPrefix(part, "dkim="))

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

	result.Details = api.PtrTo(strings.TrimPrefix(part, "dmarc="))

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

	result.Details = api.PtrTo(strings.TrimPrefix(part, "bimi="))

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

	result.Details = api.PtrTo(strings.TrimPrefix(part, "arc="))

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
		if !slices.Contains(sealInstances, i) || !slices.Contains(sigInstances, i) || !slices.Contains(authInstances, i) {
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

	result.Details = &receivedSPF

	// Try to extract domain
	domainRe := regexp.MustCompile(`(?:envelope-from|sender)="?([^\s;"]+)`)
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

// CalculateAuthenticationScore calculates the authentication score from auth results
// Returns a score from 0-100 where higher is better
func (a *AuthenticationAnalyzer) CalculateAuthenticationScore(results *api.AuthenticationResults) int {
	if results == nil {
		return 0
	}

	score := 0

	// SPF (30 points)
	if results.Spf != nil {
		switch results.Spf.Result {
		case api.AuthResultResultPass:
			score += 30
		case api.AuthResultResultNeutral, api.AuthResultResultNone:
			score += 15
		case api.AuthResultResultSoftfail:
			score += 5
		default: // fail, temperror, permerror
			score += 0
		}
	}

	// DKIM (30 points) - at least one passing signature
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		hasPass := false
		for _, dkim := range *results.Dkim {
			if dkim.Result == api.AuthResultResultPass {
				hasPass = true
				break
			}
		}
		if hasPass {
			score += 30
		} else {
			// Has DKIM signatures but none passed
			score += 10
		}
	}

	// DMARC (30 points)
	if results.Dmarc != nil {
		switch results.Dmarc.Result {
		case api.AuthResultResultPass:
			score += 30
		case api.AuthResultResultNone:
			score += 10
		default: // fail
			score += 0
		}
	}

	// BIMI (10 points)
	if results.Bimi != nil {
		switch results.Bimi.Result {
		case api.AuthResultResultPass:
			score += 10
		case api.AuthResultResultNone:
			score += 5
		default: // fail
			score += 0
		}
	}

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}

	return score
}
