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

// pluralize returns "y" or "ies" based on count
func pluralize(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
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
