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
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// AuthenticationAnalyzer analyzes email authentication results
type AuthenticationAnalyzer struct {
	receiverHostname string
}

// NewAuthenticationAnalyzer creates a new authentication analyzer
func NewAuthenticationAnalyzer(receiverHostname string) *AuthenticationAnalyzer {
	return &AuthenticationAnalyzer{receiverHostname: receiverHostname}
}

// AnalyzeAuthentication extracts and analyzes authentication results from email headers
func (a *AuthenticationAnalyzer) AnalyzeAuthentication(email *EmailMessage) *api.AuthenticationResults {
	results := &api.AuthenticationResults{}

	// Parse Authentication-Results headers
	authHeaders := email.GetAuthenticationResults(a.receiverHostname)
	for _, header := range authHeaders {
		a.parseAuthenticationResultsHeader(header, results)
	}

	// If no Authentication-Results headers, try to parse legacy headers
	if results.Spf == nil {
		results.Spf = a.parseLegacySPF(email)
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

		// Parse IPRev
		if strings.HasPrefix(part, "iprev=") {
			if results.Iprev == nil {
				results.Iprev = a.parseIPRevResult(part)
			}
		}

		// Parse x-google-dkim
		if strings.HasPrefix(part, "x-google-dkim=") {
			if results.XGoogleDkim == nil {
				results.XGoogleDkim = a.parseXGoogleDKIMResult(part)
			}
		}

		// Parse x-aligned-from
		if strings.HasPrefix(part, "x-aligned-from=") {
			if results.XAlignedFrom == nil {
				results.XAlignedFrom = a.parseXAlignedFromResult(part)
			}
		}
	}
}

// CalculateAuthenticationScore calculates the authentication score from auth results
// Returns a score from 0-100 where higher is better
func (a *AuthenticationAnalyzer) CalculateAuthenticationScore(results *api.AuthenticationResults) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// Core authentication (90 points total)
	// SPF (30 points)
	score += 30 * a.calculateSPFScore(results) / 100

	// DKIM (30 points)
	score += 30 * a.calculateDKIMScore(results) / 100

	// DMARC (30 points)
	score += 30 * a.calculateDMARCScore(results) / 100

	// BIMI (10 points)
	score += 10 * a.calculateBIMIScore(results) / 100

	// Penalty-only: IPRev (up to -7 points on failure)
	if iprevScore := a.calculateIPRevScore(results); iprevScore < 100 {
		score += 7 * (iprevScore - 100) / 100
	}

	// Penalty-only: X-Google-DKIM (up to -12 points on failure)
	score += 12 * a.calculateXGoogleDKIMScore(results) / 100

	// Penalty-only: X-Aligned-From (up to -5 points on failure)
	if xAlignedScore := a.calculateXAlignedFromScore(results); xAlignedScore < 100 {
		score += 5 * (xAlignedScore - 100) / 100
	}

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}

	return score, ScoreToGrade(score)
}
