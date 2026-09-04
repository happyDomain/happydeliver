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

	"git.happydns.org/happyDeliver/internal/model"
)

// AuthenticationAnalyzer analyzes email authentication results
type AuthenticationAnalyzer struct {
	receiverHostname string
}

// NewAuthenticationAnalyzer creates a new authentication analyzer
func NewAuthenticationAnalyzer(receiverHostname string) *AuthenticationAnalyzer {
	return &AuthenticationAnalyzer{receiverHostname: receiverHostname}
}

// AnalyzeAuthentication extracts and analyzes authentication results from email headers.
//
// Only the headers written by authservID are trusted; an empty authservID trusts every
// Authentication-Results header found in the message.
func (a *AuthenticationAnalyzer) AnalyzeAuthentication(email *EmailMessage, authservID string) *model.AuthenticationResults {
	results := &model.AuthenticationResults{}

	// Parse Authentication-Results headers
	authHeaders := email.GetAuthenticationResults(authservID)
	for _, header := range authHeaders {
		a.parseAuthenticationResultsHeader(header, results)
	}

	// If the Authentication-Results headers reported no verdict on the envelope
	// sender, fall back to the legacy Received-SPF ones, which may carry either
	// identity. They are only consulted then: when the modern headers did report
	// that verdict, they are the authority, and a stray Received-SPF written by
	// another hop must not add a HELO penalty of its own.
	if results.Spf == nil {
		legacySpf, legacyHelo := a.parseLegacySPF(email, authservID)

		results.Spf = legacySpf
		if results.SpfHelo == nil {
			results.SpfHelo = legacyHelo
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
func (a *AuthenticationAnalyzer) parseAuthenticationResultsHeader(header string, results *model.AuthenticationResults) {
	// Split by semicolon to get individual results
	parts := strings.Split(header, ";")
	if len(parts) < 2 {
		return
	}

	// Best envelope sender verdict of this header, kept apart from results.Spf so
	// that the priority below arbitrates between the methods of this header only.
	// Across headers the topmost one wins: it was written by the closest hop,
	// while a header below it was already in the message when that hop received
	// it, and must never supersede the verdict it gave.
	var headerSpf *model.AuthResult

	// Skip the authserv-id (first part)
	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}

		// Parse SPF. A header may carry several spf= methods, one per identity
		// checked: route each of them to the field describing that identity, so a
		// HELO verdict never stands in for the envelope sender one.
		if strings.HasPrefix(part, "spf=") {
			spfResult := a.parseSPFResult(part)

			if spfResult.Identity != nil && *spfResult.Identity == model.AuthResultIdentityHelo {
				if results.SpfHelo == nil {
					results.SpfHelo = spfResult
				}
			} else if headerSpf == nil || spfIdentityPriority(spfResult) > spfIdentityPriority(headerSpf) {
				// An explicit smtp.mailfrom method supersedes one with no ptype
				headerSpf = spfResult
			}
		}

		// Parse DKIM
		if strings.HasPrefix(part, "dkim=") {
			dkimResult := a.parseDKIMResult(part)
			if dkimResult != nil {
				if results.Dkim == nil {
					dkimList := []model.AuthResult{*dkimResult}
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

		// Parse x-ptr
		if strings.HasPrefix(part, "x-ptr=") {
			if results.XPtr == nil {
				results.XPtr = a.parseXPtrResult(part)
			}
		}

		// Parse x-tls
		if strings.HasPrefix(part, "x-tls=") {
			if results.XTls == nil {
				results.XTls = a.parseXTLSResult(part)
			}
		}
	}

	// First verdict on the envelope sender wins, whichever header carried it
	if results.Spf == nil {
		results.Spf = headerSpf
	}
}

// CalculateAuthenticationScore calculates the authentication score from auth results
// Returns a score from 0-100 where higher is better
func (a *AuthenticationAnalyzer) CalculateAuthenticationScore(results *model.AuthenticationResults) (int, string) {
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

	// Penalty-only: SPF on the HELO identity (up to -5 points on failure)
	score += 5 * a.calculateSPFHeloScore(results) / 100

	// Penalty-only: IPRev (up to -7 points on failure)
	if iprevScore := a.calculateIPRevScore(results); iprevScore < 100 {
		score += 7 * (iprevScore - 100) / 100
	}

	// Penalty-only: X-Google-DKIM (up to -12 points on failure)
	score += 12 * a.calculateXGoogleDKIMScore(results) / 100

	// Penalty-only: X-Aligned-From (up to -5 points on failure)
	score += 5 * a.calculateXAlignedFromScore(results) / 100

	// Penalty-only: X-TLS / transport encryption (-10 points when not encrypted)
	score += 10 * a.calculateXTLSScore(results) / 100

	// Keep the score within bounds: the penalties above can add up to more than
	// what the core checks award, so the total may go below zero
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	return score, ScoreToGrade(score)
}
