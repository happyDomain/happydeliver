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
	"time"

	"git.happydns.org/happyDeliver/internal/model"
)

// AuthenticationAnalyzer analyzes email authentication results
type AuthenticationAnalyzer struct {
	receiverHostname string

	// dkimVerifier computes a first-hand DKIM verdict when the message carries
	// none. A nil verifier limits the analyzer to what other servers reported.
	dkimVerifier *DKIMVerifier

	// dmarcVerifier computes a first-hand DMARC verdict when no trusted
	// Authentication-Results header covers it. A nil verifier limits the
	// analyzer to what other servers reported.
	dmarcVerifier *DMARCVerifier
}

// NewAuthenticationAnalyzer creates a new authentication analyzer.
//
// The analyzer only reports the verdicts other servers recorded in
// Authentication-Results headers; use NewAuthenticationAnalyzerWithResolver to
// also verify DKIM signatures first-hand.
func NewAuthenticationAnalyzer(receiverHostname string) *AuthenticationAnalyzer {
	return &AuthenticationAnalyzer{receiverHostname: receiverHostname}
}

// NewAuthenticationAnalyzerWithResolver creates an analyzer that verifies DKIM
// signatures and DMARC alignment itself, through resolver, when no trusted
// Authentication-Results header covers them. A nil resolver disables that
// verification.
func NewAuthenticationAnalyzerWithResolver(receiverHostname string, timeout time.Duration, resolver DNSResolver) *AuthenticationAnalyzer {
	return &AuthenticationAnalyzer{
		receiverHostname: receiverHostname,
		dkimVerifier:     NewDKIMVerifier(resolver, timeout),
		dmarcVerifier:    NewDMARCVerifier(resolver, timeout),
	}
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

	// If no Authentication-Results headers, try to parse legacy headers
	if results.Spf == nil {
		results.Spf = a.parseLegacySPF(email, authservID)
	}

	// No trusted Authentication-Results said anything about DKIM: verify the
	// signatures ourselves instead of leaving the message unjudged. This only
	// ever fills a gap — a dkim= we do trust is that receiver's own measurement,
	// taken on the message as it stood there, and is never overwritten.
	if results.Dkim == nil || len(*results.Dkim) == 0 {
		if verified := a.dkimVerifier.VerifyDKIM(email.Raw); len(verified) > 0 {
			results.Dkim = &verified
		}
	}

	// No trusted Authentication-Results said anything about DMARC: evaluate
	// alignment ourselves, against the SPF and DKIM verdicts now on hand and the
	// policy published for the From domain. Same rule as DKIM above: this only
	// ever fills a gap.
	if results.Dmarc == nil {
		if fromDomain := fromAddressDomain(email); fromDomain != "" {
			var dkimResults []model.AuthResult
			if results.Dkim != nil {
				dkimResults = *results.Dkim
			}
			results.Dmarc = a.dmarcVerifier.VerifyDMARC(fromDomain, results.Spf, dkimResults)
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

// fromAddressDomain returns the domain of the message's From header, the
// domain DMARC protects, or "" when the header is absent or unparsable.
func fromAddressDomain(email *EmailMessage) string {
	if email.From == nil {
		return ""
	}
	idx := strings.LastIndex(email.From.Address, "@")
	if idx == -1 {
		return ""
	}
	return email.From.Address[idx+1:]
}

// parseAuthenticationResultsHeader parses an Authentication-Results header
// Format: example.com; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com
func (a *AuthenticationAnalyzer) parseAuthenticationResultsHeader(header string, results *model.AuthenticationResults) {
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

	// Ensure score doesn't exceed 100
	if score > 100 {
		score = 100
	}

	return score, ScoreToGrade(score)
}
