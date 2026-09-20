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

	"git.happydns.org/happyDeliver/pkg/authresults"
	"git.happydns.org/happyDeliver/pkg/grade"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
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
func (a *AuthenticationAnalyzer) AnalyzeAuthentication(email *mailmsg.Message, authservID string) *model.AuthenticationResults {
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
	field, read := authresults.Parse(header)
	if !read {
		return
	}

	// Best envelope sender verdict of this header, kept apart from results.Spf so
	// that the priority below arbitrates between the methods of this header only.
	// Across headers the topmost one wins: it was written by the closest hop,
	// while a header below it was already in the message when that hop received
	// it, and must never supersede the verdict it gave.
	var headerSpf *model.AuthResult

	for _, method := range field.Methods {
		switch method.Name {
		// A header may carry several spf= methods, one per identity checked:
		// route each of them to the field describing that identity, so a HELO
		// verdict never stands in for the envelope sender one.
		case "spf":
			spfResult := a.parseSPFResult(method)

			if spfResult.Identity != nil && *spfResult.Identity == model.AuthResultIdentityHelo {
				if results.SpfHelo == nil {
					results.SpfHelo = spfResult
				}
			} else if headerSpf == nil || spfIdentityPriority(spfResult) > spfIdentityPriority(headerSpf) {
				// An explicit smtp.mailfrom method supersedes one with no ptype
				headerSpf = spfResult
			}

		case "dkim":
			dkimResult := a.parseDKIMResult(method)
			if results.Dkim == nil {
				dkimList := []model.AuthResult{*dkimResult}
				results.Dkim = &dkimList
			} else {
				*results.Dkim = append(*results.Dkim, *dkimResult)
			}

		case "dmarc":
			if results.Dmarc == nil {
				results.Dmarc = a.parseDMARCResult(method)
			}

		case "bimi":
			if results.Bimi == nil {
				results.Bimi = a.parseBIMIResult(method)
			}

		case "arc":
			if results.Arc == nil {
				results.Arc = a.parseARCResult(method)
			}

		case "iprev":
			if results.Iprev == nil {
				results.Iprev = a.parseIPRevResult(method)
			}

		case "x-google-dkim":
			if results.XGoogleDkim == nil {
				results.XGoogleDkim = a.parseXGoogleDKIMResult(method)
			}

		case "x-aligned-from":
			if results.XAlignedFrom == nil {
				results.XAlignedFrom = a.parseXAlignedFromResult(method)
			}

		case "x-ptr":
			if results.XPtr == nil {
				results.XPtr = a.parseXPtrResult(method)
			}

		case "x-tls":
			if results.XTls == nil {
				results.XTls = a.parseXTLSResult(method)
			}
		}
	}

	// First verdict on the envelope sender wins, whichever header carried it
	if results.Spf == nil {
		results.Spf = headerSpf
	}
}

// methodDetails is the method as the receiver wrote it, without the name it
// wrote it under: what the report quotes back to a sender is the verdict and
// what was read to reach it, not a repetition of the method's own name.
func methodDetails(method authresults.Method) string {
	_, details, written := strings.Cut(method.Raw, "=")
	if !written {
		return method.Raw
	}

	return strings.TrimSpace(details)
}

// hasRequiredResults tells whether any of the mechanisms the score is built
// on (SPF, DKIM, DMARC) was actually evaluated by a receiver. An ARC seal or a
// transport check alone says nothing about the sender's authentication.
func (a *AuthenticationAnalyzer) hasRequiredResults(results *model.AuthenticationResults) bool {
	return results.Spf != nil || results.SpfHelo != nil ||
		(results.Dkim != nil && len(*results.Dkim) > 0) ||
		results.Dmarc != nil
}

// CalculateAuthenticationScore calculates the authentication score from auth results
// Returns a score from 0-100 where higher is better, and an empty grade when no
// receiver reported any of the required mechanisms: the category did not run,
// so it must not weigh on the report as if the sender had failed everything.
func (a *AuthenticationAnalyzer) CalculateAuthenticationScore(results *model.AuthenticationResults) (int, string) {
	if results == nil || !a.hasRequiredResults(results) {
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

	return score, grade.Of(score)
}
