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
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

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

	result.Details = api.PtrTo(strings.TrimPrefix(part, "spf="))

	return result
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

func (a *AuthenticationAnalyzer) calculateSPFScore(results *api.AuthenticationResults) (score int) {
	if results.Spf != nil {
		switch results.Spf.Result {
		case api.AuthResultResultPass:
			return 100
		case api.AuthResultResultNeutral, api.AuthResultResultNone:
			return 50
		case api.AuthResultResultSoftfail:
			return 17
		default: // fail, temperror, permerror
			return 0
		}
	}

	return 0
}
