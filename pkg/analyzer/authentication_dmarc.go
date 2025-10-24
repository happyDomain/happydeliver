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

func (a *AuthenticationAnalyzer) calculateDMARCScore(results *api.AuthenticationResults) (score int) {
	if results.Dmarc != nil {
		switch results.Dmarc.Result {
		case api.AuthResultResultPass:
			return 100
		case api.AuthResultResultNone:
			return 33
		default: // fail
			return 0
		}
	}

	return 0
}
