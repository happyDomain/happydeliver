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

func (a *AuthenticationAnalyzer) calculateBIMIScore(results *api.AuthenticationResults) (score int) {
	if results.Bimi != nil {
		switch results.Bimi.Result {
		case api.AuthResultResultPass:
			return 100
		case api.AuthResultResultDeclined:
			return 59
		default: // fail
			return 0
		}
	}

	return 0
}
