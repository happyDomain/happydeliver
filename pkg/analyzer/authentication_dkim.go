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

func (a *AuthenticationAnalyzer) calculateDKIMScore(results *api.AuthenticationResults) (score int) {
	// Expect at least one passing signature
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		hasPass := false
		hasNonPass := false
		for _, dkim := range *results.Dkim {
			if dkim.Result == api.AuthResultResultPass {
				hasPass = true
			} else {
				hasNonPass = true
			}
		}
		if hasPass && hasNonPass {
			// Could be better
			return 90
		} else if hasPass {
			return 100
		} else {
			// Has DKIM signatures but none passed
			return 20
		}
	}

	return 0
}
