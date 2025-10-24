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

// parseIPRevResult parses IP reverse lookup result from Authentication-Results
// Example: iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)
func (a *AuthenticationAnalyzer) parseIPRevResult(part string) *api.IPRevResult {
	result := &api.IPRevResult{}

	// Extract result (pass, fail, temperror, permerror, none)
	re := regexp.MustCompile(`iprev=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = api.IPRevResultResult(resultStr)
	}

	// Extract IP address (smtp.remote-ip or remote-ip)
	ipRe := regexp.MustCompile(`(?:smtp\.)?remote-ip=([^\s;()]+)`)
	if matches := ipRe.FindStringSubmatch(part); len(matches) > 1 {
		ip := matches[1]
		result.Ip = &ip
	}

	// Extract hostname from parentheses
	hostnameRe := regexp.MustCompile(`\(([^)]+)\)`)
	if matches := hostnameRe.FindStringSubmatch(part); len(matches) > 1 {
		hostname := matches[1]
		result.Hostname = &hostname
	}

	result.Details = api.PtrTo(strings.TrimPrefix(part, "iprev="))

	return result
}

func (a *AuthenticationAnalyzer) calculateIPRevScore(results *api.AuthenticationResults) (score int) {
	if results.Iprev != nil {
		switch results.Iprev.Result {
		case api.Pass:
			return 100
		default: // fail, temperror, permerror
			return 0
		}
	}

	return 0
}
