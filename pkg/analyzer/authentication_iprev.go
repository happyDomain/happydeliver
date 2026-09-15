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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"

	"git.happydns.org/happyDeliver/pkg/authresults"
)

// parseIPRevResult parses IP reverse lookup result from Authentication-Results
// Example: iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)
func (a *AuthenticationAnalyzer) parseIPRevResult(method authresults.Method) *model.IPRevResult {
	result := &model.IPRevResult{
		Result:  model.IPRevResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	// The address that was looked up, under the two spellings receivers
	// prefer and under the ptype RFC 7601 gives iprev.
	if ip := method.Property("smtp.remote-ip", "remote-ip", "policy.iprev"); ip != "" {
		result.Ip = &ip
	}

	// The hostname the lookup answered, which receivers write in a comment
	// and nowhere else.
	if hostname := method.Comment(); hostname != "" {
		result.Hostname = &hostname
	}

	return result
}

func (a *AuthenticationAnalyzer) calculateIPRevScore(results *model.AuthenticationResults) (score int) {
	if results.Iprev != nil {
		switch results.Iprev.Result {
		case model.IPRevResultResultPass:
			return 100
		default: // fail, temperror, permerror
			return 0
		}
	}

	return 100
}
