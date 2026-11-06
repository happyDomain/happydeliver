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

// parseBIMIResult parses BIMI result from Authentication-Results
// Example: bimi=pass header.d=example.com header.selector=default policy.authority=pass
func (a *AuthenticationAnalyzer) parseBIMIResult(method authresults.Method) *model.AuthResult {
	result := &model.AuthResult{
		Result:  model.AuthResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	if domain := method.Property("header.d", "d"); domain != "" {
		result.Domain = &domain
	}
	if selector := method.Property("header.selector", "selector"); selector != "" {
		result.Selector = &selector
	}
	if authority := method.Property("policy.authority"); authority != "" {
		result.Authority = &authority
	}

	return result
}

// bimiUncertified tells whether no valid mark certificate backs the logo. The
// receiver says so with policy.authority when the record publishes a
// certificate; when it says nothing, because there is none or because it is
// not one to write that property, the analysis of the record decides. Without
// an analysis, nothing says so.
func bimiUncertified(results *model.AuthenticationResults, dns *model.DNSResults) bool {
	if results.Bimi != nil && results.Bimi.Authority != nil {
		return *results.Bimi.Authority != "pass"
	}
	if dns == nil || dns.BimiRecord == nil {
		return false
	}
	vmc := dns.BimiRecord.Vmc
	return vmc == nil || !vmc.Valid
}

// calculateBIMIScore only grants all the points to a logo a mark certificate
// vouches for: a receiver also reports pass for a self-asserted logo, which
// earns what declining does. dns is what the records of the sender say.
func (a *AuthenticationAnalyzer) calculateBIMIScore(results *model.AuthenticationResults, dns *model.DNSResults) (score int) {
	if results.Bimi != nil {
		switch results.Bimi.Result {
		case model.AuthResultResultPass:
			if bimiUncertified(results, dns) {
				return 50
			}
			return 100
		case model.AuthResultResultDeclined:
			return 50
		default: // fail
			return 0
		}
	}

	return 0
}
