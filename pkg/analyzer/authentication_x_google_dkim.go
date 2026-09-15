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

// parseXGoogleDKIMResult parses Google DKIM result from Authentication-Results
// Example: x-google-dkim=pass (2048-bit rsa key) header.d=1e100.net header.i=@1e100.net header.b=fauiPVZ6
func (a *AuthenticationAnalyzer) parseXGoogleDKIMResult(method authresults.Method) *model.AuthResult {
	result := &model.AuthResult{
		Result:  model.AuthResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	if domain := method.Property("header.d", "d"); domain != "" {
		result.Domain = &domain
	}

	// The selector, which Google does not always name.
	if selector := method.Property("header.s", "s"); selector != "" {
		result.Selector = &selector
	}

	return result
}

func (a *AuthenticationAnalyzer) calculateXGoogleDKIMScore(results *model.AuthenticationResults) (score int) {
	if results.XGoogleDkim != nil {
		switch results.XGoogleDkim.Result {
		case model.AuthResultResultPass:
			// pass: don't alter the score
		default: // fail
			return -100
		}
	}

	return 0
}
