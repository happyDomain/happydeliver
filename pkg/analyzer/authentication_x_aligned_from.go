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

// parseXAlignedFromResult parses X-Aligned-From result from Authentication-Results
// Example: x-aligned-from=pass (Address match)
func (a *AuthenticationAnalyzer) parseXAlignedFromResult(method authresults.Method) *model.AuthResult {
	return &model.AuthResult{
		Result: model.AuthResultResult(method.Result),

		// Everything after the result, as the receiver worded it.
		Details: utils.PtrTo(methodDetails(method)),
	}
}

func (a *AuthenticationAnalyzer) calculateXAlignedFromScore(results *model.AuthenticationResults) (score int) {
	if results.XAlignedFrom != nil {
		switch results.XAlignedFrom.Result {
		case model.AuthResultResultPass:
			// pass: no impact
			return 0
		case model.AuthResultResultFail:
			// fail: negative contribution
			return -100
		default:
			// neutral, none, etc.: no impact
			return 0
		}
	}

	return 0
}
