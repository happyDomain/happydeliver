// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

// parseXPtrResult parses the x-ptr result from Authentication-Results.
// Example: x-ptr=fail smtp.helo=relay.example.org policy.ptr=mail.example.com
func (a *AuthenticationAnalyzer) parseXPtrResult(method authresults.Method) *model.XPtrResult {
	result := &model.XPtrResult{
		Result:  model.XPtrResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	if helo := method.Property("smtp.helo"); helo != "" {
		result.Helo = &helo
	}
	if name := method.Property("policy.ptr"); name != "" {
		result.Ptr = &name
	}

	return result
}
