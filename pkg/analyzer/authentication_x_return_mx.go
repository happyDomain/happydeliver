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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"

	"git.happydns.org/happyDeliver/pkg/authresults"
)

// parseXReturnMXResult parses an x-return-mx result, written by the ReturnOK
// module of authentication_milter, from Authentication-Results.
// Example: x-return-mx=warn header.domain=example.com policy.is_org=yes (A Records found: 192.0.2.1)
func (a *AuthenticationAnalyzer) parseXReturnMXResult(method authresults.Method) *model.XReturnMXResult {
	result := &model.XReturnMXResult{
		Result:  model.XReturnMXResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	if domain := method.Property("smtp.domain"); domain != "" {
		result.Domain = &domain
		result.Identity = utils.PtrTo(model.XReturnMXResultIdentitySmtp)
	} else if domain := method.Property("header.domain"); domain != "" {
		result.Domain = &domain
		result.Identity = utils.PtrTo(model.XReturnMXResultIdentityHeader)
	}
	if org := method.Property("policy.org_domain"); org != "" {
		result.OrgDomain = &org
	}
	if isOrg, written := method.Lookup("policy.is_org"); written {
		result.IsOrg = utils.PtrTo(strings.EqualFold(isOrg, "yes"))
	}

	return result
}
