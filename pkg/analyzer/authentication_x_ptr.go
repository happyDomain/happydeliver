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
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// parseXPtrResult parses the x-ptr result from Authentication-Results.
// Example: x-ptr=fail smtp.helo=relay.example.org policy.ptr=mail.example.com
func (a *AuthenticationAnalyzer) parseXPtrResult(part string) *model.XPtrResult {
	result := &model.XPtrResult{}

	// Extract result (pass, fail, none, temperror, permerror)
	re := regexp.MustCompile(`x-ptr=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = model.XPtrResultResult(resultStr)
	}

	// Extract announced HELO hostname (smtp.helo)
	heloRe := regexp.MustCompile(`smtp\.helo=([^\s;()]+)`)
	if matches := heloRe.FindStringSubmatch(part); len(matches) > 1 {
		helo := matches[1]
		result.Helo = &helo
	}

	// Extract reverse DNS hostname (policy.ptr)
	ptrRe := regexp.MustCompile(`policy\.ptr=([^\s;()]+)`)
	if matches := ptrRe.FindStringSubmatch(part); len(matches) > 1 {
		ptr := matches[1]
		result.Ptr = &ptr
	}

	result.Details = utils.PtrTo(strings.TrimPrefix(part, "x-ptr="))

	return result
}
