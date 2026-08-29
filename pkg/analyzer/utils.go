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

// This file gathers the small helpers the analyzers share: they carry no
// knowledge of any one check, only of the shapes an email or a DNS answer comes
// in. A helper belongs here once it is generic enough that its home file no
// longer explains it.

package analyzer

import (
	"regexp"
	"strconv"
	"strings"
)

// parseFloat32 parses a header field as a float32, reporting whether it held a
// number.
func parseFloat32(s string) (float32, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return float32(v), true
}

// extractFloatField parses re's first capture group in header as a float32.
func extractFloatField(header string, re *regexp.Regexp) (float32, bool) {
	matches := re.FindStringSubmatch(header)
	if len(matches) < 2 {
		return 0, false
	}
	return parseFloat32(matches[1])
}
