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

// Package shorteners holds the list of public URL shortening services, as
// published by PeterDave Hello and contributors.
//
// It answers one question, and only about the upstream list: is this host a
// shortening service. Which hosts happyDeliver adds to the list, and which
// branded short links it refuses to count as hiding anything, are a judgement
// about email and live with the check that makes it.
package shorteners

import (
	_ "embed"
	"strings"
	"sync"
)

// list is the url-shorteners list by PeterDave Hello and contributors
// (https://github.com/PeterDaveHello/url-shorteners), embedded verbatim and
// licensed CC-BY-SA-4.0. See THIRD-PARTY-NOTICES.md, and
// data/url-shorteners.LICENSE for the license text.
//
//go:embed data/url-shorteners.list
var list string

// Hosts is the set of shortening services the upstream list holds, every entry
// normalised the way NormalizeHost reads a host, and nothing added to or taken
// from what upstream published.
var Hosts = sync.OnceValue(loadHosts)

// loadHosts reads the embedded list, one host a line.
func loadHosts() map[string]struct{} {
	hosts := make(map[string]struct{}, strings.Count(list, "\n"))

	for line := range strings.Lines(list) {
		host := NormalizeHost(line)
		// Skip blank lines and the license/attribution comment header
		if host == "" || strings.HasPrefix(host, "#") {
			continue
		}
		hosts[host] = struct{}{}
	}

	return hosts
}

// NormalizeHost writes a host the way the set keys it: lowercase, unpadded, and
// without the "www." a shortened link never needs but sometimes carries.
func NormalizeHost(host string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "www.")
}
