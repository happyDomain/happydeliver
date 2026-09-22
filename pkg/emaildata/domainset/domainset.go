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

// Package domainset is a set of domains shared by the embedded domain lists,
// matching a domain or any of its subdomains.
package domainset

import (
	"strings"

	"git.happydns.org/happyDeliver/pkg/domainname"
)

// Set is a set of domains, keyed the way domainname.Normalize writes one.
type Set map[string]struct{}

// FromLines reads a line-oriented list, one domain a line, skipping blank
// lines and the comment header a published list carries.
func FromLines(list string) Set {
	set := make(Set, strings.Count(list, "\n"))

	for line := range strings.Lines(list) {
		if domain := domainname.Normalize(line); domain != "" && !strings.HasPrefix(domain, "#") {
			set[domain] = struct{}{}
		}
	}

	return set
}

// FromSlice reads a list already parsed into domains.
func FromSlice(domains []string) Set {
	set := make(Set, len(domains))

	for _, domain := range domains {
		if domain := domainname.Normalize(domain); domain != "" {
			set[domain] = struct{}{}
		}
	}

	return set
}

// Has answers whether the domain, or a domain it is a subdomain of, is in
// the set.
func (s Set) Has(domain string) bool {
	domain = domainname.Normalize(domain)

	for domain != "" {
		if _, ok := s[domain]; ok {
			return true
		}

		_, parent, found := strings.Cut(domain, ".")
		if !found {
			return false
		}
		domain = parent
	}

	return false
}
