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

// Package disposable answers whether a domain belongs to a known disposable
// (throwaway) email provider, from the list maintained by Martin and
// contributors.
package disposable

import (
	_ "embed"
	"sync"

	"git.happydns.org/happyDeliver/pkg/emaildata/domainset"
)

// list is the disposable_email_blocklist.conf of
// https://github.com/disposable-email-domains/disposable-email-domains,
// embedded verbatim and dedicated to the public domain under CC0-1.0. See
// THIRD-PARTY-NOTICES.md, and data/disposable_email_blocklist.LICENSE for the
// dedication text.
//
//go:embed data/disposable_email_blocklist.conf
var list string

// License is the CC0-1.0 text shipped alongside the list.
//
//go:embed data/disposable_email_blocklist.LICENSE
var License string

// Attribution names the list and where it comes from.
const Attribution = `Disposable email domain list
----------------------------

By Martin and contributors
Source:  https://github.com/disposable-email-domains/disposable-email-domains
License: CC0 1.0 Universal (CC0-1.0), a public domain dedication,
         https://creativecommons.org/publicdomain/zero/1.0/
Changes: none, the list is embedded exactly as published upstream.

This material is provided as-is, without warranties, as stated in section 4
of the dedication reproduced below.`

// Hosts is the set of domains the upstream list holds, every entry
// normalised the way the set keys it, and nothing added to or taken from
// what upstream published.
var Hosts = sync.OnceValue(func() domainset.Set { return domainset.FromLines(list) })

// Is answers whether the domain, or a domain it is a subdomain of, is a
// disposable provider: a provider handing out addresses under a subdomain
// of its own is still that provider.
func Is(domain string) bool {
	return Hosts().Has(domain)
}
