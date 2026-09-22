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

// Package freemail answers whether a domain belongs to a known free mailbox
// provider, from the list maintained by Kiko Beats and contributors.
package freemail

import (
	_ "embed"
	"encoding/json"
	"log"
	"sync"

	"git.happydns.org/happyDeliver/pkg/emaildata/domainset"
)

// list is the domains.json of https://github.com/Kikobeats/free-email-domains,
// embedded verbatim and licensed MIT. See THIRD-PARTY-NOTICES.md, and
// data/free-email-domains.LICENSE for the license text.
//
//go:embed data/free-email-domains.json
var list []byte

// License is the MIT license text shipped alongside the list.
//
//go:embed data/free-email-domains.LICENSE
var License string

// Attribution is the credit the MIT license asks to be kept with the work.
const Attribution = `Free mailbox provider domain list
---------------------------------

Copyright (c) 2017 Kiko Beats and contributors
Source:  https://github.com/Kikobeats/free-email-domains
License: MIT, reproduced below
Changes: none, the list is embedded exactly as published upstream.

This material is provided as-is, without warranties, as stated in the
license reproduced below.`

// Hosts is the set of domains the upstream list holds, every entry
// normalised the way the set keys it, and nothing added to or taken from
// what upstream published.
var Hosts = sync.OnceValue(loadHosts)

// loadHosts reads the embedded list, a JSON array of domains.
func loadHosts() domainset.Set {
	var domains []string
	if err := json.Unmarshal(list, &domains); err != nil {
		// The list is embedded at build time; a malformed one is a broken
		// build, not something an analysis can answer for.
		log.Printf("freemail: the embedded list cannot be read: %v", err)
		return domainset.Set{}
	}

	return domainset.FromSlice(domains)
}

// notMailboxProviders are domains the upstream list carries that are not
// places anyone may open a mailbox. They are sending infrastructure: an ESP
// signs its bounce addresses with them, so a Return-Path under one is the
// normal envelope of mail sent through that provider, not a sender mailing
// from a public mailbox service. Reporting them as such tells the operator
// to move off a domain their own ESP chose for them.
//
// The upstream list is embedded exactly as published, so the correction
// lives here rather than in the data.
var notMailboxProviders = sync.OnceValue(func() domainset.Set {
	return domainset.FromSlice([]string{
		"amazonses.com", // Amazon SES default MAIL FROM
	})
})

// Is answers whether the domain, or a domain it is a subdomain of, is a free
// mailbox provider.
func Is(domain string) bool {
	if notMailboxProviders().Has(domain) {
		return false
	}

	return Hosts().Has(domain)
}
