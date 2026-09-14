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

// Package domainname reads the names an email is judged by: the host a machine
// answers to, and the domain a name ultimately belongs to.
//
// Two names that differ may still be the same host, and two hosts that differ
// may still be the same party: "Mail.Example.Com." and "mail.example.com" are
// one machine, and "mail.example.co.uk" and "www.example.co.uk" are one
// organisation. Nearly every reading of a message - who signed it, who sent
// it, where its links lead - turns on one of those two questions, so they are
// answered in one place rather than by each reader in its own way.
package domainname

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Normalize puts a hostname in comparable form: lowercased, trimmed, and
// without the root dot, so that "Mail.Example.Com." and "mail.example.com" are
// recognised as the same host.
func Normalize(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

// Organizational returns the domain a name belongs to, the eTLD+1 the Public
// Suffix List recognises: "mail.example.com" is "example.com", and
// "mail.example.co.uk" is "example.co.uk" rather than the "co.uk" a count of
// labels would give.
//
// A name the list cannot resolve falls back to its last two labels. That is
// wrong for a multi-label suffix the list does not know, and right for
// everything else; the alternative, refusing to answer, would leave the caller
// with nothing to compare.
func Organizational(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))

	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		labels := strings.Split(domain, ".")
		if len(labels) <= 2 {
			return domain
		}
		return strings.Join(labels[len(labels)-2:], ".")
	}

	return etldPlusOne
}
