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

package content

import (
	"slices"

	"git.happydns.org/happyDeliver/pkg/domainname"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// senderDomains lists the organizational domains a message is sent under: the
// From: header its reader sees, the Return-Path its bounces go back to, and
// every domain a DKIM-Signature header claims to sign for. Each is reported
// once, in that order, and the list is empty for a message naming none.
//
// The d= domains are taken as they are written, unverified: the content
// analysis does not see the verdicts of the authentication one. That widens
// the identity a message is read against, which can only silence a finding
// about its destinations, never invent one, and is the safe direction for a
// signal nobody is charged for.
func senderDomains(email *mailmsg.Message) []string {
	if email == nil {
		return nil
	}

	var domains []string
	add := func(domain string) {
		if domain = domainname.Organizational(domain); domain == "" {
			return
		} else if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}

	if email.From != nil {
		add(mailmsg.AddressDomain(email.From.Address))
	} else {
		add(mailmsg.AddressDomain(email.GetHeaderValue("From")))
	}

	add(mailmsg.AddressDomain(email.ReturnPath))

	for _, signature := range email.DKIMSignatures() {
		add(signature.Domain)
	}

	return domains
}

// destinationDomains lists the organizational domains the links of the body
// lead to, once each and in the order they were found.
//
// A link is read at the end of its redirections, so a message whose links are
// rewritten through a click tracker is read on where the recipient actually
// lands rather than on the tracker that forwards them there. A URL that names
// no domain — a mailto:, an address literal, a placeholder never substituted —
// is left out: nothing about a registrable domain can be said of it.
//
// Only the body links are read. An image source and the address of the
// List-Unsubscribe header are destinations of another kind, which the sender
// is not to answer for here: the first is a matter of hosting, the second sits
// with the provider handling the unsubscribe.
func (r *Results) destinationDomains() []string {
	var domains []string

	for _, probed := range r.probedURLs() {
		if probed.Role != urlRoleLink {
			continue
		}

		domain := domainname.OrganizationalOfURL(probed.destination())
		if domain != "" && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}

	return domains
}
