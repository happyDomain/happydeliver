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
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Normalize puts a hostname in comparable form: lowercased, trimmed, and
// without the root dot, so that "Mail.Example.Com." and "mail.example.com" are
// recognised as the same host.
func Normalize(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

// ASCII puts a hostname in the one form two of them can be compared in: its
// A-labels, the ASCII spelling every internationalised name has exactly one of.
// "éxample.com" and "xn--xample-9ua.com" are the same host written twice, and
// only this form says so; a message advertising one while linking to the other
// advertises where it goes, and is not to be read as deceiving anybody.
//
// It is also the form the public suffix list is written in, so a host in
// Unicode finds no suffix, and no registrable domain, until it is converted.
//
// A name the IDNA rules reject is returned normalised but unconverted, since
// there is nothing else to return and dropping it would silence the comparison
// rather than settle it: a name no encoder accepts is then as unequal to
// another as it reads.
func ASCII(hostname string) string {
	hostname = Normalize(hostname)

	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return hostname
	}

	return ascii
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
	// In A-labels: the list is written in them, and a host in Unicode has no
	// suffix in it until converted.
	domain = ASCII(domain)

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

// HostOfURL returns the host an http or https URL names, in the form Normalize
// compares hosts under, or an empty string for a URL that names none: another
// scheme (mailto:, tel:, data:), a relative reference, a URL that does not
// parse. An address literal is returned as it stands, being what the URL
// plainly names.
func HostOfURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}

	// Hostname() drops the port and the brackets of an IPv6 literal, which a
	// manual cut at the last colon would slice in half.
	return Normalize(parsed.Hostname())
}

// OrganizationalOfURL returns the organizational domain an http or https URL
// leads to. It is empty whenever the URL designates no such domain: another
// scheme, no host at all, or an address literal, which names a machine rather
// than a domain anybody registered.
func OrganizationalOfURL(rawURL string) string {
	host := HostOfURL(rawURL)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}

	return Organizational(host)
}
