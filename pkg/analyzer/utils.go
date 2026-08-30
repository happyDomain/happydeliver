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
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
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

// submatch returns the first capture group of pattern in s, or "".
func submatch(s, pattern string) string {
	if matches := regexp.MustCompile(pattern).FindStringSubmatch(s); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// textprotoCanonical converts a header name to canonical form
func textprotoCanonical(s string) string {
	// Simple implementation - capitalize each word
	words := strings.Split(s, "-")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, "-")
}

// pluralize returns "y" or "ies" based on count
func pluralize(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
}

// normalizeHostname puts a hostname in comparable form: lowercased, trimmed,
// and without the root dot, so that "Mail.Example.Com." and "mail.example.com"
// are recognised as the same host.
func normalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

// getOrganizationalDomain extracts the organizational domain from a fully qualified domain name
// using the Public Suffix List (PSL) to correctly handle multi-level TLDs.
// For example: mail.example.com -> example.com, mail.example.co.uk -> example.co.uk
func getOrganizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Use golang.org/x/net/publicsuffix to get the eTLD+1 (organizational domain)
	// This correctly handles cases like .co.uk, .com.au, etc.
	etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to simple two-label extraction if PSL lookup fails
		labels := strings.Split(domain, ".")
		if len(labels) <= 2 {
			return domain
		}
		return strings.Join(labels[len(labels)-2:], ".")
	}

	return etldPlusOne
}

// orgDomainOrEmpty dereferences an optional organizational domain pointer.
func orgDomainOrEmpty(orgDomain *string) string {
	if orgDomain == nil {
		return ""
	}
	return *orgDomain
}

// cgnatRange is the RFC 6598 shared address space: carrier-grade NAT addresses
// never identify a sending MTA, and no DNS list carries them.
var cgnatRange = net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// classEAndReservedRange is the IPv4 240.0.0.0/4 block: Class E plus the
// reserved-but-unassigned space above it, including the broadcast address
// 255.255.255.255. No sending MTA is ever addressed from it.
var classEAndReservedRange = net.IPNet{
	IP:   net.IPv4(240, 0, 0, 0),
	Mask: net.CIDRMask(4, 32),
}

// isPublicIPAddr reports whether ipStr parses as a routable address. An address
// that does not parse is not public.
func isPublicIPAddr(ipStr string) bool {
	return isPublicIP(net.ParseIP(ipStr))
}

// isPublicIP reports whether ip is a routable address, i.e. neither private,
// loopback, link-local, unspecified, multicast, carrier-grade NAT, nor
// Class-E/reserved. IPv6 unique-local addresses (fc00::/7) are covered by
// net.IP.IsPrivate.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}

	if cgnatRange.Contains(ip) || classEAndReservedRange.Contains(ip) {
		return false
	}

	return true
}
