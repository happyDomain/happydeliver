// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

// Package netguard tells the addresses happyDeliver may connect to, or count
// on others to connect to, from those that are not reachable on the public
// Internet.
package netguard

import (
	"net"
	"net/netip"
)

// nonPublicNets lists the ranges that are not routable on the public Internet
// and that the net.IP predicates used by IsPublic do not report.
var nonPublicNets = mustPrefixes(
	"100.64.0.0/10",   // shared address space (CGNAT), RFC 6598
	"192.0.0.0/24",    // IETF protocol assignments, RFC 6890
	"192.0.2.0/24",    // documentation (TEST-NET-1), RFC 5737
	"198.18.0.0/15",   // benchmarking, RFC 2544
	"198.51.100.0/24", // documentation (TEST-NET-2), RFC 5737
	"203.0.113.0/24",  // documentation (TEST-NET-3), RFC 5737
	"240.0.0.0/4",     // reserved, RFC 1112, broadcast included
	"64:ff9b::/96",    // NAT64: the last 32 bits are an arbitrary IPv4 address
	"100::/64",        // discard-only, RFC 6666
	"2001:db8::/32",   // documentation, RFC 3849
	"3fff::/20",       // documentation, RFC 9637
)

func mustPrefixes(prefixes ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// IsPublic reports whether ip is routable on the public Internet: neither
// private, loopback, link-local, multicast, unspecified, nor in one of the
// special-purpose ranges (shared address space, documentation, benchmarking,
// reserved). An address that does not parse is not public.
func IsPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range nonPublicNets {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// IsPublicString is IsPublic on an address written out.
func IsPublicString(s string) bool {
	return IsPublic(net.ParseIP(s))
}
