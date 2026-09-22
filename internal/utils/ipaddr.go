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

package utils

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

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

// IsPublicIPAddr reports whether ipStr parses as a routable address. An address
// that does not parse is not public.
func IsPublicIPAddr(ipStr string) bool {
	return IsPublicIP(net.ParseIP(ipStr))
}

// IsPublicIP reports whether ip is a routable address, i.e. neither private,
// loopback, link-local, unspecified, multicast, carrier-grade NAT, nor
// Class-E/reserved. IPv6 unique-local addresses (fc00::/7) are covered by
// net.IP.IsPrivate.
func IsPublicIP(ip net.IP) bool {
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

// ReverseLabels writes an address the way DNS blocklist and IP-to-ASN queries
// key it: octets reversed for IPv4, nibbles reversed for IPv6, least
// significant first and dot separated, with no suffix and no trailing dot.
// Empty for an address that is neither.
func ReverseLabels(ip netip.Addr) string {
	ip = ip.Unmap()

	switch {
	case ip.Is4():
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])

	case ip.Is6():
		b := ip.As16()
		nibbles := make([]string, 0, 32)
		for i := len(b) - 1; i >= 0; i-- {
			nibbles = append(nibbles, strconv.FormatUint(uint64(b[i]&0x0f), 16))
			nibbles = append(nibbles, strconv.FormatUint(uint64(b[i]>>4), 16))
		}
		return strings.Join(nibbles, ".")

	default:
		return ""
	}
}
