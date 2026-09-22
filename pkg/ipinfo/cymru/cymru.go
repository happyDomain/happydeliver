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

// Package cymru answers where an address comes from off the Team Cymru
// IP-to-ASN mapping service. It is one implementation of ipinfo.Source, and
// answers the same generic ipinfo.Origin as any other.
package cymru

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// sourceName is how this source signs the origins it answers. It has to
// match the IPOriginSource enum the API schema declares, which
// pkg/analyzer converts it to.
const sourceName = "cymru"

// TXTResolver is what the source needs of a resolver. The analyzer's own
// DNSResolver satisfies it, and so does any test fake.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Client reads the origin of an address off the Team Cymru IP-to-ASN mapping
// service (https://www.team-cymru.com/ip-asn-mapping), which publishes
// routing tables over DNS: one TXT lookup for the address, another for the
// name of the AS it found.
//
// The country it answers is the one the block was allocated in by its
// registry, not where the address is used.
type Client struct {
	resolver TXTResolver
}

// New builds a source over the given resolver.
func New(resolver TXTResolver) *Client {
	return &Client{resolver: resolver}
}

// Lookup asks the service about the address. An address the service has no
// route for answers nil, nil.
func (c *Client) Lookup(ctx context.Context, ip netip.Addr) (*ipinfo.Origin, error) {
	name := cymruOriginName(ip)
	if name == "" {
		return nil, nil
	}

	records, err := c.resolver.LookupTXT(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("origin lookup of %s: %w", ip, err)
	}

	origin := parseCymruOrigin(records)
	if origin == nil {
		return nil, nil
	}

	// The name is a second lookup, and a failure there costs nothing but the
	// name: the AS number alone is already an answer.
	if origin.ASN != 0 {
		if records, err := c.resolver.LookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com.", origin.ASN)); err == nil {
			origin.ASName = parseCymruASName(records)
		}
	}

	return origin, nil
}

// cymruOriginName is the name to ask about an address: its reversed labels
// under origin.asn.cymru.com for IPv4, under origin6.asn.cymru.com for IPv6.
// Empty for an address that is neither.
func cymruOriginName(ip netip.Addr) string {
	labels := utils.ReverseLabels(ip)
	if labels == "" {
		return ""
	}

	if ip.Unmap().Is4() {
		return labels + ".origin.asn.cymru.com."
	}
	return labels + ".origin6.asn.cymru.com."
}

// parseCymruOrigin reads the origin records, each of the form
// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01". Several records mean several
// prefixes cover the address, and the most specific one is the route the
// address actually takes. A record may name several ASes, space separated,
// when a prefix is multi-homed; the first is kept.
func parseCymruOrigin(records []string) *ipinfo.Origin {
	var best *ipinfo.Origin
	bestBits := -1

	for _, record := range records {
		fields := splitCymru(record)
		if len(fields) < 3 {
			continue
		}

		asn, ok := firstASN(fields[0])
		if !ok {
			continue
		}

		origin := &ipinfo.Origin{
			ASN:     asn,
			Prefix:  fields[1],
			Country: fields[2],
			Source:  sourceName,
		}
		if origin.Country != "" {
			origin.CountrySource = sourceName
		}
		if len(fields) > 3 {
			origin.Registry = fields[3]
		}
		if len(fields) > 4 {
			if allocated, err := time.Parse("2006-01-02", fields[4]); err == nil {
				origin.Allocated = &allocated
			}
		}

		// The most specific prefix wins, but a record whose prefix cannot
		// be read still carries an ASN worth reporting: it is kept when
		// nothing better has been seen, rather than dropped.
		bits := -1
		if prefix, err := netip.ParsePrefix(origin.Prefix); err == nil {
			bits = prefix.Bits()
		}
		if best == nil || bits > bestBits {
			best, bestBits = origin, bits
		}
	}

	return best
}

// parseCymruASName reads the name off an AS record of the form
// "15169 | US | arin | 2000-03-30 | GOOGLE, US": the last field, minus the
// country the service appends to it, which the origin record already gave.
func parseCymruASName(records []string) string {
	for _, record := range records {
		fields := splitCymru(record)
		if len(fields) < 5 {
			continue
		}

		name := fields[4]
		if i := strings.LastIndex(name, ","); i >= 0 && len(strings.TrimSpace(name[i+1:])) == 2 {
			name = strings.TrimSpace(name[:i])
		}
		if name != "" {
			return name
		}
	}

	return ""
}

// splitCymru splits a record on its pipes and trims each field.
func splitCymru(record string) []string {
	fields := strings.Split(record, "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields
}

// firstASN reads the first AS number of a field that may hold several.
func firstASN(field string) (uint32, bool) {
	first, _, _ := strings.Cut(field, " ")
	asn, err := strconv.ParseUint(first, 10, 32)
	if err != nil || asn == 0 {
		return 0, false
	}
	return uint32(asn), true
}

// isNotFound tells a name that does not exist from a resolver that could not
// answer.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
