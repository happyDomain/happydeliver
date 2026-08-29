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

package analyzer

import (
	"net"

	"git.happydns.org/happyDeliver/internal/model"
)

// hopIPClass tells apart the three situations the inbound hop selection has to
// distinguish. Unknown is deliberately not merged with either of the other two:
// a hop we cannot classify must never be skipped as if it were internal.
type hopIPClass int

const (
	// hopIPUnknown is a hop whose Received header carried no address, or one
	// that does not parse as an IP.
	hopIPUnknown hopIPClass = iota

	// hopIPInternal is an address that cannot belong to a sender out on the
	// Internet: RFC 1918 private, loopback, link-local, unspecified, IPv6
	// unique-local, or RFC 6598 shared address space.
	hopIPInternal

	// hopIPPublic is a routable address, i.e. a plausible sending MTA.
	hopIPPublic
)

// classifyHopIP classifies a received hop by the IP address it reports.
func classifyHopIP(hop model.ReceivedHop) hopIPClass {
	if hop.Ip == nil || *hop.Ip == "" {
		return hopIPUnknown
	}

	if net.ParseIP(*hop.Ip) == nil {
		return hopIPUnknown
	}

	if isPublicIPAddr(*hop.Ip) {
		return hopIPPublic
	}

	return hopIPInternal
}

// InboundHop returns the hop of the received chain to use as the message's point
// of entry: the sender IP for FCrDNS scoring, the announced HELO name, and the
// address whose PTR record is checked.
//
// For a message this instance received itself, that is always the topmost hop:
// our own MTA wrote it, so it is the one Received header we can trust.
//
// An uploaded EML is different. Its topmost hop is frequently an internal hop of
// the recipient's own infrastructure (a private-addressed LMTP handoff, say),
// and the real external delivery sits further down the chain. Selecting the
// topmost hop there measures the recipient's internal network instead of the
// sender.
//
// Because every Received header of an uploaded file is attacker-controlled, the
// walk below only recognises one unambiguous shape: one or more contiguous hops
// with an explicitly non-public IP at the top, immediately followed by a hop
// with a public IP. Anything else — a hop with no IP, an unparsable address, a
// fully internal chain — stops the walk and falls back to the topmost hop, the
// historical behaviour. In particular, no hop is ever skipped on the strength of
// its protocol keyword, hostname shape, or domain: all three are trivially
// forged in a file a user hands us.
//
// Returns nil for an empty chain.
func InboundHop(chain []model.ReceivedHop, source model.ReportSource) *model.ReceivedHop {
	if len(chain) == 0 {
		return nil
	}

	if source != model.ReportSourceUploaded {
		return &chain[0]
	}

	for i := range chain {
		switch classifyHopIP(chain[i]) {
		case hopIPInternal:
			// Recipient-side hop: keep descending.
			continue

		case hopIPPublic:
			// First externally-addressed hop below the internal ones. When
			// nothing was skipped this is the topmost hop anyway.
			return &chain[i]

		default:
			// Unclassifiable hop: we cannot tell whether the chain is still
			// internal at this point, so we stop guessing.
			return &chain[0]
		}
	}

	// Every hop was internal: nothing better to offer than the topmost one.
	return &chain[0]
}
