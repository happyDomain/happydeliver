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

package analyzer

import (
	"net"

	"git.happydns.org/happyDeliver/internal/model"
)

// InboundHopIndex returns the position in the received chain of the hop the
// message entered through: the one providing the sender IP, the HELO name and
// the address checked for FCrDNS. Returns -1 for an empty chain.
//
// A message received by this instance always uses the topmost hop, written by
// our own MTA and therefore the only trustworthy one.
//
// An uploaded EML may instead open on internal hops of the recipient's
// infrastructure, the external delivery sitting further down. As all its
// headers are attacker-controlled, only one unambiguous shape is recognised:
// contiguous non-public hops followed by a public one. Anything else falls back
// to the topmost hop. Hops are skipped on IP class alone, never on protocol
// keyword, hostname or domain, all trivially forged.
func InboundHopIndex(chain []model.ReceivedHop, source model.ReportSource) int {
	if len(chain) == 0 {
		return -1
	}

	if source != model.ReportSourceUploaded {
		return 0
	}

	for i := range chain {
		if chain[i].Ip == nil {
			break
		}

		// A hop we cannot classify is never skipped as if it were internal: we
		// no longer know where in the chain we stand, so we stop guessing.
		ip := net.ParseIP(*chain[i].Ip)
		if ip == nil {
			break
		}

		// First externally-addressed hop below the internal ones.
		if isPublicIP(ip) {
			return i
		}
	}

	// Unclassifiable hop, or a fully internal chain: nothing better to offer
	// than the topmost hop.
	return 0
}
