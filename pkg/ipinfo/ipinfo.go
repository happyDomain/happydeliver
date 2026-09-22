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

// Package ipinfo answers where an address comes from: the autonomous system
// announcing it and the country it is registered or located in.
//
// It states facts and judges none of them. Whether a sender's network is
// worth remarking on is the analysis's business; what this package settles
// is how the fact is obtained, and from whom: the Team Cymru DNS service when
// nothing else is configured, and MaxMind databases when an operator has
// them.
package ipinfo

import (
	"context"
	"net/netip"
	"time"
)

// Origin is what is known of the network an address belongs to. Every field
// but Source may be empty: a source answers what it knows, and what it does
// not know is left blank rather than guessed.
type Origin struct {
	// ASN is the autonomous system announcing the address, or zero when no
	// source knew it.
	ASN uint32

	// ASName is the name the AS is registered under.
	ASName string

	// Prefix is the BGP prefix the address is announced within, when the
	// source reads routing tables.
	Prefix string

	// Country is the ISO 3166-1 alpha-2 code of the country the address is
	// tied to. What that means depends on CountrySource: a registry answers
	// where the block was allocated, a geolocation database where the
	// address is believed to be used.
	Country string

	// CountrySource names who answered Country, which need not be Source: a
	// chain may complete an ASN-only database with a registry's country.
	// Empty when no source knew a country.
	CountrySource string

	// CountryName spells Country out, when the source provides it.
	CountryName string

	// Registry is the regional Internet registry the block was allocated by,
	// when the source is a registry itself.
	Registry string

	// Allocated is when the block was allocated, when the source knows it.
	Allocated *time.Time

	// Source names who gave the network answer the origin is built on. A
	// field whose meaning depends on who answered says so itself, as
	// Country does with CountrySource.
	Source string
}

// Source is anything that can say where an address comes from.
type Source interface {
	// Lookup answers what the source knows of the address. A nil Origin with
	// a nil error means the source knows nothing of it, which is an answer,
	// not a failure: an address nobody announces has no origin to report.
	Lookup(ctx context.Context, ip netip.Addr) (*Origin, error)
}
