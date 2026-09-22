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
package ipinfo

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// stubSource answers the same thing whatever the address.
type stubSource struct {
	origin *Origin
	err    error
}

func (s stubSource) Lookup(context.Context, netip.Addr) (*Origin, error) {
	return s.origin, s.err
}

func TestChainLookup(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	asnOnly := &Origin{ASN: 64496, ASName: "Example Networks", Source: "maxmind"}
	registry := &Origin{ASN: 64497, ASName: "EXAMPLE-AS", Prefix: "192.0.2.0/24", Country: "FR", CountrySource: "cymru", Registry: "ripencc", Source: "cymru"}

	tests := []struct {
		name    string
		chain   Chain
		want    *Origin
		wantErr bool
	}{
		{
			// The operator's ASN-only database gives the network, the
			// registry service the country. The country then says it came
			// from the registry, whatever answered the rest: the two do not
			// mean the same thing to a reader.
			name:  "first answer completed by the second",
			chain: Chain{stubSource{origin: asnOnly}, stubSource{origin: registry}},
			want:  &Origin{ASN: 64496, ASName: "Example Networks", Prefix: "192.0.2.0/24", Country: "FR", CountrySource: "cymru", Registry: "ripencc", Source: "maxmind"},
		},
		{
			name:  "a failing source is skipped",
			chain: Chain{stubSource{err: errors.New("down")}, stubSource{origin: registry}},
			want:  registry,
		},
		{
			name:  "a silent source is skipped",
			chain: Chain{stubSource{}, stubSource{origin: registry}},
			want:  registry,
		},
		{
			name:  "nobody knows",
			chain: Chain{stubSource{}, stubSource{}},
			want:  nil,
		},
		{
			name:    "everybody failed",
			chain:   Chain{stubSource{err: errors.New("down")}},
			wantErr: true,
		},
		{
			name:  "empty chain",
			chain: Chain{},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The chain writes into the first origin it gets, so each case
			// gets copies of its own.
			for i, s := range tt.chain {
				if stub, ok := s.(stubSource); ok && stub.origin != nil {
					origin := *stub.origin
					tt.chain[i] = stubSource{origin: &origin}
				}
			}

			got, err := tt.chain.Lookup(context.Background(), ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Lookup() error = %v, wantErr %v", err, tt.wantErr)
			}
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("Lookup() = %+v, want nil", *got)
			case tt.want != nil && got == nil:
				t.Fatalf("Lookup() = nil, want %+v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("Lookup() = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

// TestChainSkipsUnconfiguredSource covers what the wiring hands a Chain: a
// source an operator did not configure answers nil rather than being left
// out of the list, and must not take the chain down with it.
func TestChainSkipsUnconfiguredSource(t *testing.T) {
	want := &Origin{ASN: 64496, Source: "cymru"}
	chain := Chain{nil, stubSource{origin: want}}

	got, err := chain.Lookup(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got == nil || *got != *want {
		t.Errorf("Lookup() = %+v, want %+v", got, *want)
	}
}
