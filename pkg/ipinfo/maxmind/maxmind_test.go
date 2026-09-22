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
package maxmind

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// fakeDB answers the records it was given, keyed by address.
type fakeDB struct {
	asn     map[string]asnRecord
	country map[string]countryRecord
	err     error
}

func (f *fakeDB) lookup(ip netip.Addr, v any) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	switch record := v.(type) {
	case *asnRecord:
		r, ok := f.asn[ip.String()]
		*record = r
		return ok, nil
	case *countryRecord:
		r, ok := f.country[ip.String()]
		*record = r
		return ok, nil
	}
	return false, nil
}

func (f *fakeDB) Close() error { return nil }

func TestMaxMindLookup(t *testing.T) {
	asn := &fakeDB{asn: map[string]asnRecord{
		"192.0.2.1": {Number: 64496, Organization: "Example Networks"},
	}}
	var country countryRecord
	country.Country.ISOCode = "FR"
	country.Country.Names = map[string]string{"en": "France", "fr": "France"}
	countries := &fakeDB{country: map[string]countryRecord{
		"192.0.2.1": country,
		"192.0.2.2": country,
	}}

	tests := []struct {
		name string
		m    *Client
		ip   string
		want *ipinfo.Origin
	}{
		{
			name: "both databases",
			m:    &Client{asn: asn, country: countries},
			ip:   "192.0.2.1",
			want: &ipinfo.Origin{ASN: 64496, ASName: "Example Networks", Country: "FR", CountryName: "France", CountrySource: sourceName, Source: sourceName},
		},
		{
			name: "country only",
			m:    &Client{asn: asn, country: countries},
			ip:   "192.0.2.2",
			want: &ipinfo.Origin{Country: "FR", CountryName: "France", CountrySource: sourceName, Source: sourceName},
		},
		{
			name: "ASN database alone",
			m:    &Client{asn: asn},
			ip:   "192.0.2.1",
			want: &ipinfo.Origin{ASN: 64496, ASName: "Example Networks", Source: sourceName},
		},
		{
			name: "unknown address",
			m:    &Client{asn: asn, country: countries},
			ip:   "203.0.113.1",
			want: nil,
		},
		{
			name: "mapped IPv4 is unmapped first",
			m:    &Client{asn: asn},
			ip:   "::ffff:192.0.2.1",
			want: &ipinfo.Origin{ASN: 64496, ASName: "Example Networks", Source: sourceName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.Lookup(context.Background(), netip.MustParseAddr(tt.ip))
			if err != nil {
				t.Fatalf("Lookup(%s) error = %v", tt.ip, err)
			}
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("Lookup(%s) = %+v, want nil", tt.ip, *got)
			case tt.want != nil && got == nil:
				t.Fatalf("Lookup(%s) = nil, want %+v", tt.ip, *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("Lookup(%s) = %+v, want %+v", tt.ip, *got, *tt.want)
			}
		})
	}

	t.Run("database failure", func(t *testing.T) {
		m := &Client{asn: &fakeDB{err: errors.New("corrupt")}}
		if _, err := m.Lookup(context.Background(), netip.MustParseAddr("192.0.2.1")); err == nil {
			t.Fatal("Lookup() error = nil, want a failure")
		}
	})
}

func TestNew(t *testing.T) {
	if _, err := New("", ""); err == nil {
		t.Error("New(\"\", \"\") error = nil, want one")
	}
	if _, err := New("/nonexistent/GeoLite2-ASN.mmdb", ""); err == nil {
		t.Error("New(missing file) error = nil, want one")
	}
}
