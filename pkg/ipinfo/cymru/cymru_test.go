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

package cymru

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// fakeResolver answers the TXT records it was given, and "no such host" for
// any other name.
type fakeResolver struct {
	txt map[string][]string
	err map[string]error
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	key := strings.TrimSuffix(name, ".")
	if err, ok := f.err[key]; ok {
		return nil, err
	}
	if records, ok := f.txt[key]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestCymruOriginName(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.0.2.1", "1.2.0.192.origin.asn.cymru.com."},
		{"::ffff:192.0.2.1", "1.2.0.192.origin.asn.cymru.com."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com."},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := cymruOriginName(netip.MustParseAddr(tt.ip))
			if got != tt.want {
				t.Errorf("cymruOriginName(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}

	if got := cymruOriginName(netip.Addr{}); got != "" {
		t.Errorf("cymruOriginName(zero) = %q, want empty", got)
	}
}

func TestCymruLookup(t *testing.T) {
	resolver := &fakeResolver{
		txt: map[string][]string{
			"1.2.0.192.origin.asn.cymru.com": {"64496 | 192.0.2.0/24 | FR | ripencc | 2001-05-04"},
			"AS64496.asn.cymru.com":          {"64496 | FR | ripencc | 2001-05-04 | EXAMPLE-AS Example Networks, FR"},

			// Two prefixes cover the address; the /24 is the route taken.
			"2.2.51.198.origin.asn.cymru.com": {
				"64497 | 198.51.0.0/16 | US | arin | 1999-01-01",
				"64498 64499 | 198.51.2.0/24 | CA | arin | 2005-06-07",
			},

			// A name lookup that answers nothing usable.
			"AS64498.asn.cymru.com": {"garbage"},

			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com": {"64500 | 2001:db8::/32 | DE | ripencc |"},
			"AS64500.asn.cymru.com": {"64500 | DE | ripencc | 2010-01-01 | V6-EXAMPLE, DE"},

			"1.2.0.203.origin.asn.cymru.com": {"not | a | record"},
		},
		err: map[string]error{
			"3.2.0.203.origin.asn.cymru.com": errors.New("timeout"),
		},
	}
	source := New(resolver)

	tests := []struct {
		name    string
		ip      string
		want    *ipinfo.Origin
		wantErr bool
	}{
		{
			name: "single prefix with name",
			ip:   "192.0.2.1",
			want: &ipinfo.Origin{ASN: 64496, ASName: "EXAMPLE-AS Example Networks", Prefix: "192.0.2.0/24", Country: "FR", CountrySource: sourceName, Registry: "ripencc", Source: sourceName},
		},
		{
			name: "most specific prefix and first AS of a multi-homed one",
			ip:   "198.51.2.2",
			want: &ipinfo.Origin{ASN: 64498, Prefix: "198.51.2.0/24", Country: "CA", CountrySource: sourceName, Registry: "arin", Source: sourceName},
		},
		{
			name: "IPv6",
			ip:   "2001:db8::1",
			want: &ipinfo.Origin{ASN: 64500, ASName: "V6-EXAMPLE", Prefix: "2001:db8::/32", Country: "DE", CountrySource: sourceName, Registry: "ripencc", Source: sourceName},
		},
		{
			name: "no route",
			ip:   "203.0.113.9",
			want: nil,
		},
		{
			name: "malformed record",
			ip:   "203.0.2.1",
			want: nil,
		},
		{
			name:    "resolver failure",
			ip:      "203.0.2.3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := source.Lookup(context.Background(), netip.MustParseAddr(tt.ip))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Lookup(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("Lookup(%s) = %+v, want nil", tt.ip, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("Lookup(%s) = nil, want %+v", tt.ip, tt.want)
			}

			// Allocated is checked apart: the fixture dates are compared by
			// their presence rather than repeated in every expectation.
			allocated := got.Allocated
			got.Allocated = nil
			if *got != *tt.want {
				t.Errorf("Lookup(%s) = %+v, want %+v", tt.ip, *got, *tt.want)
			}
			if tt.want.Registry != "" && tt.ip != "2001:db8::1" && allocated == nil {
				t.Errorf("Lookup(%s) lost the allocation date", tt.ip)
			}
		})
	}
}

// TestParseCymruOriginUnreadablePrefix checks a record whose prefix cannot
// be read is still reported: the ASN it carries is what the report shows as
// the sender network, and dropping the only record loses it entirely.
func TestParseCymruOriginUnreadablePrefix(t *testing.T) {
	origin := parseCymruOrigin([]string{"64496 |  | FR | ripencc | 2001-05-04"})
	if origin == nil {
		t.Fatal("parseCymruOrigin(record without a prefix) = nil, want the ASN it carries")
	}
	if origin.ASN != 64496 {
		t.Errorf("ASN = %d, want 64496", origin.ASN)
	}

	// A readable prefix still wins over one that is not, whichever comes first.
	records := []string{"64496 |  | FR | ripencc | 2001-05-04", "64497 | 192.0.2.0/24 | FR | ripencc | 2001-05-04"}
	if origin := parseCymruOrigin(records); origin == nil || origin.ASN != 64497 {
		t.Errorf("parseCymruOrigin(%v) = %v, want the record with a readable prefix", records, origin)
	}
}

func TestParseCymruASName(t *testing.T) {
	tests := []struct {
		record string
		want   string
	}{
		{"15169 | US | arin | 2000-03-30 | GOOGLE, US", "GOOGLE"},
		{"64496 | FR | ripencc | 2001-05-04 | EXAMPLE-AS Example Networks, FR", "EXAMPLE-AS Example Networks"},
		{"64496 | FR | ripencc | 2001-05-04 | Acme, Inc., US", "Acme, Inc."},
		{"64496 | FR | ripencc | 2001-05-04 | Acme, Inc.", "Acme, Inc."},
		{"64496 | FR | ripencc | 2001-05-04 |", ""},
		{"garbage", ""},
	}

	for _, tt := range tests {
		if got := parseCymruASName([]string{tt.record}); got != tt.want {
			t.Errorf("parseCymruASName(%q) = %q, want %q", tt.record, got, tt.want)
		}
	}
}
