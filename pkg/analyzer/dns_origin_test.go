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
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

func TestPopulateInboundHopResultsSenderOrigin(t *testing.T) {
	d := newMockAnalyzer(map[string][]string{
		"1.2.0.192.origin.asn.cymru.com": {"64496 | 192.0.2.0/24 | FR | ripencc | 2001-05-04"},
		"AS64496.asn.cymru.com":          {"64496 | FR | ripencc | 2001-05-04 | EXAMPLE-AS, FR"},
	}, nil)

	tests := []struct {
		name string
		ip   string
		want *model.IPOrigin
	}{
		{
			name: "announced address",
			ip:   "192.0.2.1",
			want: &model.IPOrigin{
				Asn:      utils.PtrTo(int64(64496)),
				AsName:   utils.PtrTo("EXAMPLE-AS"),
				Prefix:   utils.PtrTo("192.0.2.0/24"),
				Country:  utils.PtrTo("FR"),
				Registry: utils.PtrTo("ripencc"),
				Source:   model.IPOriginSourceCymru,
			},
		},
		{
			name: "address nobody announces",
			ip:   "203.0.113.1",
		},
		{
			name: "private address is not asked about",
			ip:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.DNSResults{}
			d.populateInboundHopResults(results, &model.ReceivedHop{Ip: utils.PtrTo(tt.ip)})

			got := results.SenderOrigin
			if tt.want == nil {
				if got != nil {
					t.Fatalf("SenderOrigin = %+v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("SenderOrigin = nil, want %+v", *tt.want)
			}
			if got.Allocated == nil {
				t.Error("SenderOrigin.Allocated = nil, want the allocation date")
			}

			// A source signs its origins with a plain string, which the
			// schema only knows as an enum member: a source added or renamed
			// without the schema following would reach the API as a value no
			// client can read.
			if !got.Source.Valid() {
				t.Errorf("SenderOrigin.Source = %q, which the IPOriginSource enum does not declare", got.Source)
			}
			if got.CountrySource != nil && !got.CountrySource.Valid() {
				t.Errorf("SenderOrigin.CountrySource = %q, which the IPOriginSource enum does not declare", *got.CountrySource)
			}
			got.Allocated = nil
			if utils.Deref(got.Asn) != *tt.want.Asn || utils.Deref(got.AsName) != *tt.want.AsName ||
				utils.Deref(got.Prefix) != *tt.want.Prefix || utils.Deref(got.Country) != *tt.want.Country ||
				utils.Deref(got.Registry) != *tt.want.Registry || got.Source != tt.want.Source ||
				got.CountryName != nil {
				t.Errorf("SenderOrigin = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func TestOriginToModelLeavesUnknownOut(t *testing.T) {
	got := originToModel(&ipinfo.Origin{Source: "cymru", Country: "DE", CountryName: "Germany"})
	if got.CountrySource != nil {
		t.Errorf("originToModel() named a country source the origin had none of: %v", *got.CountrySource)
	}
	if got.Asn != nil || got.AsName != nil || got.Prefix != nil || got.Registry != nil || got.Allocated != nil {
		t.Errorf("originToModel() filled fields the source did not know: %+v", *got)
	}
	if utils.Deref(got.Country) != "DE" || utils.Deref(got.CountryName) != "Germany" || got.Source != model.IPOriginSourceCymru {
		t.Errorf("originToModel() = %+v", *got)
	}
}
