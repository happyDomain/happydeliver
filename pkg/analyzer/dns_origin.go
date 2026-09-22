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
	"context"
	"log"
	"net/netip"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// checkSenderOrigin asks where the sending address comes from. It answers
// nil for an address nobody announces, for one that is not public (a private
// address has no origin worth asking about), and when the source could not
// answer: a network being unreachable says nothing about the sender, and the
// report shows nothing rather than a guess.
func (d *DNSAnalyzer) checkSenderOrigin(senderIP string) *model.IPOrigin {
	if d.ipOrigin == nil || !utils.IsPublicIPAddr(senderIP) {
		return nil
	}

	ip, err := netip.ParseAddr(senderIP)
	if err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	origin, err := d.ipOrigin.Lookup(ctx, ip)
	if err != nil {
		log.Printf("origin of %s could not be read: %v", senderIP, err)
		return nil
	}
	if origin == nil {
		return nil
	}

	return originToModel(origin)
}

// originToModel carries an origin into the report, leaving out what the
// source did not know.
func originToModel(origin *ipinfo.Origin) *model.IPOrigin {
	return &model.IPOrigin{
		Source:        model.IPOriginSource(origin.Source),
		Asn:           utils.PtrToNonZero(int64(origin.ASN)),
		AsName:        utils.PtrToNonZero(origin.ASName),
		Prefix:        utils.PtrToNonZero(origin.Prefix),
		Country:       utils.PtrToNonZero(origin.Country),
		CountryName:   utils.PtrToNonZero(origin.CountryName),
		CountrySource: utils.PtrToNonZero(model.IPOriginSource(origin.CountrySource)),
		Registry:      utils.PtrToNonZero(origin.Registry),
		Allocated:     origin.Allocated,
	}
}
