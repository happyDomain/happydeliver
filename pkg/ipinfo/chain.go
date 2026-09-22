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
)

// Chain asks several sources in turn and answers the first origin found,
// completed with what later sources know that it did not: an operator with
// an ASN database but no country one still gets a country, from the
// registry. A source that fails is skipped, and its failure reported only
// when no source answered at all; a nil source is one the operator did not
// configure, and is left out the same way.
type Chain []Source

// Lookup asks each source in order.
func (c Chain) Lookup(ctx context.Context, ip netip.Addr) (*Origin, error) {
	var found *Origin
	var errs []error

	for _, source := range c {
		if source == nil {
			continue
		}

		origin, err := source.Lookup(ctx, ip)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if origin == nil {
			continue
		}

		if found == nil {
			found = origin
			continue
		}

		if found.ASN == 0 {
			found.ASN = origin.ASN
		}
		if found.ASName == "" {
			found.ASName = origin.ASName
		}
		if found.Prefix == "" {
			found.Prefix = origin.Prefix
		}
		if found.Country == "" {
			// The country comes with the name of who answered it: an
			// ASN-only database completed by the registry gives a country
			// that means "where the block was allocated", and saying it came
			// from a geolocation database would be a different claim.
			found.Country = origin.Country
			found.CountryName = origin.CountryName
			found.CountrySource = origin.CountrySource
		}
		if found.Registry == "" {
			found.Registry = origin.Registry
		}
		if found.Allocated == nil {
			found.Allocated = origin.Allocated
		}
	}

	if found == nil && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return found, nil
}
