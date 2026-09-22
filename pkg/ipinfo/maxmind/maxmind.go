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
// Package maxmind answers where an address comes from off MaxMind databases
// the operator keeps. It is one implementation of ipinfo.Source, and answers
// the same generic ipinfo.Origin as any other.
package maxmind

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"

	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// sourceName is how this source signs the origins it answers. It has to
// match the IPOriginSource enum the API schema declares, which pkg/analyzer
// converts it to.
const sourceName = "maxmind"

// Client reads the origin of an address off MaxMind databases the operator
// keeps up to date: GeoLite2-ASN or GeoIP2-ISP for the autonomous system,
// GeoLite2-Country, GeoIP2-Country or either City edition for the country.
// Either may be left out, and the source then answers only half.
//
// The country it answers is where the address is believed to be used, which
// is what a geolocation database is for, and not where the block was
// allocated.
type Client struct {
	asn     mmdb
	country mmdb
}

// mmdb is what this source needs of a database: look an address up and
// decode what is stored for it. It is an interface so that the decoding can
// be tested without a database file in the repository.
type mmdb interface {
	lookup(ip netip.Addr, v any) (found bool, err error)
	Close() error
}

// reader is a database file.
type reader struct{ *maxminddb.Reader }

func (r reader) lookup(ip netip.Addr, v any) (bool, error) {
	result := r.Lookup(ip)
	if err := result.Err(); err != nil {
		return false, err
	}
	if !result.Found() {
		return false, nil
	}
	return true, result.Decode(v)
}

// asnRecord is what an ASN database stores for a network.
type asnRecord struct {
	Number       uint32 `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
}

// countryRecord is what a Country or City database stores for a network.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// New opens the named databases. An empty path leaves that half of
// the answer to another source; a path that cannot be opened is an error,
// because an operator who named a file expects it to be read.
func New(asnPath, countryPath string) (*Client, error) {
	if asnPath == "" && countryPath == "" {
		return nil, errors.New("no MaxMind database named")
	}

	m := &Client{}

	if asnPath != "" {
		db, err := maxminddb.Open(asnPath)
		if err != nil {
			return nil, fmt.Errorf("opening ASN database %s: %w", asnPath, err)
		}
		m.asn = reader{db}
	}

	if countryPath != "" {
		db, err := maxminddb.Open(countryPath)
		if err != nil {
			if m.asn != nil {
				m.asn.Close()
			}
			return nil, fmt.Errorf("opening country database %s: %w", countryPath, err)
		}
		m.country = reader{db}
	}

	return m, nil
}

// Close releases the databases.
func (m *Client) Close() error {
	var errs []error
	for _, db := range []mmdb{m.asn, m.country} {
		if db != nil {
			errs = append(errs, db.Close())
		}
	}
	return errors.Join(errs...)
}

// Lookup reads what the databases hold for the address. An address neither
// database knows answers nil, nil.
func (m *Client) Lookup(_ context.Context, ip netip.Addr) (*ipinfo.Origin, error) {
	ip = ip.Unmap()
	origin := &ipinfo.Origin{Source: sourceName}
	known := false

	if m.asn != nil {
		var record asnRecord
		found, err := m.asn.lookup(ip, &record)
		if err != nil {
			return nil, fmt.Errorf("ASN lookup of %s: %w", ip, err)
		}
		if found && record.Number != 0 {
			origin.ASN = record.Number
			origin.ASName = record.Organization
			known = true
		}
	}

	if m.country != nil {
		var record countryRecord
		found, err := m.country.lookup(ip, &record)
		if err != nil {
			return nil, fmt.Errorf("country lookup of %s: %w", ip, err)
		}
		if found && record.Country.ISOCode != "" {
			origin.Country = record.Country.ISOCode
			origin.CountryName = record.Country.Names["en"]
			origin.CountrySource = sourceName
			known = true
		}
	}

	if !known {
		return nil, nil
	}

	return origin, nil
}
