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
	"flag"
	"log"
	"sync"

	"git.happydns.org/happyDeliver/pkg/ipinfo"
)

// Options is what an operator decides about where addresses are looked up.
type Options struct {
	// ASNDB is the path of a MaxMind ASN database (GeoLite2-ASN, GeoIP2-ISP).
	// Empty leaves the autonomous system to the registry service.
	ASNDB string

	// CountryDB is the path of a MaxMind Country or City database. Empty
	// leaves the country to the registry service, which then answers where
	// the block was allocated rather than where the address is used.
	CountryDB string
}

// Settings is what the operator decided, read off the command line, the
// environment or the configuration file.
var Settings Options

func init() {
	flag.StringVar(&Settings.ASNDB, "geoip-asn-db", Settings.ASNDB, "MaxMind ASN database (GeoLite2-ASN.mmdb) to read the sender's network from (default: Team Cymru DNS service)")
	flag.StringVar(&Settings.CountryDB, "geoip-country-db", Settings.CountryDB, "MaxMind Country or City database (GeoLite2-Country.mmdb) to read the sender's country from (default: registry country from the Team Cymru DNS service)")
}

// Configured opens the databases Settings names, once for the whole process:
// a database is a file mapped in memory, and every analyzer shares it. It
// answers nil when the operator named none, which a Chain leaves out.
var Configured = sync.OnceValue(func() ipinfo.Source {
	if Settings.ASNDB == "" && Settings.CountryDB == "" {
		return nil
	}

	m, err := New(Settings.ASNDB, Settings.CountryDB)
	if err != nil {
		// An operator who named a file expects it to be read, so the failure
		// is said out loud; the analysis then falls back on the registry
		// rather than on nothing.
		log.Printf("ipinfo/maxmind: %v; falling back on the Team Cymru service", err)
		return nil
	}

	return m
})
