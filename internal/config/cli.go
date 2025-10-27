// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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

package config

import (
	"flag"
)

// declareFlags registers flags for the structure Options.
func declareFlags(o *Config) {
	flag.StringVar(&o.DevProxy, "dev", o.DevProxy, "Proxify traffic to this host for static assets")
	flag.StringVar(&o.Bind, "bind", o.Bind, "Bind port/socket")
	flag.StringVar(&o.Database.Type, "database-type", o.Database.Type, "Select the database type between sqlite, postgres")
	flag.StringVar(&o.Database.DSN, "database-dsn", o.Database.DSN, "Database DSN or path")
	flag.StringVar(&o.Email.Domain, "domain", o.Email.Domain, "Domain used to receive emails")
	flag.StringVar(&o.Email.TestAddressPrefix, "address-prefix", o.Email.TestAddressPrefix, "Expected email adress prefix (deny address that doesn't start with this prefix)")
	flag.StringVar(&o.Email.LMTPAddr, "lmtp-addr", o.Email.LMTPAddr, "LMTP server listen address")
	flag.DurationVar(&o.Analysis.DNSTimeout, "dns-timeout", o.Analysis.DNSTimeout, "Timeout when performing DNS query")
	flag.DurationVar(&o.Analysis.HTTPTimeout, "http-timeout", o.Analysis.HTTPTimeout, "Timeout when performing HTTP query")
	flag.Var(&StringArray{&o.Analysis.RBLs}, "rbl", "Append a RBL (use this option multiple time to append multiple RBLs)")
	flag.BoolVar(&o.Analysis.CheckAllIPs, "check-all-ips", o.Analysis.CheckAllIPs, "Check all IPs found in email headers against RBLs (not just the first one)")
	flag.DurationVar(&o.ReportRetention, "report-retention", o.ReportRetention, "How long to keep reports (e.g., 720h, 30d). 0 = keep forever")
	flag.UintVar(&o.RateLimit, "rate-limit", o.RateLimit, "API rate limit (requests per second per IP)")
	flag.Var(&URL{&o.SurveyURL}, "survey-url", "URL for user feedback survey")

	// Others flags are declared in some other files likes sources, storages, ... when they need specials configurations
}

// parseCLI parse the flags and treats extra args as configuration filename.
func parseCLI(o *Config) error {
	flag.Parse()

	return nil
}
