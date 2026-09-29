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

package reputation

import (
	"flag"

	sdk "git.happydns.org/checker-sdk-go/checker"

	"git.happydns.org/happyDeliver/pkg/virustotal"
)

// Credentials for the checker-blacklist sources that need one. Each is an
// option specific to that source's implementation, so it is declared here
// rather than threaded through internal/config, the same way
// pkg/analyzer/attachment's scanners declare their own flags. The VirusTotal
// key lives in pkg/virustotal instead, shared with attachment hash lookups.
var (
	// SafeBrowsingAPIKey is the Google Safe Browsing API key for the domain
	// blacklist checker.
	SafeBrowsingAPIKey string

	// AbuseChAuthKey is the one Auth-Key an abuse.ch account gets. URLhaus,
	// ThreatFox and MalwareBazaar each declare their own option for it.
	AbuseChAuthKey string

	// OTXAPIKey is the AlienVault OTX API key for the domain blacklist checker.
	OTXAPIKey string

	// PulsediveAPIKey is the Pulsedive API key for the domain blacklist checker.
	PulsediveAPIKey string

	// CriminalIPAPIKey is the Criminal IP API key for the domain blacklist checker.
	CriminalIPAPIKey string
)

func init() {
	flag.StringVar(&SafeBrowsingAPIKey, "blacklist-safebrowsing-api-key", SafeBrowsingAPIKey, "Google Safe Browsing API key for the domain blacklist checker")
	flag.StringVar(&AbuseChAuthKey, "blacklist-abusech-auth-key", AbuseChAuthKey, "abuse.ch Auth-Key for the domain blacklist checker (enables URLhaus, ThreatFox and MalwareBazaar)")
	flag.StringVar(&OTXAPIKey, "blacklist-otx-api-key", OTXAPIKey, "AlienVault OTX API key for the domain blacklist checker")
	flag.StringVar(&PulsediveAPIKey, "blacklist-pulsedive-api-key", PulsediveAPIKey, "Pulsedive API key for the domain blacklist checker")
	flag.StringVar(&CriminalIPAPIKey, "blacklist-criminalip-api-key", CriminalIPAPIKey, "Criminal IP API key for the domain blacklist checker")
}

// CheckerOptions returns the map that checker-blacklist sources read
// via stringOpt(). Empty values are omitted so sources that require a
// credential stay disabled rather than failing with an empty key.
//
// Every key here must be an option ID a source actually declares: a key that
// matches nothing is not an error anywhere, it just leaves the source
// permanently disabled while the flag that feeds it looks configured.
// TestCheckerOptionsKeysAreDeclared checks them against the registry.
func CheckerOptions() sdk.CheckerOptions {
	opts := sdk.CheckerOptions{}
	set := func(key, value string) {
		if value != "" {
			opts[key] = value
		}
	}
	set("virustotal_api_key", virustotal.APIKey)
	set("google_safe_browsing_api_key", SafeBrowsingAPIKey)
	set("urlhaus_auth_key", AbuseChAuthKey)
	set("threatfox_auth_key", AbuseChAuthKey)
	set("malwarebazaar_auth_key", AbuseChAuthKey)
	set("otx_api_key", OTXAPIKey)
	set("pulsedive_api_key", PulsediveAPIKey)
	set("criminal_ip_api_key", CriminalIPAPIKey)
	return opts
}
