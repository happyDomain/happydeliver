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
	"testing"

	blacklist "git.happydns.org/checker-blacklist/checker"

	"git.happydns.org/happyDeliver/pkg/virustotal"
)

// setAllCredentials fills every credential package var, so every branch of
// CheckerOptions is taken. It restores the previous values on cleanup: the
// flags are package state, what a test sets, it puts back.
func setAllCredentials(t *testing.T) {
	t.Helper()
	saved := struct {
		virustotal, safeBrowsing, abuseCh, otx, pulsedive, criminalIP string
	}{virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey}
	t.Cleanup(func() {
		virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey =
			saved.virustotal, saved.safeBrowsing, saved.abuseCh, saved.otx, saved.pulsedive, saved.criminalIP
	})

	virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey =
		"key", "key", "key", "key", "key", "key"
}

// clearAllCredentials empties every credential package var, restoring the
// previous values on cleanup.
func clearAllCredentials(t *testing.T) {
	t.Helper()
	saved := struct {
		virustotal, safeBrowsing, abuseCh, otx, pulsedive, criminalIP string
	}{virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey}
	t.Cleanup(func() {
		virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey =
			saved.virustotal, saved.safeBrowsing, saved.abuseCh, saved.otx, saved.pulsedive, saved.criminalIP
	})

	virustotal.APIKey, SafeBrowsingAPIKey, AbuseChAuthKey, OTXAPIKey, PulsediveAPIKey, CriminalIPAPIKey =
		"", "", "", "", "", ""
}

// TestCheckerOptionsKeysAreDeclared pins every option key against the IDs
// the checker-blacklist sources actually declare. A key that matches nothing
// fails silently in production: stringOpt returns "", the source takes itself
// out on a missing credential, and the operator sees a configured flag with no
// effect. That is how "safebrowsing_api_key" went unnoticed against the
// declared "google_safe_browsing_api_key".
func TestCheckerOptionsKeysAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, src := range blacklist.Sources() {
		o := src.Options()
		for _, f := range o.Admin {
			declared[f.Id] = true
		}
		for _, f := range o.User {
			declared[f.Id] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("no checker-blacklist source declares any option")
	}

	setAllCredentials(t)
	opts := CheckerOptions()

	if len(opts) == 0 {
		t.Fatal("CheckerOptions returned no option with every credential set")
	}
	for key := range opts {
		if !declared[key] {
			t.Errorf("CheckerOptions emits %q, which no checker-blacklist source declares", key)
		}
	}
}

// TestCheckerOptionsCoversEverySecret is the other direction: every
// credential a source declares must have a flag feeding it. Without one the
// source can never be enabled, and a module upgrade adding a keyed source
// would go unnoticed the way URLhaus, ThreatFox, MalwareBazaar, OTX, Pulsedive
// and Criminal IP once did.
func TestCheckerOptionsCoversEverySecret(t *testing.T) {
	setAllCredentials(t)
	opts := CheckerOptions()

	for _, src := range blacklist.Sources() {
		o := src.Options()
		for _, f := range append(o.Admin, o.User...) {
			if !f.Secret {
				continue
			}
			if _, ok := opts[f.Id]; !ok {
				t.Errorf("source %q declares credential %q, which no flag feeds", src.ID(), f.Id)
			}
		}
	}
}

func TestCheckerOptionsOmitsEmptyCredentials(t *testing.T) {
	clearAllCredentials(t)
	if opts := CheckerOptions(); len(opts) != 0 {
		t.Errorf("CheckerOptions with no credential = %v, want no option: an empty key makes a source fail instead of staying disabled", opts)
	}
}
