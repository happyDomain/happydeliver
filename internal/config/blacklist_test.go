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

package config

import (
	"testing"

	blacklist "git.happydns.org/checker-blacklist/checker"
)

// TestAsCheckerOptionsKeysAreDeclared pins every option key against the IDs
// the checker-blacklist sources actually declare. A key that matches nothing
// fails silently in production: stringOpt returns "", the source takes itself
// out on a missing credential, and the operator sees a configured flag with no
// effect. That is how "safebrowsing_api_key" went unnoticed against the
// declared "google_safe_browsing_api_key".
func TestAsCheckerOptionsKeysAreDeclared(t *testing.T) {
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

	// Every field set, so every branch of AsCheckerOptions is taken.
	opts := BlacklistConfig{
		VirusTotalAPIKey:   "vt-key",
		SafeBrowsingAPIKey: "sb-key",
	}.AsCheckerOptions()

	if len(opts) == 0 {
		t.Fatal("AsCheckerOptions returned no option for a fully populated config")
	}
	for key := range opts {
		if !declared[key] {
			t.Errorf("AsCheckerOptions emits %q, which no checker-blacklist source declares", key)
		}
	}
}

func TestAsCheckerOptionsOmitsEmptyCredentials(t *testing.T) {
	if opts := (BlacklistConfig{}).AsCheckerOptions(); len(opts) != 0 {
		t.Errorf("AsCheckerOptions on a zero config = %v, want no option: an empty key makes a source fail instead of staying disabled", opts)
	}
}
