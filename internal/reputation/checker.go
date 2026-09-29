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
	"context"
	"fmt"
	"log"
	"time"

	blacklist "git.happydns.org/checker-blacklist/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/model"
)

// collectTimeout is the ceiling for one full checker-blacklist aggregation.
// The module caps each source at 30s plus a 2s grace (checker/collect.go), so
// the ceiling only binds when those fail to, and a shorter one would cut the
// API sources short. Feed sources never hold it: their downloads run detached
// from the check, and a cold one answers pending after a couple of seconds
// (checker/feedcache.go).
const collectTimeout = 60 * time.Second

// Checker runs the checker-blacklist aggregation against a domain, with the
// credentials of the configuration. It is the one place the provider is
// called from.
type Checker struct {
	provider sdk.ObservationProvider
	cfg      config.BlacklistConfig
}

// NewChecker builds a checker over the provider.
func NewChecker(provider sdk.ObservationProvider, cfg config.BlacklistConfig) *Checker {
	return &Checker{provider: provider, cfg: cfg}
}

// options is what a collection against the domain sends the provider.
func (c *Checker) options(domain string) sdk.CheckerOptions {
	opts := CheckerOptions()
	// "domain_name" is the option key the checker-blacklist provider reads
	// (see checker/collect.go in the checker-blacklist module).
	opts["domain_name"] = domain
	return opts
}

// Check runs the aggregation against the domain. It returns nil when the
// check cannot be run, a nil Checker included, so the surrounding domain
// analysis still succeeds.
func (c *Checker) Check(ctx context.Context, domain string) *model.DomainBlacklistResult {
	if c == nil {
		return nil
	}

	// Cap the aggregation: sources run concurrently, each with its own
	// timeouts; this is the host-side ceiling. It deliberately does not reuse
	// Analysis.HTTPTimeout, which budgets a single outbound call: a parent
	// deadline shorter than a source's own silently overrides it.
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()

	started := time.Now()
	data, err := c.Collect(ctx, domain)
	if err != nil {
		log.Printf("Domain blacklist check of %s failed after %s: %v", domain, time.Since(started).Round(time.Millisecond), err)
		return nil
	}

	return buildResult(data)
}

// Collect runs one aggregation against the domain, within the caller's
// context alone: Check puts the configured ceiling on it, the feed cache
// warmup a budget of its own. Every collection goes through here so it
// sends the very options a check would: OISD, for one, keeps a cache per
// variant (checker/oisd.go), so a warmup sending anything else would fill a
// sibling cache nobody reads.
func (c *Checker) Collect(ctx context.Context, domain string) (*blacklist.BlacklistData, error) {
	raw, err := c.provider.Collect(ctx, c.options(domain))
	if err != nil {
		return nil, err
	}

	data := dataOf(raw)
	if data == nil {
		return nil, fmt.Errorf("unexpected blacklist observation %T", raw)
	}
	return data, nil
}
