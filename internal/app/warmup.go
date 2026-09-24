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

package app

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	blacklist "git.happydns.org/checker-blacklist/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"

	"git.happydns.org/happyDeliver/internal/config"
)

const (
	// warmupDomain is the domain the warmup collection runs against. It has no
	// functional bearing: a feed source downloads its whole list and only then
	// filters it on the domain (checker/feedcache.go), so any syntactically
	// valid name fills the cache identically. example.com is reserved by RFC
	// 2606 and can never be listed, so the warmup cannot produce a spurious
	// verdict either.
	warmupDomain = "example.com"

	// warmupTimeout is deliberately not the per-request collect timeout: no
	// client is waiting here, and an operator who lowers CollectTimeout to
	// keep the API snappy should not thereby starve the refresh that makes it
	// snappy. Feeds run concurrently, so the budget is the slowest single
	// fetch, not their sum: the module's shared client caps any one request at
	// 60s (checker/httpclient.go), plus parsing a few hundred thousand lines.
	warmupTimeout = 2 * time.Minute
)

// warmupSourceIDs are the checker-blacklist sources that keep a feed cache,
// and are therefore the only ones worth warming. Every other source is either
// pure DNS (nothing to cache) or behind an API key whose quota we will not
// spend on a background task. Source IDs double as rule names
// (checker/rule.go).
var warmupSourceIDs = map[string]bool{
	"oisd":       true,
	"disconnect": true,
	"botvrij":    true,
	"openphish":  true,
	"phishtank":  true,
}

// BlacklistWarmupService fills the checker-blacklist feed caches in the
// background, so a domain check does not pay for downloading them. It is
// opt-in: left off, the feed sources are simply reloaded by whichever check
// finds them stale, which the collect timeout is sized for.
type BlacklistWarmupService struct {
	provider sdk.ObservationProvider
	cfg      *config.Config
	enabled  bool
	interval time.Duration
	ticker   *time.Ticker
	done     chan struct{}
	stopOnce sync.Once
}

// NewBlacklistWarmupService creates a new blacklist feed cache warmup service
func NewBlacklistWarmupService(provider sdk.ObservationProvider, cfg *config.Config) *BlacklistWarmupService {
	return &BlacklistWarmupService{
		provider: provider,
		cfg:      cfg,
		enabled:  cfg.Analysis.Blacklist.Warmup,
		interval: cfg.Analysis.Blacklist.WarmupInterval,
		done:     make(chan struct{}),
	}
}

// Start begins the warmup service in a background goroutine
func (s *BlacklistWarmupService) Start(ctx context.Context) {
	if s.provider == nil || !s.enabled {
		log.Println("Blacklist feed cache warmup is disabled (caches fill on the first check that finds them stale)")
		return
	}

	if s.interval > 0 {
		log.Printf("Starting blacklist feed cache warmup: now, then every %s", s.interval)
	} else {
		log.Println("Starting blacklist feed cache warmup: at startup only")
	}

	// Warm the caches immediately, in background: this runs before the
	// listener binds, and the feeds take far longer than a start should.
	go s.runWarmup(ctx)

	if s.interval <= 0 {
		return
	}

	s.ticker = time.NewTicker(s.interval)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.runWarmup(ctx)
			case <-ctx.Done():
				s.Stop()
				return
			case <-s.done:
				return
			}
		}
	}()
}

// Stop stops the warmup service. It is safe to call more than once: the
// service stops itself when the parent context is cancelled, and RunServer
// also defers a Stop, so both can race on a real shutdown.
func (s *BlacklistWarmupService) Stop() {
	s.stopOnce.Do(func() {
		if s.ticker != nil {
			s.ticker.Stop()
		}
		close(s.done)
	})
}

// warmupContext restricts a collection to the feed-backed sources. Collect
// consults sdk.RuleEnabled before firing each source, and RuleEnabled treats a
// rule *absent* from the map as enabled, so the map has to name every source
// explicitly: enumerating the registry means an unknown ID is always disabled,
// and a source added upstream is left out of the warmup rather than silently
// billed on every tick.
func warmupContext(ctx context.Context) context.Context {
	enabled := map[string]bool{}
	for _, src := range blacklist.Sources() {
		enabled[src.ID()] = warmupSourceIDs[src.ID()]
	}
	return sdk.WithEnabledRules(ctx, enabled)
}

// runWarmup performs one warmup collection
func (s *BlacklistWarmupService) runWarmup(ctx context.Context) {
	ctx, cancel := context.WithTimeout(warmupContext(ctx), warmupTimeout)
	defer cancel()

	// Reuse the very options a request would send: OISD, for one, keeps a
	// cache per variant and Query picks between them on "oisd_variant"
	// (checker/oisd.go), so warming with anything else would fill a sibling
	// cache nobody reads.
	opts := s.cfg.Analysis.Blacklist.AsCheckerOptions()
	// "domain_name" is the option key the checker-blacklist provider reads
	// (see checker/collect.go in the checker-blacklist module).
	opts["domain_name"] = warmupDomain

	started := time.Now()
	raw, err := s.provider.Collect(ctx, opts)
	if err != nil {
		log.Printf("Blacklist feed cache warmup failed: %v", err)
		return
	}

	// Collect never reports a per-source failure through its error: it folds
	// them into the results it returns, so the outcome has to be read there.
	warmed, failures := warmupOutcome(raw)
	if len(failures) > 0 {
		log.Printf("Blacklist feed cache warmup: %d source(s) warmed in %s, %d failed: %v",
			warmed, time.Since(started).Round(time.Millisecond), len(failures), failures)
		return
	}

	log.Printf("Blacklist feed cache warmup: %d source(s) warmed in %s",
		warmed, time.Since(started).Round(time.Millisecond))
}

// warmupOutcome counts the sources that answered and describes those that did
// not, as "source: reason" entries sorted for a stable log line.
func warmupOutcome(raw any) (warmed int, failures []string) {
	data, ok := raw.(*blacklist.BlacklistData)
	if !ok || data == nil {
		return 0, nil
	}

	for _, r := range data.Results {
		if !r.Enabled {
			continue
		}
		if r.Error != "" {
			failures = append(failures, r.SourceID+": "+r.Error)
			continue
		}
		warmed++
	}
	sort.Strings(failures)

	return warmed, failures
}
