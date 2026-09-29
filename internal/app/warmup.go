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
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	blacklist "git.happydns.org/checker-blacklist/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/reputation"
)

const (
	// warmupDomain is the domain the warmup collection runs against. It has no
	// functional bearing: a feed source downloads its whole list in background
	// and only matches the domain against it (checker/feedcache.go), so any
	// syntactically valid name starts the very same download. example.com is
	// reserved by RFC 2606 and can never be listed, so the warmup cannot
	// produce a spurious verdict either.
	warmupDomain = "example.com"

	// warmupTimeout is how long one warmup keeps waiting for the feed
	// downloads to end. The module runs them detached from any caller, each
	// bounded by its own fetch timeout, the longest being PhishTank's 5
	// minutes (checker/phishtank.go); past this budget the warmup only stops
	// watching, the download carries on. It is deliberately not the
	// per-request collect timeout: no client is waiting here.
	warmupTimeout = 6 * time.Minute

	// warmupPollInterval spaces the lookups that watch the downloads. A
	// lookup is local: it never downloads anything itself and waits at most
	// a couple of seconds for a running download (feedColdWait in
	// checker/feedcache.go).
	warmupPollInterval = 10 * time.Second

	// feedIdleCutoff mirrors feedIdleAfter in checker/feedcache.go: the
	// module stops refreshing a feed nobody looked up for that long, and the
	// next lookup finds it cold. A warmup repeating less often than this
	// keeps nothing warm on a quiet instance.
	feedIdleCutoff = 48 * time.Hour
)

// warmupSourceIDs are the checker-blacklist sources that keep a feed cache,
// and are therefore the only ones worth warming. Every other source is either
// pure DNS (nothing to cache) or behind an API key whose quota we will not
// spend on a background task. Source IDs double as rule names
// (checker/rule.go).
var warmupSourceIDs = map[string]bool{
	"oisd":       true,
	"disconnect": true,
	"openphish":  true,
	"phishtank":  true,
}

// BlacklistWarmupService fills the checker-blacklist feed caches in the
// background. The module downloads a feed only once something looks it up,
// then refreshes it on its own every TTL until nobody has looked it up for
// feedIdleCutoff. Without a warmup, the first checks after a start or a long
// idle period therefore get no answer from the feed sources: they report
// themselves pending until their download ends. It is opt-in.
//
// The warmup looks the feed sources up at startup, which starts their
// downloads, then watches them until they end. Each later tick keeps the
// module's refresh loops alive, restarting any that went idle; on warm
// caches it does no network I/O.
type BlacklistWarmupService struct {
	checker      *reputation.Checker
	enabled      bool
	interval     time.Duration
	timeout      time.Duration
	pollInterval time.Duration
	ticker       *time.Ticker
	done         chan struct{}
	stopOnce     sync.Once
}

// NewBlacklistWarmupService creates a new blacklist feed cache warmup service
func NewBlacklistWarmupService(checker *reputation.Checker, cfg *config.Config) *BlacklistWarmupService {
	return &BlacklistWarmupService{
		checker:      checker,
		enabled:      cfg.Analysis.Blacklist.Warmup,
		interval:     cfg.Analysis.Blacklist.WarmupInterval,
		timeout:      warmupTimeout,
		pollInterval: warmupPollInterval,
		done:         make(chan struct{}),
	}
}

// Start begins the warmup service in a background goroutine
func (s *BlacklistWarmupService) Start(ctx context.Context) {
	if s.checker == nil || !s.enabled {
		log.Println("Blacklist feed cache warmup is disabled (feeds start downloading on the first check that needs them)")
		return
	}

	if s.interval > 0 {
		log.Printf("Starting blacklist feed cache warmup: now, then every %s", s.interval)
		if s.interval >= feedIdleCutoff {
			log.Printf("Blacklist feed cache warmup: an interval of %s does not keep the feeds warm on a quiet instance, the module stops refreshing a feed after %s without lookup", s.interval, feedIdleCutoff)
		}
		s.ticker = time.NewTicker(s.interval)
	} else {
		log.Println("Starting blacklist feed cache warmup: at startup only")
	}

	// Warm the caches immediately, in background: this runs before the
	// listener binds, and the feeds take far longer than a start should.
	go func() {
		s.runWarmup(ctx)
		if s.ticker == nil {
			return
		}

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

// runWarmup performs one warmup. Its first lookup starts the download of
// every feed that is not being refreshed yet, and answers pending for those
// until the download ends, so it keeps looking them up until none is pending
// anymore: the log then says how the downloads ended, not that they began.
func (s *BlacklistWarmupService) runWarmup(ctx context.Context) {
	ctx, cancel := context.WithTimeout(warmupContext(ctx), s.timeout)
	defer cancel()

	started := time.Now()
	for {
		data, err := s.checker.Collect(ctx, warmupDomain)
		if err != nil {
			log.Printf("Blacklist feed cache warmup failed: %v", err)
			return
		}

		// Collect never reports a per-source failure through its error: it folds
		// them into the results it returns, so the outcome has to be read there.
		outcome := warmupOutcome(data)
		if len(outcome.pending) == 0 {
			log.Print(outcome.summary(time.Since(started)))
			return
		}

		select {
		case <-time.After(s.pollInterval):
		case <-ctx.Done():
			log.Print(outcome.summary(time.Since(started)))
			return
		case <-s.done:
			return
		}
	}
}

// warmupResult is how the feed sources answered one warmup lookup.
type warmupResult struct {
	warmed int
	// pending lists the sources whose download is still running, sorted.
	pending []string
	// failures describes the sources that failed as "source: reason"
	// entries, sorted for a stable log line.
	failures []string
}

// warmupOutcome sorts the enabled sources of a collection by how they
// answered.
func warmupOutcome(data *blacklist.BlacklistData) warmupResult {
	var res warmupResult
	for _, r := range data.Results {
		switch {
		case !r.Enabled:
		case r.Error != "":
			res.failures = append(res.failures, r.SourceID+": "+r.Error)
		case r.Pending:
			res.pending = append(res.pending, r.SourceID)
		default:
			res.warmed++
		}
	}
	sort.Strings(res.pending)
	sort.Strings(res.failures)

	return res
}

// summary is the log line reporting the outcome of a warmup that ran for
// elapsed.
func (r warmupResult) summary(elapsed time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Blacklist feed cache warmup: %d source(s) warmed in %s", r.warmed, elapsed.Round(time.Millisecond))
	if len(r.pending) > 0 {
		fmt.Fprintf(&b, ", %d still downloading in background: %v", len(r.pending), r.pending)
	}
	if len(r.failures) > 0 {
		fmt.Fprintf(&b, ", %d failed: %v", len(r.failures), r.failures)
	}
	return b.String()
}
