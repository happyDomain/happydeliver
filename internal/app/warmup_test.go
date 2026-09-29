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
	"slices"
	"sync"
	"testing"
	"time"

	blacklist "git.happydns.org/checker-blacklist/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/reputation"
)

// fakeWarmupProvider is a hand-written sdk.ObservationProvider stand-in so the
// warmup tests never reach a real feed or reputation API.
type fakeWarmupProvider struct {
	mu    sync.Mutex
	calls int
	ctx   context.Context
	opts  sdk.CheckerOptions
	data  *blacklist.BlacklistData
	// seq, when set, is answered one entry per call instead of data, its
	// last entry repeating.
	seq []*blacklist.BlacklistData
	err error

	called chan struct{}
}

func newFakeWarmupProvider() *fakeWarmupProvider {
	return &fakeWarmupProvider{called: make(chan struct{}, 8)}
}

func (f *fakeWarmupProvider) Key() sdk.ObservationKey {
	return blacklist.ObservationKeyBlacklist
}

func (f *fakeWarmupProvider) Collect(ctx context.Context, opts sdk.CheckerOptions) (any, error) {
	f.mu.Lock()
	f.calls++
	f.ctx = ctx
	f.opts = opts
	f.mu.Unlock()

	select {
	case f.called <- struct{}{}:
	default:
	}

	if f.err != nil {
		return nil, f.err
	}
	if len(f.seq) > 0 {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.seq[min(f.calls, len(f.seq))-1], nil
	}
	return f.data, nil
}

func (f *fakeWarmupProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeWarmupProvider) lastContext() context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctx
}

func (f *fakeWarmupProvider) lastOptions() sdk.CheckerOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opts
}

// waitForCall blocks until the provider has been called once, or fails.
func (f *fakeWarmupProvider) waitForCall(t *testing.T) {
	t.Helper()
	select {
	case <-f.called:
	case <-time.After(2 * time.Second):
		t.Fatal("Collect was never called")
	}
}

// newWarmupService builds the service over a checker wrapping the provider.
func newWarmupService(provider sdk.ObservationProvider, cfg *config.Config) *BlacklistWarmupService {
	return NewBlacklistWarmupService(reputation.NewChecker(provider, cfg.Analysis.Blacklist), cfg)
}

// warmupTestConfig enables the warmup, which the default config does not.
func warmupTestConfig(interval time.Duration) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Analysis.Blacklist.Warmup = true
	cfg.Analysis.Blacklist.WarmupInterval = interval
	return cfg
}

// quiet reports whether the provider stayed untouched. The warmup collects
// from a goroutine when it is on, so give it a chance to misbehave before
// concluding it stayed quiet.
func quiet(provider *fakeWarmupProvider) bool {
	time.Sleep(50 * time.Millisecond)
	return provider.callCount() == 0
}

// TestBlacklistWarmupIsOffByDefault pins the opt-in: warming downloads several
// feeds on every start, so an untouched config must not do it.
func TestBlacklistWarmupIsOffByDefault(t *testing.T) {
	provider := newFakeWarmupProvider()

	svc := newWarmupService(provider, config.DefaultConfig())
	svc.Start(context.Background())
	defer svc.Stop()

	if !quiet(provider) {
		t.Errorf("Collect called %d time(s) on a default config, want 0", provider.callCount())
	}
}

// TestBlacklistWarmupDisabledKeepsItsInterval checks the two knobs are
// independent: an interval alone does not turn the warmup on.
func TestBlacklistWarmupDisabledKeepsItsInterval(t *testing.T) {
	provider := newFakeWarmupProvider()

	cfg := warmupTestConfig(time.Hour)
	cfg.Analysis.Blacklist.Warmup = false

	svc := newWarmupService(provider, cfg)
	svc.Start(context.Background())
	defer svc.Stop()

	if !quiet(provider) {
		t.Errorf("Collect called %d time(s) with warmup off, want 0", provider.callCount())
	}
}

// TestBlacklistWarmupAtStartupOnly covers the third state: enabled, but with
// no ticker behind it.
func TestBlacklistWarmupAtStartupOnly(t *testing.T) {
	provider := newFakeWarmupProvider()

	svc := newWarmupService(provider, warmupTestConfig(0))
	svc.Start(context.Background())
	defer svc.Stop()

	provider.waitForCall(t)

	if svc.ticker != nil {
		t.Error("a ticker was started for a startup-only warmup, want none")
	}
	if got := provider.callCount(); got != 1 {
		t.Errorf("Collect called %d time(s), want exactly 1", got)
	}
}

func TestBlacklistWarmupNilProvider(t *testing.T) {
	svc := NewBlacklistWarmupService(nil, warmupTestConfig(time.Hour))
	svc.Start(context.Background())
	svc.Stop()
}

func TestBlacklistWarmupCollectsOnStart(t *testing.T) {
	provider := newFakeWarmupProvider()

	svc := newWarmupService(provider, warmupTestConfig(time.Hour))
	svc.Start(context.Background())
	defer svc.Stop()

	provider.waitForCall(t)

	opts := provider.lastOptions()
	if got := opts["domain_name"]; got != warmupDomain {
		t.Errorf("opts[domain_name] = %v, want %q", got, warmupDomain)
	}
}

// TestBlacklistWarmupOnlyWarmsFeedSources is the test that matters most: the
// rule map is what keeps a background task from spending API quota, and the
// "a rule absent from the map counts as enabled" rule makes a wrong map fail
// silently.
func TestBlacklistWarmupOnlyWarmsFeedSources(t *testing.T) {
	provider := newFakeWarmupProvider()

	svc := newWarmupService(provider, warmupTestConfig(time.Hour))
	svc.Start(context.Background())
	defer svc.Stop()

	provider.waitForCall(t)

	ctx := provider.lastContext()
	if ctx == nil {
		t.Fatal("Collect received a nil context")
	}

	sources := blacklist.Sources()
	if len(sources) == 0 {
		t.Fatal("no checker-blacklist source is registered")
	}

	feedSources := 0
	for _, src := range sources {
		want := warmupSourceIDs[src.ID()]
		if want {
			feedSources++
		}
		if got := sdk.RuleEnabled(ctx, src.ID()); got != want {
			t.Errorf("RuleEnabled(%q) = %v, want %v", src.ID(), got, want)
		}
	}

	if feedSources != len(warmupSourceIDs) {
		t.Errorf("matched %d feed source(s) against the registry, want %d: warmupSourceIDs names a source that no longer exists upstream", feedSources, len(warmupSourceIDs))
	}
}

// TestBlacklistWarmupStopIsIdempotent pins the guard in Stop: the service
// stops itself when the parent context is cancelled and RunServer also defers
// a Stop, so an unguarded close(done) panics on any real shutdown.
func TestBlacklistWarmupStopIsIdempotent(t *testing.T) {
	provider := newFakeWarmupProvider()

	ctx, cancel := context.WithCancel(context.Background())
	svc := newWarmupService(provider, warmupTestConfig(10*time.Millisecond))
	svc.Start(ctx)

	provider.waitForCall(t)

	cancel()
	// Let the goroutine notice the cancellation and stop itself first.
	time.Sleep(50 * time.Millisecond)
	svc.Stop()
	svc.Stop()
}

// feedResults is a collection where each named feed source answered as its
// state says: "pending", "clean", or anything else as an error.
func feedResults(states map[string]string) *blacklist.BlacklistData {
	data := &blacklist.BlacklistData{}
	for id, state := range states {
		r := blacklist.SourceResult{SourceID: id, Enabled: true}
		switch state {
		case "pending":
			r.Pending = true
		case "clean":
		default:
			r.Error = state
		}
		data.Results = append(data.Results, r)
	}
	return data
}

// TestBlacklistWarmupWaitsForPendingFeeds pins what the module's detached
// downloads call for: the first lookup only starts them and answers
// pending, so the warmup has to keep looking until they end, then stop.
func TestBlacklistWarmupWaitsForPendingFeeds(t *testing.T) {
	provider := newFakeWarmupProvider()
	provider.seq = []*blacklist.BlacklistData{
		feedResults(map[string]string{"oisd": "pending", "openphish": "pending"}),
		feedResults(map[string]string{"oisd": "pending", "openphish": "clean"}),
		feedResults(map[string]string{"oisd": "clean", "openphish": "clean"}),
	}

	svc := newWarmupService(provider, warmupTestConfig(0))
	svc.pollInterval = time.Millisecond
	svc.runWarmup(context.Background())

	if got := provider.callCount(); got != 3 {
		t.Errorf("Collect called %d time(s), want 3: once per lookup until no feed is pending", got)
	}
}

// TestBlacklistWarmupGivesUpOnPendingFeeds checks the budget: a download that
// never ends must not keep the warmup looking forever.
func TestBlacklistWarmupGivesUpOnPendingFeeds(t *testing.T) {
	provider := newFakeWarmupProvider()
	provider.data = feedResults(map[string]string{"phishtank": "pending"})

	svc := newWarmupService(provider, warmupTestConfig(0))
	svc.timeout = 20 * time.Millisecond
	svc.pollInterval = time.Millisecond

	done := make(chan struct{})
	go func() {
		svc.runWarmup(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runWarmup kept polling past its timeout")
	}
}

// TestBlacklistWarmupStopEndsPolling checks a shutdown does not wait for the
// warmup budget to run out.
func TestBlacklistWarmupStopEndsPolling(t *testing.T) {
	provider := newFakeWarmupProvider()
	provider.data = feedResults(map[string]string{"phishtank": "pending"})

	svc := newWarmupService(provider, warmupTestConfig(0))
	svc.pollInterval = time.Hour

	done := make(chan struct{})
	go func() {
		svc.runWarmup(context.Background())
		close(done)
	}()

	provider.waitForCall(t)
	svc.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runWarmup kept polling after Stop")
	}
}

func TestWarmupOutcome(t *testing.T) {
	for _, tc := range []struct {
		name         string
		data         *blacklist.BlacklistData
		wantWarmed   int
		wantPending  []string
		wantFailures []string
	}{
		{
			name: "no result",
			data: &blacklist.BlacklistData{},
		},
		{
			name: "disabled sources are not counted",
			data: &blacklist.BlacklistData{Results: []blacklist.SourceResult{
				{SourceID: "oisd", Enabled: false},
				{SourceID: "disconnect", Enabled: true},
			}},
			wantWarmed: 1,
		},
		{
			name: "failures are reported sorted",
			data: &blacklist.BlacklistData{Results: []blacklist.SourceResult{
				{SourceID: "openphish", Enabled: true, Error: "timeout"},
				{SourceID: "oisd", Enabled: true},
				{SourceID: "disconnect", Enabled: true, Error: "HTTP 503"},
			}},
			wantWarmed:   1,
			wantFailures: []string{"disconnect: HTTP 503", "openphish: timeout"},
		},
		{
			// A pending source carries no error, yet has no data either:
			// counting it as warmed is what made every cold start look fine.
			name: "pending sources are not warmed",
			data: &blacklist.BlacklistData{Results: []blacklist.SourceResult{
				{SourceID: "phishtank", Enabled: true, Pending: true},
				{SourceID: "oisd", Enabled: true, Pending: true},
				{SourceID: "disconnect", Enabled: true},
			}},
			wantWarmed:  1,
			wantPending: []string{"oisd", "phishtank"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := warmupOutcome(tc.data)
			if got.warmed != tc.wantWarmed {
				t.Errorf("warmed = %d, want %d", got.warmed, tc.wantWarmed)
			}
			if !slices.Equal(got.pending, tc.wantPending) {
				t.Errorf("pending = %v, want %v", got.pending, tc.wantPending)
			}
			if !slices.Equal(got.failures, tc.wantFailures) {
				t.Errorf("failures = %v, want %v", got.failures, tc.wantFailures)
			}
		})
	}
}
