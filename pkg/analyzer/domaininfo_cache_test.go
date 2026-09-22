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

package analyzer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"git.happydns.org/happyDomain/pkg/domaininfo/types"
)

func TestDomainInfoCache(t *testing.T) {
	calls := map[string]int{}
	failing := errors.New("registry down")
	lookup := func(_ context.Context, domain string) (*types.DomainInfo, error) {
		calls[domain]++
		switch domain {
		case "missing.example":
			return nil, types.ErrDomainDoesNotExist
		case "down.example":
			return nil, failing
		}
		return &types.DomainInfo{Name: domain}, nil
	}

	cache := newDomainInfoCache(lookup, time.Hour, 2)
	ctx := context.Background()

	// A registration is asked once.
	for range 3 {
		info, err := cache.get(ctx, "example.com")
		if err != nil || info == nil || info.Name != "example.com" {
			t.Fatalf("get(example.com) = %v, %v", info, err)
		}
	}
	if calls["example.com"] != 1 {
		t.Errorf("example.com was asked %d times, want once", calls["example.com"])
	}

	// So is a domain that does not exist.
	for range 2 {
		if _, err := cache.get(ctx, "missing.example"); !errors.Is(err, types.ErrDomainDoesNotExist) {
			t.Fatalf("get(missing.example) error = %v, want ErrDomainDoesNotExist", err)
		}
	}
	if calls["missing.example"] != 1 {
		t.Errorf("missing.example was asked %d times, want once", calls["missing.example"])
	}

	// A failure is not remembered.
	for range 2 {
		if _, err := cache.get(ctx, "down.example"); !errors.Is(err, failing) {
			t.Fatalf("get(down.example) error = %v, want the failure", err)
		}
	}
	if calls["down.example"] != 2 {
		t.Errorf("down.example was asked %d times, want twice", calls["down.example"])
	}

	// The cache is bounded: a third domain evicts one, and the cache still
	// answers.
	if _, err := cache.get(ctx, "example.net"); err != nil {
		t.Fatal(err)
	}
	if len(cache.entries) > 2 {
		t.Errorf("cache holds %d entries, want at most 2", len(cache.entries))
	}
}

func TestDomainInfoCacheExpires(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string) (*types.DomainInfo, error) {
		calls++
		return &types.DomainInfo{Name: "example.com"}, nil
	}

	cache := newDomainInfoCache(lookup, time.Nanosecond, 10)
	cache.get(context.Background(), "example.com")
	time.Sleep(time.Millisecond)
	cache.get(context.Background(), "example.com")

	if calls != 2 {
		t.Errorf("an expired entry was served: asked %d times, want twice", calls)
	}
}

// TestDomainInfoCacheSingleFlight checks that messages arriving together
// about the same sender domain cost the registry one lookup, not one each.
func TestDomainInfoCacheSingleFlight(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})

	lookup := func(_ context.Context, domain string) (*types.DomainInfo, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release // hold the first caller until every other one has arrived
		return &types.DomainInfo{Name: domain}, nil
	}

	cache := newDomainInfoCache(lookup, time.Hour, 16)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := cache.get(context.Background(), "example.com")
			if err != nil || info == nil || info.Name != "example.com" {
				t.Errorf("get(example.com) = %v, %v", info, err)
			}
		}()
	}

	// Let the in-flight lookup answer once the others have had time to join it.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("the registry was asked %d times, want once", calls)
	}
}

// TestDomainInfoCacheDetachedFromTheFirstCaller checks an analysis that
// joins an in-flight lookup is answered on its own budget: the caller that
// opened the flight giving up must not fail the ones waiting on it.
func TestDomainInfoCacheDetachedFromTheFirstCaller(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})

	lookup := func(ctx context.Context, domain string) (*types.DomainInfo, error) {
		started <- ctx
		<-release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &types.DomainInfo{Name: domain}, nil
	}

	cache := newDomainInfoCache(lookup, time.Hour, 16)

	// The first caller opens the flight, then gives up.
	first, cancelFirst := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := cache.get(first, "example.com")
		firstErr <- err
	}()

	lookupCtx := <-started

	// A second analysis joins the flight, on a context of its own.
	joined := make(chan *types.DomainInfo, 1)
	joinedErr := make(chan error, 1)
	go func() {
		info, err := cache.get(context.Background(), "example.com")
		joined <- info
		joinedErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	cancelFirst()
	if err := <-firstErr; !errors.Is(err, context.Canceled) {
		t.Errorf("the caller that gave up got %v, want context.Canceled", err)
	}
	if err := lookupCtx.Err(); err != nil {
		t.Errorf("the in-flight lookup was cancelled with its first caller: %v", err)
	}

	close(release)
	info, err := <-joined, <-joinedErr
	if err != nil || info == nil || info.Name != "example.com" {
		t.Fatalf("the analysis waiting on the flight got %v, %v; want the registration", info, err)
	}
}
