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
	"time"

	"golang.org/x/sync/singleflight"

	"git.happydns.org/happyDomain/pkg/domaininfo/types"
)

// domainInfoCache remembers what a registry answered about a domain, for a
// while. It remembers a domain not existing too: that is an answer, and one
// a registry is asked about just as often. What it does not remember is a
// failure, which may be over by the next message.
//
// Messages arrive in parallel and a popular sender domain is asked about by
// several at once, so a miss is single-flighted: the first asks the registry
// and the rest wait on that answer, rather than every one of them opening
// its own RDAP conversation.
type domainInfoCache struct {
	lookup types.Getter
	ttl    time.Duration
	size   int

	inflight singleflight.Group

	mu      sync.Mutex
	entries map[string]domainInfoEntry
}

type domainInfoEntry struct {
	info    *types.DomainInfo
	missing bool
	until   time.Time
}

// newDomainInfoCache wraps a getter.
func newDomainInfoCache(lookup types.Getter, ttl time.Duration, size int) *domainInfoCache {
	return &domainInfoCache{
		lookup:  lookup,
		ttl:     ttl,
		size:    size,
		entries: make(map[string]domainInfoEntry),
	}
}

// get answers from the cache, or asks and remembers.
func (c *domainInfoCache) get(ctx context.Context, domain string) (*types.DomainInfo, error) {
	now := time.Now()

	c.mu.Lock()
	entry, ok := c.entries[domain]
	c.mu.Unlock()

	if ok && now.Before(entry.until) {
		if entry.missing {
			return nil, types.ErrDomainDoesNotExist
		}
		return entry.info, nil
	}

	// The lookup runs detached from whichever caller opened the flight: the
	// others waiting on it have budgets of their own, and the first one's
	// context going away — its own deadline spent, or its HTTP request
	// cancelled — must not fail theirs. Only its deadline is carried over,
	// so the flight stays bounded. Each caller's own context governs its
	// wait, and nothing more.
	answers := c.inflight.DoChan(domain, func() (any, error) {
		lookupCtx := context.WithoutCancel(ctx)
		if deadline, ok := ctx.Deadline(); ok {
			var cancel context.CancelFunc
			lookupCtx, cancel = context.WithDeadline(lookupCtx, deadline)
			defer cancel()
		}

		info, err := c.lookup(lookupCtx, domain)
		switch {
		case errors.Is(err, types.ErrDomainDoesNotExist):
			c.remember(domain, domainInfoEntry{missing: true, until: time.Now().Add(c.ttl)})
		case err != nil:
			return nil, err
		default:
			c.remember(domain, domainInfoEntry{info: info, until: time.Now().Add(c.ttl)})
		}

		return info, err
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case answer := <-answers:
		if answer.Val == nil {
			return nil, answer.Err
		}

		return answer.Val.(*types.DomainInfo), answer.Err
	}
}

// remember stores an entry, making room by dropping what has expired, and
// then whatever comes first when nothing has: the cache is a courtesy to
// the registries, not a record.
func (c *domainInfoCache) remember(domain string, entry domainInfoEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.size {
		now := time.Now()
		for key, old := range c.entries {
			if !now.Before(old.until) {
				delete(c.entries, key)
			}
		}
		for key := range c.entries {
			if len(c.entries) < c.size {
				break
			}
			delete(c.entries, key)
		}
	}

	c.entries[domain] = entry
}
