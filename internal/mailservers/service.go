// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package mailservers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

// ErrRateLimited is returned when a client, or a domain, asked for more
// probes than allowed: each makes this instance connect to servers it does
// not run.
var ErrRateLimited = errors.New("too many mail server probes requested")

// probeBudget bounds one whole probe of a domain, whatever its number of MX:
// past it, what was not observed stays so.
const probeBudget = 3 * time.Minute

// Limits on probes actually run, cached results not counted.
const (
	limitWindow    = time.Hour
	limitPerClient = 20
	limitPerDomain = 6
)

// Service serves the probes of the mail servers of domains, from a cache
// when they were probed recently, a single probe at a time per domain, and
// within limits per client and per domain.
type Service struct {
	prober interface {
		Probe(ctx context.Context, domain string) *model.MailServersResult
	}
	ttl time.Duration
	now func() time.Time

	group singleflight.Group

	mu      sync.Mutex
	cache   map[string]cached
	clients map[string][]time.Time
	domains map[string][]time.Time
}

type cached struct {
	result  *model.MailServersResult
	expires time.Time
}

// NewService serves the probes of prober, caching each result for ttl.
func NewService(prober *Prober, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{
		prober:  prober,
		ttl:     ttl,
		now:     time.Now,
		cache:   map[string]cached{},
		clients: map[string][]time.Time{},
		domains: map[string][]time.Time{},
	}
}

// Check returns what the mail servers of domain look like, probing them
// unless they were recently. client is who asks, for the limits.
func (s *Service) Check(ctx context.Context, client, domain string) (*model.MailServersResult, error) {
	domain = domainname.Normalize(domain)

	s.mu.Lock()
	if c, ok := s.cache[domain]; ok && s.now().Before(c.expires) {
		s.mu.Unlock()
		return c.result, nil
	}
	s.mu.Unlock()

	ch := s.group.DoChan(domain, func() (any, error) {
		if !s.allow(client, domain) {
			return nil, ErrRateLimited
		}
		// Detached from the request: other clients may wait on this
		// probe, and its result is worth caching even if this one leaves.
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeBudget)
		defer cancel()
		result := s.prober.Probe(probeCtx, domain)

		s.mu.Lock()
		s.cache[domain] = cached{result: result, expires: s.now().Add(s.ttl)}
		s.evict()
		s.mu.Unlock()
		return result, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*model.MailServersResult), nil
	}
}

// allow counts a probe against the limits of client and domain, telling
// whether it may run.
func (s *Service) allow(client, domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	recent := func(times []time.Time) []time.Time {
		kept := times[:0]
		for _, t := range times {
			if now.Sub(t) < limitWindow {
				kept = append(kept, t)
			}
		}
		return kept
	}
	clientKey := strings.TrimSpace(client)
	byClient := recent(s.clients[clientKey])
	byDomain := recent(s.domains[domain])
	if len(byClient) >= limitPerClient || len(byDomain) >= limitPerDomain {
		s.clients[clientKey], s.domains[domain] = byClient, byDomain
		return false
	}
	s.clients[clientKey] = append(byClient, now)
	s.domains[domain] = append(byDomain, now)
	return true
}

// evict drops the expired entries, so that the maps do not grow with every
// domain ever asked. The caller holds the lock.
func (s *Service) evict() {
	now := s.now()
	for domain, c := range s.cache {
		if now.After(c.expires) {
			delete(s.cache, domain)
		}
	}
	for key, times := range s.clients {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= limitWindow {
			delete(s.clients, key)
		}
	}
	for key, times := range s.domains {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= limitWindow {
			delete(s.domains, key)
		}
	}
}
