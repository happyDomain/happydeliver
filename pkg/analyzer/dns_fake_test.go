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

package analyzer

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
)

// fakeResolver answers every kind of lookup from maps keyed on the name
// without its trailing dot, NXDOMAIN for anything absent, and the error of
// err for a name listed there. It records every query, so tests can tell
// what an analysis asked.
type fakeResolver struct {
	txt   map[string][]string
	mx    map[string][]*net.MX
	hosts map[string][]string
	cname map[string]string
	err   map[string]error

	mu      sync.Mutex
	queries []string
}

func (f *fakeResolver) record(kind, name string) string {
	key := strings.ToLower(strings.TrimSuffix(name, "."))
	f.mu.Lock()
	f.queries = append(f.queries, kind+" "+key)
	f.mu.Unlock()
	return key
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	key := f.record("TXT", name)
	if err, ok := f.err[key]; ok {
		return nil, err
	}
	if r, ok := f.txt[key]; ok {
		return r, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	key := f.record("MX", name)
	if err, ok := f.err[key]; ok {
		return nil, err
	}
	if r, ok := f.mx[key]; ok {
		return r, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	key := f.record("A", name)
	if err, ok := f.err[key]; ok {
		return nil, err
	}
	if r, ok := f.hosts[key]; ok {
		return r, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.record("PTR", addr)
	return nil, notFound(addr)
}

func (f *fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	key := f.record("CNAME", name)
	if c, ok := f.cname[key]; ok {
		return c + ".", nil
	}
	return key + ".", nil
}

// newFakeAnalyzer builds an analyzer over f that reaches no registry and takes
// the documentation ranges for public addresses.
func newFakeAnalyzer(f *fakeResolver) *DNSAnalyzer {
	d := NewDNSAnalyzerWithResolver(5*time.Second, nil, f).WithDomainInfo(nil, 0)
	d.ipOrigin = nil
	d.publicAddr = func(ip net.IP) bool {
		return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
	}
	return d
}

func hasIssue(issues []model.Issue, t model.IssueType) *model.Issue {
	for i := range issues {
		if issues[i].Type == t {
			return &issues[i]
		}
	}
	return nil
}
