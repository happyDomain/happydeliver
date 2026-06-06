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
	"net"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
)

// returnOKMockResolver lets tests control MX and host (A/AAAA) lookups per domain.
type returnOKMockResolver struct {
	mx    map[string][]*net.MX
	hosts map[string][]string
}

func (m *returnOKMockResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if recs, ok := m.mx[name]; ok {
		return recs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (m *returnOKMockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if recs, ok := m.hosts[host]; ok {
		return recs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (m *returnOKMockResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *returnOKMockResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func TestCheckReturnOKDomain(t *testing.T) {
	mx := []*net.MX{{Host: "mail.example.com.", Pref: 10}}

	tests := []struct {
		name          string
		domain        string
		orgDomain     string
		resolver      *returnOKMockResolver
		wantStatus    string
		wantHasMX     bool
		wantHasAddr   bool
		wantOrgDomain string // "" means OrgDomain should be nil
	}{
		{
			name:        "domain with MX passes",
			domain:      "example.com",
			resolver:    &returnOKMockResolver{mx: map[string][]*net.MX{"example.com": mx}},
			wantStatus:  returnOKStatusPass,
			wantHasMX:   true,
			wantHasAddr: false,
		},
		{
			name:        "no MX but A/AAAA warns",
			domain:      "example.com",
			resolver:    &returnOKMockResolver{hosts: map[string][]string{"example.com": {"192.0.2.1"}}},
			wantStatus:  returnOKStatusWarn,
			wantHasMX:   false,
			wantHasAddr: true,
		},
		{
			name:          "fallback to org domain MX",
			domain:        "sub.example.com",
			orgDomain:     "example.com",
			resolver:      &returnOKMockResolver{mx: map[string][]*net.MX{"example.com": mx}},
			wantStatus:    returnOKStatusPass,
			wantHasMX:     true,
			wantHasAddr:   false,
			wantOrgDomain: "example.com",
		},
		{
			name:        "nothing anywhere fails",
			domain:      "example.com",
			orgDomain:   "example.com",
			resolver:    &returnOKMockResolver{},
			wantStatus:  returnOKStatusFail,
			wantHasMX:   false,
			wantHasAddr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDNSAnalyzerWithResolver(5*time.Second, tt.resolver)
			got := d.checkReturnOKDomain(tt.domain, tt.orgDomain)
			if got == nil {
				t.Fatalf("checkReturnOKDomain returned nil")
			}
			if got.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.HasMx == nil || *got.HasMx != tt.wantHasMX {
				t.Errorf("HasMx = %v, want %v", got.HasMx, tt.wantHasMX)
			}
			if got.HasAddress == nil || *got.HasAddress != tt.wantHasAddr {
				t.Errorf("HasAddress = %v, want %v", got.HasAddress, tt.wantHasAddr)
			}
			if tt.wantOrgDomain == "" {
				if got.OrgDomain != nil {
					t.Errorf("OrgDomain = %v, want nil", *got.OrgDomain)
				}
			} else {
				if got.OrgDomain == nil || *got.OrgDomain != tt.wantOrgDomain {
					t.Errorf("OrgDomain = %v, want %q", got.OrgDomain, tt.wantOrgDomain)
				}
			}
		})
	}
}

func TestCheckReturnOKDomainEmpty(t *testing.T) {
	d := NewDNSAnalyzerWithResolver(5*time.Second, &returnOKMockResolver{})
	if got := d.checkReturnOKDomain("", ""); got != nil {
		t.Errorf("checkReturnOKDomain(\"\") = %v, want nil", got)
	}
}

func TestCalculateReturnOKPenalty(t *testing.T) {
	fail := &model.ReturnOKDomain{Domain: "a.example", Status: returnOKStatusFail}
	pass := &model.ReturnOKDomain{Domain: "b.example", Status: returnOKStatusPass}
	warn := &model.ReturnOKDomain{Domain: "c.example", Status: returnOKStatusWarn}

	tests := []struct {
		name    string
		results *model.DNSResults
		want    int
	}{
		{"nil return_ok", &model.DNSResults{}, 0},
		{"both pass", &model.DNSResults{ReturnOk: &model.ReturnOK{From: pass, ReturnPath: pass}}, 0},
		{"warn is not penalised", &model.DNSResults{ReturnOk: &model.ReturnOK{From: warn}}, 0},
		{"one fail", &model.DNSResults{ReturnOk: &model.ReturnOK{From: fail, ReturnPath: pass}}, -10},
		{"both fail", &model.DNSResults{ReturnOk: &model.ReturnOK{From: fail, ReturnPath: fail}}, -20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateReturnOKPenalty(tt.results); got != tt.want {
				t.Errorf("calculateReturnOKPenalty() = %d, want %d", got, tt.want)
			}
		})
	}
}
