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
	"os"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDomain/pkg/domaininfo/types"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// disposableDomain is a provider the embedded list is known to hold, and
// freeDomain a provider everyone knows.
const (
	disposableDomain = "mailinator.com"
	freeDomain       = "gmail.com"
)

func TestCheckDomainInfoProviderKind(t *testing.T) {
	d := newMockAnalyzer(nil, nil)

	tests := []struct {
		name       string
		domain     string
		orgDomain  string
		wantDomain string
		disposable bool
		free       bool
	}{
		{"corporate domain", "mail.example.com", "example.com", "example.com", false, false},
		{"organizational domain derived when not given", "mail.example.com", "", "example.com", false, false},
		{"disposable provider", disposableDomain, disposableDomain, disposableDomain, true, false},
		{"subdomain of a disposable provider", "mx." + disposableDomain, disposableDomain, disposableDomain, true, false},
		{"free provider", freeDomain, freeDomain, freeDomain, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.checkDomainInfo(tt.domain, tt.orgDomain)
			if got == nil {
				t.Fatal("checkDomainInfo() = nil")
			}
			if got.Domain != tt.wantDomain || got.Disposable != tt.disposable || got.FreeProvider != tt.free {
				t.Errorf("checkDomainInfo(%q, %q) = {%s %v %v}, want {%s %v %v}", tt.domain, tt.orgDomain,
					got.Domain, got.Disposable, got.FreeProvider, tt.wantDomain, tt.disposable, tt.free)
			}
		})
	}

	if got := d.checkDomainInfo("", ""); got != nil {
		t.Errorf("checkDomainInfo(\"\") = %+v, want nil", *got)
	}
}

func TestCalculateDomainInfoPenaltyProviderKind(t *testing.T) {
	tests := []struct {
		name    string
		results *model.DNSResults
		want    int
	}{
		{"nothing known", &model.DNSResults{}, 0},
		{"corporate domains", &model.DNSResults{
			FromDomainInfo: &model.SenderDomainInfo{Domain: "example.com"},
			RpDomainInfo:   &model.SenderDomainInfo{Domain: "example.net"},
		}, 0},
		{"free provider costs nothing", &model.DNSResults{
			FromDomainInfo: &model.SenderDomainInfo{Domain: freeDomain, FreeProvider: true},
		}, 0},
		{"disposable From", &model.DNSResults{
			FromDomainInfo: &model.SenderDomainInfo{Domain: disposableDomain, Disposable: true},
		}, penaltyDisposableFrom},
		{"disposable Return-Path", &model.DNSResults{
			FromDomainInfo: &model.SenderDomainInfo{Domain: "example.com"},
			RpDomainInfo:   &model.SenderDomainInfo{Domain: disposableDomain, Disposable: true},
		}, penaltyDisposableReturnPath},
		{"both disposable", &model.DNSResults{
			FromDomainInfo: &model.SenderDomainInfo{Domain: disposableDomain, Disposable: true},
			RpDomainInfo:   &model.SenderDomainInfo{Domain: "other." + disposableDomain, Disposable: true},
		}, penaltyDisposableFrom + penaltyDisposableReturnPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateDomainInfoPenalty(tt.results); got != tt.want {
				t.Errorf("calculateDomainInfoPenalty() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestAnalyzeDNSDomainInfo checks which domains the analysis describes: the
// From domain always, the Return-Path only when another organization's.
func TestAnalyzeDNSDomainInfo(t *testing.T) {
	d := newMockAnalyzer(nil, nil)

	email, err := mailmsg.Parse([]byte("From: sender@example.com\r\nSubject: x\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		alignment  model.DomainAlignment
		wantFrom   string
		wantRp     string // empty when no Return-Path block is expected
		disposable bool
	}{
		{
			name: "same organization",
			alignment: model.DomainAlignment{
				FromDomain: utils.PtrTo("mail.example.com"), FromOrgDomain: utils.PtrTo("example.com"),
				ReturnPathDomain: utils.PtrTo("bounce.example.com"), ReturnPathOrgDomain: utils.PtrTo("example.com"),
			},
			wantFrom: "example.com",
		},
		{
			name: "another organization bounces",
			alignment: model.DomainAlignment{
				FromDomain: utils.PtrTo("example.com"), FromOrgDomain: utils.PtrTo("example.com"),
				ReturnPathDomain: utils.PtrTo("bounce.example.net"), ReturnPathOrgDomain: utils.PtrTo("example.net"),
			},
			wantFrom: "example.com",
			wantRp:   "example.net",
		},
		{
			name: "no Return-Path",
			alignment: model.DomainAlignment{
				FromDomain: utils.PtrTo("example.com"), FromOrgDomain: utils.PtrTo("example.com"),
			},
			wantFrom: "example.com",
		},
		{
			name: "organizational domains derived when the header analysis gave none",
			alignment: model.DomainAlignment{
				FromDomain:       utils.PtrTo("mail.example.com"),
				ReturnPathDomain: utils.PtrTo("bounce.example.net"),
			},
			wantFrom: "example.com",
			wantRp:   "example.net",
		},
		{
			name: "disposable sender",
			alignment: model.DomainAlignment{
				FromDomain: utils.PtrTo(disposableDomain), FromOrgDomain: utils.PtrTo(disposableDomain),
			},
			wantFrom:   disposableDomain,
			disposable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := d.AnalyzeDNS(email, &model.HeaderAnalysis{DomainAlignment: &tt.alignment}, nil)

			if results.FromDomainInfo == nil {
				t.Fatal("FromDomainInfo = nil")
			}
			if results.FromDomainInfo.Domain != tt.wantFrom || results.FromDomainInfo.Disposable != tt.disposable {
				t.Errorf("FromDomainInfo = %+v, want domain %q disposable %v", *results.FromDomainInfo, tt.wantFrom, tt.disposable)
			}

			switch {
			case tt.wantRp == "" && results.RpDomainInfo != nil:
				t.Errorf("RpDomainInfo = %+v, want none", *results.RpDomainInfo)
			case tt.wantRp != "" && results.RpDomainInfo == nil:
				t.Errorf("RpDomainInfo = nil, want %q", tt.wantRp)
			case tt.wantRp != "" && results.RpDomainInfo.Domain != tt.wantRp:
				t.Errorf("RpDomainInfo.Domain = %q, want %q", results.RpDomainInfo.Domain, tt.wantRp)
			}
		})
	}
}

func TestAnalyzeDomainOnlyDomainInfo(t *testing.T) {
	d := newMockAnalyzer(nil, nil)

	results := d.AnalyzeDomainOnly("mail." + disposableDomain)
	if results.FromDomainInfo == nil || !results.FromDomainInfo.Disposable || results.FromDomainInfo.Domain != disposableDomain {
		t.Errorf("FromDomainInfo = %+v, want %s flagged disposable", results.FromDomainInfo, disposableDomain)
	}

	score, _ := d.CalculateDomainOnlyScore(results)
	clean := d.AnalyzeDomainOnly("example.com")
	cleanScore, _ := d.CalculateDomainOnlyScore(clean)
	if score >= cleanScore && cleanScore > 0 {
		t.Errorf("disposable domain scored %d, no less than a clean one at %d", score, cleanScore)
	}
}

// fakeRegistry answers registrations from a map, and fails for any other
// domain.
func fakeRegistry(known map[string]*types.DomainInfo) types.Getter {
	return func(_ context.Context, domain string) (*types.DomainInfo, error) {
		if info, ok := known[domain]; ok {
			if info == nil {
				return nil, types.ErrDomainDoesNotExist
			}
			return info, nil
		}
		return nil, errors.New("registry unreachable")
	}
}

func TestReadRegistration(t *testing.T) {
	created := time.Now().AddDate(-2, 0, 0)
	expires := time.Now().AddDate(1, 0, 0)
	registrarURL := "https://registrar.example"

	d := newMockAnalyzer(nil, nil).WithDomainInfo(fakeRegistry(map[string]*types.DomainInfo{
		"example.com": {
			Name:           "example.com",
			Registrar:      "Example Registrar",
			RegistrarURL:   &registrarURL,
			CreationDate:   &created,
			ExpirationDate: &expires,
			Status:         []string{"clientTransferProhibited"},
			Contacts: map[string]*types.ContactInfo{
				"registrant": {Name: "Somebody", Email: "somebody@example.com", Country: "FR"},
			},
		},
		"bare.example":    {Name: "bare.example", Registrar: "Unknown"},
		"missing.example": nil,
	}), time.Second)

	t.Run("registered", func(t *testing.T) {
		info := d.checkDomainInfo("mail.example.com", "example.com")
		if info.Error != nil {
			t.Fatalf("Error = %q, want none", *info.Error)
		}
		if utils.Deref(info.Registrar) != "Example Registrar" || utils.Deref(info.RegistrarUrl) != registrarURL {
			t.Errorf("registrar = %v %v", info.Registrar, info.RegistrarUrl)
		}
		if info.CreationDate == nil || !info.CreationDate.Equal(created) || info.ExpirationDate == nil || !info.ExpirationDate.Equal(expires) {
			t.Errorf("dates = %v %v", info.CreationDate, info.ExpirationDate)
		}
		if age := utils.Deref(info.AgeDays); age < 729 || age > 732 {
			t.Errorf("AgeDays = %d, want about two years", age)
		}
		if info.Status == nil || len(*info.Status) != 1 {
			t.Errorf("status = %v", info.Status)
		}
		if utils.Deref(info.RegistrantCountry) != "FR" {
			t.Errorf("RegistrantCountry = %v, want FR", info.RegistrantCountry)
		}
	})

	t.Run("nothing published", func(t *testing.T) {
		info := d.checkDomainInfo("bare.example", "")
		if info.Error != nil || info.Registrar != nil || info.CreationDate != nil || info.AgeDays != nil || info.Status != nil || info.RegistrantCountry != nil {
			t.Errorf("checkDomainInfo(bare.example) = %+v, want every registration field left out", *info)
		}
	})

	t.Run("not registered", func(t *testing.T) {
		info := d.checkDomainInfo("missing.example", "")
		if utils.Deref(info.Error) != "domain is not registered" || info.Registrar != nil {
			t.Errorf("checkDomainInfo(missing.example) = %+v", *info)
		}
	})

	t.Run("registry unreachable", func(t *testing.T) {
		info := d.checkDomainInfo("down.example", "")
		if info.Error == nil || !strings.Contains(*info.Error, "registry unreachable") || info.Registrar != nil {
			t.Errorf("checkDomainInfo(down.example) = %+v", *info)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		info := newMockAnalyzer(nil, nil).WithDomainInfo(nil, 0).checkDomainInfo("example.com", "")
		if info.Error != nil || info.Registrar != nil {
			t.Errorf("checkDomainInfo() with no getter = %+v, want nothing read", *info)
		}
	})
}

// TestMain leaves registrations unread by default: the tests that exercise
// the report generator on real messages must not depend on registries
// answering, and the ones about registrations inject a registry of their
// own.
func TestMain(m *testing.M) {
	domainInfoDisabled = true
	os.Exit(m.Run())
}
