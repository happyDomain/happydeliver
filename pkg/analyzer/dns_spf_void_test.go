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
	"net"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func TestSPFVoidLookups(t *testing.T) {
	servfail := &net.DNSError{Err: "server misbehaving", Name: "flaky.example.net", IsTemporary: true}
	tests := []struct {
		name      string
		txt       map[string][]string
		mx        map[string][]*net.MX
		hosts     map[string][]string
		err       map[string]error
		wantVoids int
		wantSev   model.IssueSeverity // "" for no issue
		wantScore int
	}{
		{
			name:      "none",
			txt:       map[string][]string{"example.com": {"v=spf1 a mx include:_spf.example.net -all"}, "_spf.example.net": {"v=spf1 ip4:192.0.2.0/24 -all"}},
			mx:        map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
			hosts:     map[string][]string{"example.com": {"192.0.2.1"}},
			wantVoids: 0,
			wantScore: 100,
		},
		{
			name:      "one dangling include",
			txt:       map[string][]string{"example.com": {"v=spf1 include:gone.example.net -all"}},
			wantVoids: 1,
			wantSev:   model.IssueSeverityMedium,
			wantScore: 100,
		},
		{
			name: "three voids across includes",
			txt: map[string][]string{
				"example.com":      {"v=spf1 a:old.example.com include:_spf.example.net -all"},
				"_spf.example.net": {"v=spf1 mx:retired.example.net exists:nothing.example.net -all"},
			},
			wantVoids: 3,
			wantSev:   model.IssueSeverityHigh,
			wantScore: 25,
		},
		{
			// Counted, though the missing policy it leads to is what the
			// score tells
			name:      "dangling redirect",
			txt:       map[string][]string{"example.com": {"v=spf1 redirect=gone.example.net"}},
			wantVoids: 1,
			wantScore: 0,
		},
		{
			// A lookup that fails is unanswered, not void
			name:      "SERVFAIL is not void",
			txt:       map[string][]string{"example.com": {"v=spf1 a:flaky.example.net -all"}},
			err:       map[string]error{"flaky.example.net": servfail},
			wantVoids: 0,
			wantScore: 100,
		},
		{
			name:      "macros are not counted",
			txt:       map[string][]string{"example.com": {"v=spf1 exists:%{i}.rbl.example.net -all"}},
			wantVoids: 0,
			wantScore: 100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newFakeAnalyzer(&fakeResolver{txt: tt.txt, mx: tt.mx, hosts: tt.hosts, err: tt.err})
			records := d.checkSPFRecords("example.com")
			if got := utils.Deref((*records)[0].VoidLookups); got != tt.wantVoids {
				t.Fatalf("void lookups = %d, want %d (records %+v)", got, tt.wantVoids, *records)
			}
			score, issues := d.calculateSPFScore(&model.DNSResults{FromDomain: "example.com", SpfRecords: records})
			issue := hasIssue(issues, model.IssueTypeSpfVoidLookups)
			switch {
			case tt.wantSev == "" && issue != nil:
				t.Errorf("unexpected issue %+v", issue)
			case tt.wantSev != "" && (issue == nil || issue.Severity != tt.wantSev):
				t.Errorf("issues = %+v, want spf_void_lookups of severity %s", issues, tt.wantSev)
			}
			if score != tt.wantScore {
				t.Errorf("score = %d, want %d", score, tt.wantScore)
			}
		})
	}
}

func TestSPFPtrMechanism(t *testing.T) {
	d := newFakeAnalyzer(&fakeResolver{
		txt: map[string][]string{
			"example.com":      {"v=spf1 include:_spf.example.net -all"},
			"_spf.example.net": {"v=spf1 ptr:example.net ip4:192.0.2.0/24 -all"},
		},
	})
	records := d.checkSPFRecords("example.com")
	score, issues := d.calculateSPFScore(&model.DNSResults{FromDomain: "example.com", SpfRecords: records})
	issue := hasIssue(issues, model.IssueTypeSpfPtr)
	if issue == nil || utils.Deref(issue.Location) != "_spf.example.net" || score != 90 {
		t.Errorf("score = %d, issues = %+v; want 90 with spf_ptr on _spf.example.net", score, issues)
	}
}
