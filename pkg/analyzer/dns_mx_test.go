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
	"slices"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

func TestCheckMXRecordsTargets(t *testing.T) {
	f := &fakeResolver{
		mx: map[string][]*net.MX{
			"null.example":   {{Host: ".", Pref: 0}},
			"good.example":   {{Host: "mx.good.example.", Pref: 10}},
			"alias.example":  {{Host: "mx.alias.example.", Pref: 10}},
			"ip.example":     {{Host: "192.0.2.25", Pref: 10}},
			"dangle.example": {{Host: "nowhere.dangle.example.", Pref: 10}},
			"lan.example":    {{Host: "mx.lan.example.", Pref: 10}},
			"mixed.example":  {{Host: "mx.mixed.example.", Pref: 10}},
		},
		hosts: map[string][]string{
			"mx.good.example":  {"192.0.2.25", "2001:db8::25"},
			"mx.alias.example": {"192.0.2.26"},
			"mx.lan.example":   {"10.0.0.25", "127.0.0.1"},
			"mx.mixed.example": {"192.0.2.27", "192.168.1.27"},
			"null.example":     {"192.0.2.80"},
		},
		cname: map[string]string{"mx.alias.example": "mx.provider.example.net"},
	}
	d := newFakeAnalyzer(f)

	mxOf := func(domain string) []model.MXRecord {
		records, failure := d.checkMXRecords(domain)
		if failure != "" || records == nil {
			t.Fatalf("lookup of %s failed: %s", domain, failure)
		}
		return *records
	}

	null := mxOf("null.example")
	if len(null) != 1 || !utils.Deref(null[0].NullMx) || null[0].Host != "." || null[0].Valid {
		t.Errorf("null MX = %+v, want a single null MX, leading nowhere", null)
	}
	if slices.Contains(f.queries, "A null.example") {
		t.Error("a null MX target must not be resolved")
	}

	good := mxOf("good.example")
	if !good[0].Valid || good[0].Error != nil || len(deref(good[0].Addresses)) != 2 || good[0].CnameTarget != nil {
		t.Errorf("good MX = %+v", good[0])
	}

	alias := mxOf("alias.example")
	if !alias[0].Valid || utils.Deref(alias[0].CnameTarget) != "mx.provider.example.net" {
		t.Errorf("aliased MX = %+v, want a valid record naming its canonical target", alias[0])
	}

	for _, domain := range []string{"ip.example", "dangle.example", "lan.example"} {
		rec := mxOf(domain)[0]
		if rec.Valid || rec.Error == nil {
			t.Errorf("%s: MX = %+v, want invalid with an error", domain, rec)
		}
	}

	mixed := mxOf("mixed.example")[0]
	if !mixed.Valid || mixed.Error == nil {
		t.Errorf("mixed MX = %+v, want valid but with a warning", mixed)
	}
}

func TestNullMXCannotReceive(t *testing.T) {
	f := &fakeResolver{
		mx: map[string][]*net.MX{
			"sub.example.com": {{Host: ".", Pref: 0}},
			"example.com":     {{Host: "mx.example.com.", Pref: 10}},
		},
		hosts: map[string][]string{"sub.example.com": {"192.0.2.1"}},
	}
	d := newFakeAnalyzer(f)
	got := d.checkReturnOKDomain("sub.example.com", "example.com")
	if got.Status != returnOKStatusFail || got.OrgDomain != nil {
		t.Errorf("null MX domain = %+v, want fail without falling back on the organizational domain", got)
	}
}

func TestDomainOnlyNullMXIssues(t *testing.T) {
	f := &fakeResolver{
		mx:  map[string][]*net.MX{"example.com": {{Host: ".", Pref: 0}}},
		txt: map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"}},
	}
	d := newFakeAnalyzer(f)
	results := d.AnalyzeDomainOnly("example.com")
	d.CalculateDomainOnlyScore(results)
	issues := deref(results.Issues.MxFrom)
	if null := hasIssue(issues, model.IssueTypeMxNull); null == nil || *null.Penalty == 0 {
		t.Errorf("issues = %v, want a charged mx_null", issueTypes(issues))
	}
}

func TestMXIssuesTargets(t *testing.T) {
	tests := []struct {
		name    string
		records []model.MXRecord
		score   int
		want    []model.IssueType
	}{
		{"healthy dual-stack", []model.MXRecord{{Host: "mx.example.com.", Valid: true, Addresses: &[]string{"192.0.2.1", "2001:db8::1"}}}, 100, []model.IssueType{}},
		{"IPv4 only", []model.MXRecord{{Host: "mx.example.com.", Valid: true, Addresses: &[]string{"192.0.2.1"}}}, 100, []model.IssueType{model.IssueTypeMxNoIpv6}},
		{"CNAME target", []model.MXRecord{{Host: "mx.example.com.", Valid: true, CnameTarget: utils.PtrTo("mx.example.net"), Addresses: &[]string{"2001:db8::1"}}}, 90, []model.IssueType{model.IssueTypeMxCname}},
		{"partly private", []model.MXRecord{{Host: "mx.example.com.", Valid: true, Error: utils.PtrTo("also private"), Addresses: &[]string{"2001:db8::1", "10.0.0.1"}}}, 100, []model.IssueType{model.IssueTypeMxInvalid}},
		{"only target is an IP", []model.MXRecord{{Host: "192.0.2.1", Valid: false, Error: utils.PtrTo("192.0.2.1 is an IP address")}}, 0, []model.IssueType{model.IssueTypeMxInvalid}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := checkScore{score: 100}
			records := tt.records
			mxIssues(&c, "example.com", &records, &model.ReturnOKDomain{Status: returnOKStatusPass}, 100, "replies")
			got := issueTypes(c.issues)
			if c.score != tt.score || len(got) != len(tt.want) {
				t.Fatalf("score = %d, issues = %v; want %d, %v", c.score, got, tt.score, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("issues = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// A null MX on the Return-Path domain of a received message loses its
// bounces: the analysis of received mail charges it like the domain test.
func TestReceivedMailNullMXReturnPath(t *testing.T) {
	f := &fakeResolver{
		mx: map[string][]*net.MX{
			"example.com":         {{Host: "mx.example.com.", Pref: 10}},
			"bounces.example.net": {{Host: ".", Pref: 0}},
		},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.1", "2001:db8::1"}},
	}
	d := newFakeAnalyzer(f)
	email, err := mailmsg.Parse([]byte("From: alice@example.com\r\nSubject: hi\r\n\r\nHello\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	results := d.AnalyzeDNS(email, &model.HeaderAnalysis{DomainAlignment: &model.DomainAlignment{
		FromDomain:       utils.PtrTo("example.com"),
		ReturnPathDomain: utils.PtrTo("bounces.example.net"),
	}}, nil)
	d.CalculateDNSScore(results, "")

	if results.ReturnOk.ReturnPath.Status != returnOKStatusFail {
		t.Errorf("Return-Path reachability = %+v, want fail", results.ReturnOk.ReturnPath)
	}
	issues := deref(results.Issues.MxReturnPath)
	if null := hasIssue(issues, model.IssueTypeMxNull); null == nil || *null.Penalty == 0 {
		t.Errorf("Return-Path issues = %+v, want a charged mx_null", issues)
	}
	if hasIssue(deref(results.Issues.MxFrom), model.IssueTypeMxNull) != nil {
		t.Error("the From domain, which has MX records, was charged for the Return-Path")
	}
}
