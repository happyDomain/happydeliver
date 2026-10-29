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
	"fmt"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// penalties adds up what the issues say they cost.
func penalties(issues []model.Issue) (sum int) {
	for _, issue := range issues {
		sum += *issue.Penalty
	}
	return
}

func issueTypes(issues []model.Issue) (out []model.IssueType) {
	for _, issue := range issues {
		out = append(out, issue.Type)
	}
	return
}

func TestSPFScoreIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	enforced := &model.DMARCRecord{Valid: true, Policy: utils.PtrTo(model.DMARCRecordPolicy("reject"))}
	record := func(qualifier string) []model.SPFRecord {
		r := model.SPFRecord{Domain: utils.PtrTo("example.com"), Record: utils.PtrTo("v=spf1 mx " + qualifier + "all"), Valid: true}
		if qualifier != "" {
			r.AllQualifier = utils.PtrTo(model.SPFRecordAllQualifier(qualifier))
		}
		return []model.SPFRecord{r}
	}

	tests := []struct {
		name     string
		records  *[]model.SPFRecord
		dmarc    *model.DMARCRecord
		score    int
		types    []model.IssueType
		severity model.IssueSeverity
	}{
		{"strict", utils.PtrTo(record("-")), nil, 100, nil, ""},
		{"no record", nil, nil, 0, []model.IssueType{model.IssueTypeSpfMissing}, model.IssueSeverityHigh},
		{"softfail alone", utils.PtrTo(record("~")), nil, 75, []model.IssueType{model.IssueTypeSpfAllSoftfail}, model.IssueSeverityMedium},
		{"softfail behind DMARC", utils.PtrTo(record("~")), enforced, 95, []model.IssueType{model.IssueTypeSpfAllSoftfail}, model.IssueSeverityLow},
		{"pass", utils.PtrTo(record("+")), nil, 50, []model.IssueType{model.IssueTypeSpfAllPass}, model.IssueSeverityHigh},
		{"pass behind DMARC", utils.PtrTo(record("+")), enforced, 75, []model.IssueType{model.IssueTypeSpfAllPass}, model.IssueSeverityHigh},
		{"neutral", utils.PtrTo(record("?")), nil, 50, []model.IssueType{model.IssueTypeSpfAllNeutral}, model.IssueSeverityMedium},
		{"no all", utils.PtrTo(record("")), nil, 50, []model.IssueType{model.IssueTypeSpfAllMissing}, model.IssueSeverityMedium},
		{"invalid", &[]model.SPFRecord{{Domain: utils.PtrTo("example.com"), Record: utils.PtrTo("v=spf1 foo"), Error: utils.PtrTo("unknown mechanism")}}, nil, 25, []model.IssueType{model.IssueTypeSpfInvalid}, model.IssueSeverityHigh},
		{"broken include", utils.PtrTo(append(record("-"), model.SPFRecord{Domain: utils.PtrTo("spf.example.net"), Error: utils.PtrTo("Failed to lookup TXT records")})), nil, 100, []model.IssueType{model.IssueTypeSpfIncludeInvalid}, model.IssueSeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.DNSResults{FromDomain: "example.com", SpfRecords: tt.records, DmarcRecord: tt.dmarc}
			score, findings := analyzer.calculateSPFScore(results)
			if score != tt.score {
				t.Errorf("score = %d, want %d", score, tt.score)
			}
			if got := issueTypes(findings); len(got) != len(tt.types) || (len(got) > 0 && got[0] != tt.types[0]) {
				t.Fatalf("types = %v, want %v", got, tt.types)
			}
			if len(findings) > 0 && findings[0].Severity != tt.severity {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tt.severity)
			}
			if got := penalties(findings); got != 100-score {
				t.Errorf("penalties add up to %d, the check lost %d", got, 100-score)
			}
		})
	}
}

func TestDKIMScoreIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	key := func(selector string, size int, algorithm string) model.DKIMRecord {
		return model.DKIMRecord{Selector: selector, Domain: "example.com", Valid: true, KeySize: utils.PtrTo(size), SigningAlgorithm: utils.PtrTo(algorithm)}
	}

	tests := []struct {
		name    string
		records *[]model.DKIMRecord
		score   int
		types   []model.IssueType
	}{
		{"sound", &[]model.DKIMRecord{key("s1", 2048, "rsa-sha256")}, 100, nil},
		{"unsigned", nil, 0, []model.IssueType{model.IssueTypeDkimMissing}},
		{"weak key", &[]model.DKIMRecord{key("s1", 1024, "rsa-sha256")}, 75, []model.IssueType{model.IssueTypeDkimKeyWeak}},
		{"short key", &[]model.DKIMRecord{key("s1", 512, "rsa-sha256")}, 25, []model.IssueType{model.IssueTypeDkimKeyShort}},
		// SHA-1 caps at 60 first; the weak key's cap of 75 is already reached
		{"sha1 and weak key", &[]model.DKIMRecord{key("s1", 1024, "rsa-sha1")}, 60, []model.IssueType{model.IssueTypeDkimSha1, model.IssueTypeDkimKeyWeak}},
		{"only broken keys", &[]model.DKIMRecord{{Selector: "s1", Domain: "example.com", Error: utils.PtrTo("no key")}, {Selector: "s2", Domain: "example.com"}}, 25, []model.IssueType{model.IssueTypeDkimInvalid, model.IssueTypeDkimInvalid}},
		{"broken key next to a sound one", &[]model.DKIMRecord{{Selector: "s1", Domain: "example.com"}, key("s2", 2048, "rsa-sha256")}, 100, []model.IssueType{model.IssueTypeDkimInvalid}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, findings := analyzer.calculateDKIMScore(&model.DNSResults{FromDomain: "example.com", DkimRecords: tt.records})
			if score != tt.score {
				t.Errorf("score = %d, want %d", score, tt.score)
			}
			got := issueTypes(findings)
			if len(got) != len(tt.types) {
				t.Fatalf("types = %v, want %v", got, tt.types)
			}
			for i := range got {
				if got[i] != tt.types[i] {
					t.Errorf("types = %v, want %v", got, tt.types)
				}
			}
			if got := penalties(findings); got != 100-score {
				t.Errorf("penalties add up to %d, the check lost %d", got, 100-score)
			}
		})
	}
}

// An Ed25519 key is short by RSA standards, and sound.
func TestDKIMScoreSparesEd25519(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	score, issues := analyzer.calculateDKIMScore(&model.DNSResults{DkimRecords: &[]model.DKIMRecord{{
		Selector: "s1", Domain: "example.com", Valid: true,
		KeyType: utils.PtrTo("ed25519"), KeySize: utils.PtrTo(256), SigningAlgorithm: utils.PtrTo("ed25519-sha256"),
	}}})
	if score != 100 || len(issues) != 0 {
		t.Errorf("score = %d, issues = %v; want 100 and none", score, issueTypes(issues))
	}
}

// The policy that applies is the one a redirect= leads to, and the issue says where it is.
func TestSPFScoreFollowsRedirect(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{FromDomain: "example.com", SpfRecords: &[]model.SPFRecord{
		{Domain: utils.PtrTo("example.com"), Record: utils.PtrTo("v=spf1 redirect=_spf.example.net"), Valid: true},
		{Domain: utils.PtrTo("_spf.example.net"), Record: utils.PtrTo("v=spf1 mx ~all"), Valid: true, AllQualifier: utils.PtrTo(model.SPFRecordAllQualifier("~"))},
	}}
	score, issues := analyzer.calculateSPFScore(results)
	if score != 75 || len(issues) != 1 || issues[0].Type != model.IssueTypeSpfAllSoftfail {
		t.Fatalf("score = %d, issues = %v; want 75 and spf_all_softfail", score, issueTypes(issues))
	}
	if issues[0].Location == nil || *issues[0].Location != "_spf.example.net" {
		t.Errorf("location = %v, want _spf.example.net", issues[0].Location)
	}
}

// A domain test weighs SPF 30 out of 100.
func TestDomainOnlyScoreWeighsSPFIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{FromDomain: "example.com"}
	analyzer.CalculateDomainOnlyScore(results)
	if results.Issues == nil || results.Issues.Spf == nil || len(*results.Issues.Spf) != 1 {
		t.Fatalf("SPF issues = %v, want one", results.Issues)
	}
	if got := *(*results.Issues.Spf)[0].Penalty; got != 30 {
		t.Errorf("a missing SPF record costs %d points, want 30", got)
	}
}

// The section charges each finding its share of the section score, so the
// penalties tell what fixing each would bring back to the grade.
func TestDNSScoreWeighsIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain:  "example.com",
		DkimRecords: &[]model.DKIMRecord{{Selector: "s1", Domain: "example.com", Valid: true, KeySize: utils.PtrTo(1024)}},
	}

	analyzer.CalculateDNSScore(results, "")

	if results.Issues == nil || results.Issues.Spf == nil || results.Issues.Dkim == nil {
		t.Fatal("no issues reported")
	}
	for _, issue := range append(*results.Issues.Spf, *results.Issues.Dkim...) {
		// Without a sender IP, four checks of 20 points: a check's 100 is 25 section points.
		want := map[model.IssueType]int{model.IssueTypeSpfMissing: 25, model.IssueTypeDkimKeyWeak: 6}[issue.Type]
		if *issue.Penalty != want {
			t.Errorf("%s costs %d section points, want %d", issue.Type, *issue.Penalty, want)
		}
	}
}

// A check that found nothing still says so, unlike one the version did not score.
func TestDNSScoreReportsScoredChecks(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain: "example.com",
		SpfRecords: &[]model.SPFRecord{{Domain: utils.PtrTo("example.com"), Record: utils.PtrTo("v=spf1 -all"), Valid: true, AllQualifier: utils.PtrTo(model.SPFRecordAllQualifier("-"))}},
	}

	analyzer.CalculateDomainOnlyScore(results)

	if results.Issues == nil || results.Issues.Spf == nil || len(*results.Issues.Spf) != 0 {
		t.Fatalf("SPF issues = %v, want an empty list", results.Issues)
	}
	if results.Issues.Dkim != nil {
		t.Errorf("DKIM issues = %v, want none: a domain test does not score DKIM", *results.Issues.Dkim)
	}
}

func TestDMARCScoreIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	policy := func(p string) *model.DMARCRecordPolicy { return utils.PtrTo(model.DMARCRecordPolicy(p)) }

	tests := []struct {
		name   string
		record *model.DMARCRecord
		score  int
		types  []model.IssueType
	}{
		{"reject", &model.DMARCRecord{Valid: true, Policy: policy("reject")}, 105, nil},
		{"missing", nil, 0, []model.IssueType{model.IssueTypeDmarcMissing}},
		{"invalid", &model.DMARCRecord{Record: utils.PtrTo("v=DMARC1; p=bogus")}, 20, []model.IssueType{model.IssueTypeDmarcInvalid}},
		{"none", &model.DMARCRecord{Valid: true, Policy: policy("none")}, 55, []model.IssueType{model.IssueTypeDmarcPolicyNone}},
		// The bonus above 100 absorbs part of what a quarantine costs
		{"quarantine", &model.DMARCRecord{Valid: true, Policy: policy("quarantine")}, 80, []model.IssueType{model.IssueTypeDmarcPolicyQuarantine}},
		{"reject in test mode", &model.DMARCRecord{Valid: true, Policy: policy("reject"), TestMode: utils.PtrTo(true)}, 80, []model.IssueType{model.IssueTypeDmarcTestMode}},
		{"weaker subdomains", &model.DMARCRecord{Valid: true, Policy: policy("reject"), SubdomainPolicy: utils.PtrTo(model.DMARCRecordSubdomainPolicy("none"))}, 75, []model.IssueType{model.IssueTypeDmarcSpWeaker}},
		{"half applied", &model.DMARCRecord{Valid: true, Policy: policy("reject"), Percentage: utils.PtrTo(50)}, 52, []model.IssueType{model.IssueTypeDmarcPct}},
		{"quarantine in test mode", &model.DMARCRecord{Valid: true, Policy: policy("quarantine"), TestMode: utils.PtrTo(true)}, 55, []model.IssueType{model.IssueTypeDmarcPolicyQuarantine, model.IssueTypeDmarcTestMode}},
		// t=y has no level below none to soften it to
		{"none in test mode", &model.DMARCRecord{Valid: true, Policy: policy("none"), TestMode: utils.PtrTo(true)}, 55, []model.IssueType{model.IssueTypeDmarcPolicyNone}},
		{"weaker non-existent subdomains", &model.DMARCRecord{Valid: true, Policy: policy("reject"), NonexistentSubdomainPolicy: utils.PtrTo(model.DMARCRecordNonexistentSubdomainPolicy("none"))}, 75, []model.IssueType{model.IssueTypeDmarcNpWeaker}},
		// Strict alignment earns 10 above 100, which absorb as much of a quarantine
		{"strict alignment absorbs a quarantine", &model.DMARCRecord{Valid: true, Policy: policy("quarantine"), SpfAlignment: utils.PtrTo(model.DMARCRecordSpfAlignmentStrict), DkimAlignment: utils.PtrTo(model.DMARCRecordDkimAlignmentStrict)}, 90, []model.IssueType{model.IssueTypeDmarcPolicyQuarantine}},
		{"pct=0", &model.DMARCRecord{Valid: true, Policy: policy("reject"), Percentage: utils.PtrTo(0)}, 0, []model.IssueType{model.IssueTypeDmarcPct}},
		// sp=quarantine matches the policy in effect once t=y applies
		{"sp judged against the policy in effect", &model.DMARCRecord{Valid: true, Policy: policy("reject"), TestMode: utils.PtrTo(true), SubdomainPolicy: utils.PtrTo(model.DMARCRecordSubdomainPolicy("quarantine"))}, 80, []model.IssueType{model.IssueTypeDmarcTestMode}},
		{"deprecated tags", &model.DMARCRecord{Valid: true, Policy: policy("reject"), DeprecatedRf: utils.PtrTo(true), DeprecatedPct: utils.PtrTo(true), Percentage: utils.PtrTo(100)}, 105, []model.IssueType{model.IssueTypeDmarcPctDeprecated, model.IssueTypeDmarcDeprecatedTags}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, issues := analyzer.calculateDMARCScore(&model.DNSResults{FromDomain: "example.com", DmarcRecord: tt.record})
			if score != tt.score {
				t.Errorf("score = %d, want %d", score, tt.score)
			}
			if got := issueTypes(issues); fmt.Sprint(got) != fmt.Sprint(tt.types) {
				t.Errorf("types = %v, want %v", got, tt.types)
			}
			if got := penalties(issues); got != 100-min(score, 100) {
				t.Errorf("penalties add up to %d, the check lost %d", got, 100-min(score, 100))
			}
		})
	}
}

func TestPTRMissingIssue(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{FromDomain: "example.com"}
	analyzer.CalculateDNSScore(results, "192.0.2.1")
	ptr := *results.Issues.Ptr
	if len(ptr) != 1 || ptr[0].Type != model.IssueTypePtrMissing || *ptr[0].Penalty != 20 {
		t.Errorf("PTR issues = %v, want ptr_missing costing the whole check, 20 points", ptr)
	}
	if len(*results.Issues.Fcrdns) != 0 || len(*results.Issues.HeloPtr) != 0 {
		t.Errorf("FCrDNS/HELO issues = %v/%v, want none without a PTR record", *results.Issues.Fcrdns, *results.Issues.HeloPtr)
	}

	noIP := &model.DNSResults{FromDomain: "example.com"}
	analyzer.CalculateDNSScore(noIP, "")
	if noIP.Issues.Ptr != nil || noIP.Issues.Fcrdns != nil || noIP.Issues.HeloPtr != nil {
		t.Errorf("reverse DNS issues reported though no sender IP was checked")
	}
}

func TestPTRScoreIssuesByCheck(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain:        "example.com",
		SenderIp:          utils.PtrTo("192.0.2.1"),
		PtrRecords:        &[]string{"a.example.com", "b.example.com"},
		PtrForwardRecords: &[]string{"192.0.2.2"},
		HeloHostname:      utils.PtrTo("mail.example.com"),
		HeloPtrMatch:      utils.PtrTo(false),
	}

	analyzer.CalculateDNSScore(results, "192.0.2.1")

	for name, got := range map[string]*[]model.Issue{
		"ptr":      results.Issues.Ptr,
		"fcrdns":   results.Issues.Fcrdns,
		"helo_ptr": results.Issues.HeloPtr,
	} {
		if got == nil || len(*got) != 1 {
			t.Errorf("%s issues = %v, want one", name, got)
		}
	}
	// Five checks of 20 points: a check's 100 is 20 section points.
	if p := *(*results.Issues.Fcrdns)[0].Penalty; p != 10 {
		t.Errorf("FCrDNS costs %d section points, want 10", p)
	}
}

func TestMXIssuesWithoutAValidRecord(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain:    "example.com",
		FromMxRecords: &[]model.MXRecord{{Host: "old.example.com", Error: utils.PtrTo("no address")}},
	}
	score, from, rp := analyzer.calculateMXScore(results)
	if score != 0 || len(from) != 1 || from[0].Type != model.IssueTypeMxInvalid || from[0].Severity != model.IssueSeverityHigh || *from[0].Penalty != 100 {
		t.Errorf("score = %d, From issues = %v, want one high mx_invalid costing 100", score, from)
	}
	if rp != nil {
		t.Errorf("Return-Path issues = %v, want none", rp)
	}
}

func TestMXIssueOfAnImplicitMX(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain: "example.com",
		ReturnOk:   &model.ReturnOK{From: &model.ReturnOKDomain{Domain: "example.com", Status: returnOKStatusWarn}},
	}
	_, from, _ := analyzer.calculateMXScore(results)
	if len(from) != 1 || from[0].Type != model.IssueTypeMxMissing || !strings.Contains(from[0].Message, "implicit MX") {
		t.Errorf("From issues = %v, want mx_missing about the implicit MX", from)
	}
}

func TestUnreachableDomainsChargedApart(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain: "example.com",
		RpDomain:   utils.PtrTo("bounces.example.net"),
		ReturnOk: &model.ReturnOK{
			From:       &model.ReturnOKDomain{Domain: "example.com", Status: returnOKStatusFail},
			ReturnPath: &model.ReturnOKDomain{Domain: "bounces.example.net", Status: returnOKStatusFail},
		},
	}
	analyzer.CalculateDNSScore(results, "")
	for name, issues := range map[string]*[]model.Issue{"From": results.Issues.MxFrom, "Return-Path": results.Issues.MxReturnPath} {
		// Half the MX check (13 section points, rounded) and 10 for the domain
		if issues == nil || len(*issues) != 1 || (*issues)[0].Type != model.IssueTypeDomainUnreachable || *(*issues)[0].Penalty != 23 {
			t.Errorf("%s issues = %v, want one domain_unreachable costing 23", name, issues)
		}
	}
}

// A domain that cannot receive mail is told once, with its MX records, and
// charged both what the MX check loses and what the section takes off.
func TestUnreachableDomainIssues(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain: "example.com",
		RpDomain:   utils.PtrTo("example.com"),
		ReturnOk: &model.ReturnOK{
			From:       &model.ReturnOKDomain{Domain: "example.com", Status: returnOKStatusFail},
			ReturnPath: &model.ReturnOKDomain{Domain: "example.com", Status: returnOKStatusFail},
		},
	}

	analyzer.CalculateDNSScore(results, "")

	if results.Issues.MxReturnPath != nil {
		t.Errorf("Return-Path issues = %v, want none: it is the From domain", *results.Issues.MxReturnPath)
	}
	got := *results.Issues.MxFrom
	if len(got) != 1 || got[0].Type != model.IssueTypeDomainUnreachable {
		t.Fatalf("From issues = %v, want one domain_unreachable", got)
	}
	// The whole MX check (25 section points out of 4 checks) and 10 per role
	if *got[0].Penalty != 45 {
		t.Errorf("penalty = %d, want 45", *got[0].Penalty)
	}
}

func TestMXIssuesOfAnotherReturnPath(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)
	results := &model.DNSResults{
		FromDomain:    "example.com",
		FromMxRecords: &[]model.MXRecord{{Host: "mx.example.com", Valid: true}, {Host: "old.example.com", Error: utils.PtrTo("no address")}},
		RpDomain:      utils.PtrTo("bounces.example.net"),
	}

	score, from, rp := analyzer.calculateMXScore(results)

	if score != 50 {
		t.Errorf("score = %d, want 50", score)
	}
	if fmt.Sprint(issueTypes(from)) != fmt.Sprint([]model.IssueType{model.IssueTypeMxInvalid}) || *from[0].Penalty != 0 {
		t.Errorf("From issues = %v, want one free mx_invalid", from)
	}
	if fmt.Sprint(issueTypes(rp)) != fmt.Sprint([]model.IssueType{model.IssueTypeMxMissing}) || *rp[0].Penalty != 50 {
		t.Errorf("Return-Path issues = %v, want mx_missing costing 50", rp)
	}
}
