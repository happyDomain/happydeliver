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
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func verdict(result model.AuthResultResult) *model.AuthResult {
	return &model.AuthResult{Result: result, Domain: utils.PtrTo("example.com")}
}

// Whatever the verdicts, every point a check takes off is charged to an
// issue saying why: the report never shows a lost point unexplained.
func TestAuthenticationIssuesExplainEveryLostPoint(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	enforced := &model.DMARCRecord{Valid: true, Policy: utils.PtrTo(model.DMARCRecordPolicy("reject"))}
	verdicts := []model.AuthResultResult{"", "pass", "fail", "softfail", "neutral", "none", "permerror", "temperror", "declined", "skipped"}
	of := func(r model.AuthResultResult) *model.AuthResult {
		if r == "" {
			return nil
		}
		return verdict(r)
	}

	for _, spf := range verdicts {
		for _, dkim := range verdicts {
			for _, dmarc := range verdicts {
				for _, bimi := range verdicts {
					results := &model.AuthenticationResults{Spf: of(spf), Dmarc: of(dmarc), Bimi: of(bimi)}
					if dkim != "" {
						results.Dkim = &[]model.AuthResult{*verdict(dkim)}
					}
					if !a.hasRequiredResults(results) {
						continue
					}
					a.ReportIssues(results, &model.DNSResults{FromDomain: "example.com", DmarcRecord: enforced}, model.ReportSourceReceived)

					charged, total := 0, 0
					for name, check := range map[string]struct {
						lost   int
						issues *[]model.Issue
					}{
						"spf":   {100 - a.calculateSPFScore(results), results.Issues.Spf},
						"dkim":  {100 - a.calculateDKIMScore(results), results.Issues.Dkim},
						"dmarc": {100 - a.calculateDMARCScore(results), results.Issues.Dmarc},
						"bimi":  {100 - a.calculateBIMIScore(results), results.Issues.Bimi},
					} {
						if check.issues == nil {
							t.Fatalf("%s/%s/%s/%s: no %s issues reported", spf, dkim, dmarc, bimi, name)
						}
						if check.lost > 0 && len(*check.issues) == 0 {
							t.Errorf("%s/%s/%s/%s: %s lost %d points and says nothing", spf, dkim, dmarc, bimi, name, check.lost)
						}
						if check.lost == 0 && len(*check.issues) > 0 && penalties(*check.issues) > 0 {
							t.Errorf("%s/%s/%s/%s: %s lost nothing but charges %d", spf, dkim, dmarc, bimi, name, penalties(*check.issues))
						}
						if p := penalties(*check.issues); p > 0 {
							charged++
							total += p
						}
					}

					// The penalties weigh each check as the score does: they add
					// up to what it lost, but for the rounding of each check. A
					// score clamped at 0 lost less than its checks did.
					if score, _ := a.CalculateAuthenticationScore(results); score > 0 {
						if diff := 100 - score - total; diff > charged || -diff > charged {
							t.Errorf("%s/%s/%s/%s: penalties add up to %d, the score lost %d", spf, dkim, dmarc, bimi, total, 100-score)
						}
					}
				}
			}
		}
	}
}

func TestAuthenticationIssuesWeighTheirVerdict(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	results := &model.AuthenticationResults{
		Spf:   verdict(model.AuthResultResultSoftfail),
		Dkim:  &[]model.AuthResult{*verdict(model.AuthResultResultPass), *verdict(model.AuthResultResultFail)},
		Dmarc: verdict(model.AuthResultResultPass),
		XTls:  verdict(model.AuthResultResultFail),
		Arc:   &model.ARCResult{Result: model.ARCResultResultFail},
	}

	a.ReportIssues(results, &model.DNSResults{FromDomain: "example.com"}, model.ReportSourceReceived)

	for _, tt := range []struct {
		name    string
		issues  *[]model.Issue
		typ     model.IssueType
		penalty int
	}{
		// softfail loses 83 of SPF's 100 points: 25 of its 30
		{"spf", results.Issues.Spf, model.IssueTypeSpfSoftfail, 25},
		{"dkim", results.Issues.Dkim, model.IssueTypeDkimExtraFail, 3},
		{"x_tls", results.Issues.XTls, model.IssueTypeTlsMissing, 10},
		// DMARC is not enforced: that is what BIMI is waiting for
		{"bimi", results.Issues.Bimi, model.IssueTypeBimiDmarcNotEnforced, 10},
		{"arc", results.Issues.Arc, model.IssueTypeArcFail, 0},
	} {
		if tt.issues == nil || len(*tt.issues) != 1 {
			t.Errorf("%s issues = %v, want one", tt.name, tt.issues)
			continue
		}
		if issue := (*tt.issues)[0]; issue.Type != tt.typ || *issue.Penalty != tt.penalty {
			t.Errorf("%s issue = %s costing %d, want %s costing %d", tt.name, issue.Type, *issue.Penalty, tt.typ, tt.penalty)
		}
	}
	if results.Issues.Dmarc == nil || len(*results.Issues.Dmarc) != 0 {
		t.Errorf("DMARC issues = %v, want an empty list for a pass", results.Issues.Dmarc)
	}
	if results.Issues.Iprev != nil {
		t.Errorf("iprev issues = %v, want none: the receiver reported no verdict", *results.Issues.Iprev)
	}
}

func TestAuthenticationIssuesWithoutVerdicts(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	for source, severity := range map[model.ReportSource]model.IssueSeverity{
		model.ReportSourceReceived: model.IssueSeverityInfo,
		model.ReportSourceUploaded: model.IssueSeverityMedium,
	} {
		results := &model.AuthenticationResults{XTls: verdict(model.AuthResultResultPass)}
		a.ReportIssues(results, nil, source)

		if results.Issues.Details == nil || len(*results.Issues.Details) != 1 || (*results.Issues.Details)[0].Severity != severity {
			t.Errorf("%s: details = %v, want one auth_unavailable of severity %s", source, results.Issues.Details, severity)
		}
		if results.Issues.Spf != nil || results.Issues.XTls != nil {
			t.Errorf("%s: checks reported issues though nothing was scored", source)
		}
	}
}

func TestAuthenticationIssuesOfAMissingVerdict(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	results := &model.AuthenticationResults{Spf: verdict(model.AuthResultResultPass)}

	a.ReportIssues(results, nil, model.ReportSourceUploaded)

	dkim := *results.Issues.Dkim
	if len(dkim) != 1 || dkim[0].Type != model.IssueTypeAuthUnevaluated || *dkim[0].Penalty != 30 {
		t.Errorf("DKIM issues = %v, want auth_unevaluated costing all 30 points", dkim)
	}
}

// Each verdict reports its own issue on its own check, charged as the
// authentication score weighs it.
func TestAuthenticationIssuesOfEachVerdict(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	enforced := &model.DMARCRecord{Valid: true, Policy: utils.PtrTo(model.DMARCRecordPolicy("reject"))}
	for _, tt := range []struct {
		name    string
		results model.AuthenticationResults
		check   func(*model.AuthenticationIssues) *[]model.Issue
		typ     model.IssueType
		penalty int // -1: not checked
	}{
		{"spf_helo fail", model.AuthenticationResults{Spf: verdict("pass"), SpfHelo: verdict("fail")}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.SpfHelo }, model.IssueTypeSpfHeloFail, 5},
		{"x_aligned_from fail", model.AuthenticationResults{Spf: verdict("pass"), XAlignedFrom: verdict("fail")}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.XAlignedFrom }, model.IssueTypeXAlignedFromFail, 5},
		{"iprev fail", model.AuthenticationResults{Spf: verdict("pass"), Iprev: &model.IPRevResult{Result: model.IPRevResultResultFail, Ip: utils.PtrTo("192.0.2.1")}}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.Iprev }, model.IssueTypeIprevFail, 7},
		{"dmarc permerror", model.AuthenticationResults{Dmarc: verdict("permerror")}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.Dmarc }, model.IssueTypeDmarcPermerror, -1},
		{"dmarc temperror", model.AuthenticationResults{Dmarc: verdict("temperror")}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.Dmarc }, model.IssueTypeDmarcTemperror, -1},
		{"bimi declined", model.AuthenticationResults{Spf: verdict("pass"), Bimi: verdict("declined")}, func(i *model.AuthenticationIssues) *[]model.Issue { return i.Bimi }, model.IssueTypeBimiDeclined, -1},
	} {
		results := tt.results
		a.ReportIssues(&results, &model.DNSResults{FromDomain: "example.com", DmarcRecord: enforced}, model.ReportSourceReceived)
		issues := tt.check(results.Issues)
		if issues == nil || len(*issues) != 1 || (*issues)[0].Type != tt.typ || (tt.penalty >= 0 && *(*issues)[0].Penalty != tt.penalty) {
			t.Errorf("%s: issues = %v, want one %s costing %d", tt.name, issues, tt.typ, tt.penalty)
		}
	}
}
