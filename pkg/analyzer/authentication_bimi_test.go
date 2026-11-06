// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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

func TestParseBIMIResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   model.AuthResultResult
		expectedDomain   string
		expectedSelector string
	}{
		{
			name:             "BIMI pass with domain and selector",
			part:             "bimi=pass header.d=example.com header.selector=default",
			expectedResult:   model.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
		{
			name:             "BIMI fail",
			part:             "bimi=fail header.d=example.com header.selector=default",
			expectedResult:   model.AuthResultResultFail,
			expectedDomain:   "example.com",
			expectedSelector: "default",
		},
		{
			name:             "BIMI with short form (d= and selector=)",
			part:             "bimi=pass d=example.com selector=v1",
			expectedResult:   model.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedSelector: "v1",
		},
		{
			name:           "BIMI none",
			part:           "bimi=none header.d=example.com",
			expectedResult: model.AuthResultResultNone,
			expectedDomain: "example.com",
		},
	}

	analyzer := NewAuthenticationAnalyzer("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseBIMIResult(readMethod(t, tt.part))

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}
			if result.Domain == nil || *result.Domain != tt.expectedDomain {
				var gotDomain string
				if result.Domain != nil {
					gotDomain = *result.Domain
				}
				t.Errorf("Domain = %v, want %v", gotDomain, tt.expectedDomain)
			}
			if tt.expectedSelector != "" {
				if result.Selector == nil || *result.Selector != tt.expectedSelector {
					var gotSelector string
					if result.Selector != nil {
						gotSelector = *result.Selector
					}
					t.Errorf("Selector = %v, want %v", gotSelector, tt.expectedSelector)
				}
			}
		})
	}
}

// A declined BIMI costs the section what its issue says: the score and the
// issue round differently, so the value has to come out even on the weight.
func TestBIMIDeclinedIssueMatchesTheScore(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	pass := &model.AuthResult{Result: model.AuthResultResultPass}
	results := &model.AuthenticationResults{
		Spf: pass, Dkim: &[]model.AuthResult{*pass}, Dmarc: pass,
		Bimi: &model.AuthResult{Result: model.AuthResultResultDeclined},
	}
	enforced := &model.DMARCRecord{Valid: true, Policy: utils.PtrTo(model.DMARCRecordPolicy("reject"))}

	dns := &model.DNSResults{FromDomain: "example.com", DmarcRecord: enforced}
	score, _ := a.CalculateAuthenticationScore(results, dns)
	a.ReportIssues(results, dns, model.ReportSourceReceived)

	issues := *results.Issues.Bimi
	if len(issues) != 1 || 100-score != *issues[0].Penalty {
		t.Errorf("score = %d, issues = %+v: the penalty must be what the score lost", score, issues)
	}
}

// A pass only earns all the points with a valid mark certificate behind the
// logo, the receiver reporting the same without one.
func TestBIMIPassNeedsACertificate(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	enforced := &model.DMARCRecord{Valid: true, Policy: utils.PtrTo(model.DMARCRecordPolicy("reject"))}

	tests := []struct {
		name      string
		authority *string
		record    *model.BIMIRecord
		wantScore int
		wantIssue model.IssueType
	}{
		{"not analysed", nil, nil, 100, ""},
		{"valid certificate", nil, &model.BIMIRecord{Valid: true, Vmc: &model.VMCInfo{Valid: true}}, 100, ""},
		{"self-asserted", nil, &model.BIMIRecord{Valid: true, VmcUrl: utils.PtrTo("")}, 50, model.IssueTypeBimiVmcMissing},
		{"invalid certificate", nil, &model.BIMIRecord{Vmc: &model.VMCInfo{Valid: false}}, 50, model.IssueTypeBimiUnverified},
		// The receiver's word goes before an analysis made afterwards
		{"receiver vouches", utils.PtrTo("pass"), &model.BIMIRecord{Valid: true, VmcUrl: utils.PtrTo("")}, 100, ""},
		{"receiver refuses", utils.PtrTo("fail"), &model.BIMIRecord{Valid: true, Vmc: &model.VMCInfo{Valid: true}}, 50, model.IssueTypeBimiUnverified},
		{"receiver refuses, not analysed", utils.PtrTo("fail"), nil, 50, model.IssueTypeBimiUnverified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{Bimi: &model.AuthResult{Result: model.AuthResultResultPass, Authority: tt.authority}, Spf: &model.AuthResult{Result: model.AuthResultResultPass}}
			dns := &model.DNSResults{FromDomain: "example.com", DmarcRecord: enforced, BimiRecord: tt.record}

			if score := a.calculateBIMIScore(results, dns); score != tt.wantScore {
				t.Errorf("score = %d, want %d", score, tt.wantScore)
			}

			a.ReportIssues(results, dns, model.ReportSourceReceived)
			issues := *results.Issues.Bimi
			switch {
			case tt.wantIssue == "" && len(issues) != 0:
				t.Errorf("issues = %+v, want none", issues)
			case tt.wantIssue != "" && (len(issues) != 1 || issues[0].Type != tt.wantIssue || *issues[0].Penalty != 5):
				t.Errorf("issues = %+v, want one %s costing 5", issues, tt.wantIssue)
			}
		})
	}
}

// policy.authority is read off the verdict, and stays absent when not written.
func TestParseBIMIAuthority(t *testing.T) {
	a := NewAuthenticationAnalyzer("")
	for part, want := range map[string]*string{
		"bimi=pass header.d=example.com policy.authority=pass": utils.PtrTo("pass"),
		"bimi=fail policy.authority=fail":                      utils.PtrTo("fail"),
		"bimi=pass header.d=example.com":                       nil,
	} {
		got := a.parseBIMIResult(readMethod(t, part)).Authority
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: authority = %v, want %v", part, got, want)
		}
	}
}
