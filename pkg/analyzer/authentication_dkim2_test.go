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
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// The fields below are the examples of draft-gondwana-dkim2-authres-02, and
// the one Fastmail's receivers write today (fastmail/authentication_milter#187).
func TestParseDKIM2Result(t *testing.T) {
	tests := []struct {
		name            string
		header          string
		wantResult      model.DKIM2ResultResult
		wantDomain      string
		wantInstance    int
		wantCommentPart string
	}{
		{
			name:            "Fastmail, alongside dkim",
			header:          "phl-mx-03.messagingengine.com; dkim2=pass (i=1..1 verified) header.d=example.com header.i=1; dkim=pass (ed25519 key sha256) header.d=example.com header.i=@example.com header.b=zzu+rhcL header.a=ed25519-sha256 header.s=dkim-ed25519",
			wantResult:      model.DKIM2ResultResultPass,
			wantDomain:      "example.com",
			wantCommentPart: "i=1..1 verified",
		},
		{
			name:            "Mailing list, pass",
			header:          "mx.example.net; dkim2=pass (i=1 sender.example.com pass,\r\n i=2 list.example.org pass) header.d=sender.example.com",
			wantResult:      model.DKIM2ResultResultPass,
			wantDomain:      "sender.example.com",
			wantCommentPart: "i=2 list.example.org pass",
		},
		{
			name:            "Third hop fails, diagnostic after a semicolon",
			header:          "mx.example.net;\r\n dkim2=fail (i=1 sender.example.com skipped,\r\n i=2 list.example.org skipped, i=3 fwd.example.net fail,\r\n i=4 relay.example.net pass;\r\n FAIL: DKIM2-Signature i=3 selector sel1 incorrect signature)\r\n header.d=sender.example.com header.i=3",
			wantResult:      model.DKIM2ResultResultFail,
			wantDomain:      "sender.example.com",
			wantInstance:    3,
			wantCommentPart: "FAIL: DKIM2-Signature i=3 selector sel1 incorrect signature",
		},
		{
			name:         "Key could not be fetched",
			header:       "mx.example.net; dkim2=temperror (i=1 sender.example.com temperror; TEMPERROR: DKIM2-Signature i=1 public key sel1 could not be fetched) header.d=sender.example.com header.i=1",
			wantResult:   model.DKIM2ResultResultTemperror,
			wantDomain:   "sender.example.com",
			wantInstance: 1,
		},
		{
			name:            "Escaped parentheses in the comment",
			header:          `mx.example.net; dkim2=fail (i=1 sender.example.com pass, i=2 fwd.example.org fail; FAIL: DKIM2-Signature i=2 MAIL FROM <alice\(work\)@example.com> did not match) header.d=sender.example.com header.i=2`,
			wantResult:      model.DKIM2ResultResultFail,
			wantDomain:      "sender.example.com",
			wantInstance:    2,
			wantCommentPart: "did not match",
		},
		{
			name:       "No DKIM2 header at all",
			header:     "mx.example.net; dkim2=none",
			wantResult: model.DKIM2ResultResultNone,
		},
	}

	analyzer := NewAuthenticationAnalyzer("")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{}
			analyzer.parseAuthenticationResultsHeader(tt.header, results)

			got := results.Dkim2
			if got == nil {
				t.Fatalf("no dkim2 verdict read")
			}
			if got.Result != tt.wantResult {
				t.Errorf("Result = %v, want %v", got.Result, tt.wantResult)
			}
			if utils.Deref(got.Domain) != tt.wantDomain {
				t.Errorf("Domain = %q, want %q", utils.Deref(got.Domain), tt.wantDomain)
			}
			if utils.Deref(got.Instance) != tt.wantInstance {
				t.Errorf("Instance = %d, want %d", utils.Deref(got.Instance), tt.wantInstance)
			}
			if !strings.Contains(utils.Deref(got.Comment), tt.wantCommentPart) {
				t.Errorf("Comment = %q, want it to contain %q", utils.Deref(got.Comment), tt.wantCommentPart)
			}
		})
	}
}

// Both kinds of signature are read side by side, neither standing in for the
// other: header.i means a sequence number for dkim2, an identity for dkim.
func TestParseAuthenticationResultsKeepsDKIMAndDKIM2Apart(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")
	results := &model.AuthenticationResults{}
	analyzer.parseAuthenticationResultsHeader(
		"mx.example.net; spf=pass smtp.mailfrom=sender.example.com; dkim=pass header.d=sender.example.com header.i=@sender.example.com header.s=sel1; dkim2=fail (i=1 sender.example.com pass, i=2 fwd.example.org fail; FAIL: Message-Instance m=2 body hash sha256 mismatch) header.d=sender.example.com header.i=2",
		results,
	)

	if results.Dkim == nil || len(*results.Dkim) != 1 || (*results.Dkim)[0].Result != model.AuthResultResultPass {
		t.Fatalf("dkim = %+v, want one passing signature", results.Dkim)
	}
	if results.Dkim2 == nil || results.Dkim2.Result != model.DKIM2ResultResultFail || utils.Deref(results.Dkim2.Instance) != 2 {
		t.Fatalf("dkim2 = %+v, want fail at i=2", results.Dkim2)
	}
}

// The i=1 signature of the message is the originator, whatever the receiver
// wrote, and a header.d naming another domain discredits its header.i: the
// comment has no part in this, consumers must not depend on it.
func TestDKIM2OriginatorComesFromTheMessage(t *testing.T) {
	tests := []struct {
		name         string
		verdict      string
		wantInstance int
	}{
		{
			name:    "Authentication-Milter: the last signature in both properties",
			verdict: "dkim2=fail (FAIL: DKIM2-Signature i=1 selector sel incorrect signature) header.d=fwd.example.org header.i=2",
		},
		{
			name:         "Draft, the domains and outcomes of the hop list left out",
			verdict:      "dkim2=fail (i=1, i=2; FAIL: Message-Instance m=2 body hash sha256 mismatch) header.d=sender.example.com header.i=2",
			wantInstance: 2,
		},
		{
			name:         "Draft, no comment",
			verdict:      "dkim2=fail header.d=sender.example.com header.i=2",
			wantInstance: 2,
		},
		{
			name:         "Draft, domain in another case",
			verdict:      "dkim2=fail header.d=Sender.Example.COM header.i=2",
			wantInstance: 2,
		},
		{
			name:         "No header.d to contradict header.i",
			verdict:      "dkim2=fail header.i=2",
			wantInstance: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "Authentication-Results: mx.example.net; " + tt.verdict + "\r\n" +
				"DKIM2-Signature: i=2; m=1; t=1793841250; d=fwd.example.org; s=sel:ed25519-sha256:AAAA\r\n" +
				"DKIM2-Signature: i=1; m=1; t=1793841250; d=sender.example.com; s=sel:ed25519-sha256:AAAA\r\n" +
				"From: a@sender.example.com\r\n\r\nhello\r\n"
			email, err := mailmsg.Parse([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}

			results := NewAuthenticationAnalyzer("").AnalyzeAuthentication(email, "")
			if results.Dkim2 == nil {
				t.Fatalf("no dkim2 verdict read")
			}
			if got := utils.Deref(results.Dkim2.Domain); got != "sender.example.com" {
				t.Errorf("Domain = %q, want sender.example.com", got)
			}
			if got := utils.Deref(results.Dkim2.Instance); got != tt.wantInstance {
				t.Errorf("Instance = %d, want %d", got, tt.wantInstance)
			}
		})
	}
}

func TestDKIM2Scoring(t *testing.T) {
	pass := model.AuthResult{Result: model.AuthResultResultPass, Domain: utils.PtrTo("example.com")}
	dkim2 := func(r model.DKIM2ResultResult) *model.DKIM2Result {
		return &model.DKIM2Result{Result: r, Domain: utils.PtrTo("example.com")}
	}
	signed := &model.DNSResults{FromDomain: "example.com", Dkim2Records: &[]model.DKIM2Record{{Instance: 1, Selector: "s", Domain: "example.com", Valid: true}}}

	tests := []struct {
		name          string
		dkim          *[]model.AuthResult
		dkim2         *model.DKIM2Result
		dns           *model.DNSResults
		wantDKIM      int
		wantDKIM2     int
		wantDKIM2Type model.IssueType
		wantDKIMType  model.IssueType
	}{
		{
			name:     "DKIM only, unchanged",
			dkim:     &[]model.AuthResult{pass},
			wantDKIM: 100,
		},
		{
			name:      "Both pass",
			dkim:      &[]model.AuthResult{pass},
			dkim2:     dkim2(model.DKIM2ResultResultPass),
			dns:       signed,
			wantDKIM:  100,
			wantDKIM2: 0,
		},
		{
			name:         "DKIM2 only, passing: softened",
			dkim2:        dkim2(model.DKIM2ResultResultPass),
			dns:          signed,
			wantDKIM:     dkimScoreDKIM2Only,
			wantDKIMType: model.IssueTypeDkimMissing,
		},
		{
			name:          "DKIM2 fails: light penalty",
			dkim:          &[]model.AuthResult{pass},
			dkim2:         dkim2(model.DKIM2ResultResultFail),
			dns:           signed,
			wantDKIM:      100,
			wantDKIM2:     -100,
			wantDKIM2Type: model.IssueTypeDkim2Fail,
		},
		{
			name:          "DKIM2 temperror",
			dkim:          &[]model.AuthResult{pass},
			dkim2:         dkim2(model.DKIM2ResultResultTemperror),
			dns:           signed,
			wantDKIM:      100,
			wantDKIM2:     -40,
			wantDKIM2Type: model.IssueTypeDkim2Temperror,
		},
		{
			name:          "Signed, but the receiver does not verify DKIM2",
			dkim:          &[]model.AuthResult{pass},
			dns:           signed,
			wantDKIM:      100,
			wantDKIM2Type: model.IssueTypeDkim2Unevaluated,
		},
	}

	a := NewAuthenticationAnalyzer("")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{
				Spf:   &model.AuthResult{Result: model.AuthResultResultPass},
				Dkim:  tt.dkim,
				Dkim2: tt.dkim2,
			}
			if got := a.calculateDKIMScore(results); got != tt.wantDKIM {
				t.Errorf("calculateDKIMScore = %d, want %d", got, tt.wantDKIM)
			}
			if got := a.calculateDKIM2Score(results); got != tt.wantDKIM2 {
				t.Errorf("calculateDKIM2Score = %d, want %d", got, tt.wantDKIM2)
			}

			dns := tt.dns
			if dns == nil {
				dns = &model.DNSResults{FromDomain: "example.com"}
			}
			a.ReportIssues(results, dns, model.ReportSourceReceived)

			if tt.wantDKIM2Type != "" {
				issues := results.Issues.Dkim2
				if issues == nil || len(*issues) != 1 || (*issues)[0].Type != tt.wantDKIM2Type {
					t.Fatalf("dkim2 issues = %+v, want one %s", issues, tt.wantDKIM2Type)
				}
				wantPenalty := -tt.wantDKIM2 * authWeightDKIM2 / 100
				if got := utils.Deref((*issues)[0].Penalty); got != wantPenalty {
					t.Errorf("dkim2 penalty = %d, want %d", got, wantPenalty)
				}
			} else if results.Issues.Dkim2 != nil && len(*results.Issues.Dkim2) > 0 {
				t.Errorf("dkim2 issues = %+v, want none", *results.Issues.Dkim2)
			}

			if tt.wantDKIMType != "" {
				issues := results.Issues.Dkim
				if issues == nil || len(*issues) != 1 || (*issues)[0].Type != tt.wantDKIMType {
					t.Fatalf("dkim issues = %+v, want one %s", issues, tt.wantDKIMType)
				}
				if (*issues)[0].Severity != model.IssueSeverityMedium {
					t.Errorf("dkim issue severity = %s, want medium", (*issues)[0].Severity)
				}
			}
		})
	}
}
