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
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func newTestDMARCVerifier(txt map[string][]string, errs map[string]error) *DMARCVerifier {
	if errs == nil {
		errs = map[string]error{}
	}
	return NewDMARCVerifier(&mockDNSResolver{txt: txt, err: errs}, 5*time.Second)
}

func pass(domain string) *model.AuthResult {
	return &model.AuthResult{Result: model.AuthResultResultPass, Domain: utils.PtrTo(domain)}
}

func fail(domain string) *model.AuthResult {
	return &model.AuthResult{Result: model.AuthResultResultFail, Domain: utils.PtrTo(domain)}
}

// TestVerifyDMARC walks the alignment logic, one deviation at a time: a
// message must pass whenever either SPF or DKIM authenticates a domain aligned
// with the From domain, and fail only when neither does.
func TestVerifyDMARC(t *testing.T) {
	tests := []struct {
		name        string
		fromDomain  string
		txt         map[string][]string
		spf         *model.AuthResult
		dkim        []model.AuthResult
		wantNil     bool
		wantResult  model.AuthResultResult
		wantDetails string
	}{
		{
			name:       "SPF aligned and passing",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			spf:        pass("example.com"),
			wantResult: model.AuthResultResultPass,
		},
		{
			name:       "DKIM aligned and passing",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			dkim:       []model.AuthResult{*fail("example.com"), *pass("example.com")},
			wantResult: model.AuthResultResultPass,
		},
		{
			name:       "SPF passes but for an unrelated domain",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			spf:        pass("unrelated.net"),
			wantResult: model.AuthResultResultFail,
		},
		{
			name:       "SPF domain matches but did not pass",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			spf:        fail("example.com"),
			wantResult: model.AuthResultResultFail,
		},
		{
			name:       "relaxed alignment accepts a subdomain via the organizational domain",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}},
			spf:        pass("mail.example.com"),
			wantResult: model.AuthResultResultPass,
		},
		{
			name:       "strict alignment refuses a subdomain",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=s"}},
			spf:        pass("mail.example.com"),
			wantResult: model.AuthResultResultFail,
		},
		{
			name:       "strict alignment accepts an exact match",
			fromDomain: "example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject; adkim=s"}},
			dkim:       []model.AuthResult{*pass("example.com")},
			wantResult: model.AuthResultResultPass,
		},
		{
			name:       "no record at the exact domain falls back to the organizational domain",
			fromDomain: "mail.example.com",
			txt:        map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=quarantine"}},
			spf:        pass("mail.example.com"),
			wantResult: model.AuthResultResultPass,
		},
		{
			name:       "no policy published anywhere",
			fromDomain: "example.com",
			txt:        map[string][]string{},
			spf:        pass("example.com"),
			wantNil:    true,
		},
		{
			name:        "malformed record",
			fromDomain:  "example.com",
			txt:         map[string][]string{"_dmarc.example.com": {"v=DMARC1"}},
			wantResult:  model.AuthResultResultPermerror,
			wantDetails: "p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newTestDMARCVerifier(tt.txt, nil).VerifyDMARC(tt.fromDomain, tt.spf, tt.dkim)

			if tt.wantNil {
				if got != nil {
					t.Fatalf("VerifyDMARC() = %+v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("VerifyDMARC() = nil, want %q", tt.wantResult)
			}
			if got.Result != tt.wantResult {
				t.Errorf("VerifyDMARC().Result = %q, want %q (details: %v)", got.Result, tt.wantResult, got.Details)
			}
			if got.Domain == nil || *got.Domain != tt.fromDomain {
				t.Errorf("VerifyDMARC().Domain = %v, want %q", got.Domain, tt.fromDomain)
			}
			if tt.wantDetails != "" && (got.Details == nil || !strings.Contains(*got.Details, tt.wantDetails)) {
				t.Errorf("VerifyDMARC().Details = %v, want it to contain %q", got.Details, tt.wantDetails)
			}
		})
	}
}

// TestVerifyDMARCTemporaryFailure checks a transient DNS error is reported as
// temperror rather than silently dropped or treated as a hard fail.
func TestVerifyDMARCTemporaryFailure(t *testing.T) {
	got := newTestDMARCVerifier(nil, map[string]error{
		"_dmarc.example.com": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
	}).VerifyDMARC("example.com", pass("example.com"), nil)

	if got == nil || got.Result != model.AuthResultResultTemperror {
		t.Fatalf("VerifyDMARC() = %+v, want temperror", got)
	}
}

// TestVerifyDMARCNilVerifier makes the zero-dependency path safe: an analyzer
// built without a resolver must decline rather than panic.
func TestVerifyDMARCNilVerifier(t *testing.T) {
	var v *DMARCVerifier
	if got := v.VerifyDMARC("example.com", pass("example.com"), nil); got != nil {
		t.Errorf("VerifyDMARC() on nil verifier = %+v, want nil", got)
	}
}

// TestVerifyDMARCNoFromDomain guards the input that must yield no verdict at
// all: DMARC without a From domain to protect is not a claim we can make.
func TestVerifyDMARCNoFromDomain(t *testing.T) {
	got := newTestDMARCVerifier(map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}, nil).VerifyDMARC("", pass("example.com"), nil)

	if got != nil {
		t.Errorf("VerifyDMARC() = %+v, want nil", got)
	}
}

// --- Where the verdict lands in the analysis ---------------------------------

func newTestDMARCAuthAnalyzer(txt map[string][]string) *AuthenticationAnalyzer {
	a := NewAuthenticationAnalyzer("")
	a.dmarcVerifier = newTestDMARCVerifier(txt, nil)
	return a
}

// TestAnalyzeAuthenticationVerifiesDMARCWhenNoAuthResults covers the plain
// case: the message states no dmarc= we trust, so we compute one ourselves
// instead of leaving the message unjudged.
func TestAnalyzeAuthenticationVerifiesDMARCWhenNoAuthResults(t *testing.T) {
	email := parseTestEmail(t, "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=sender@example.com\r\n"+
		"From: Sender <sender@example.com>\r\n"+
		"To: Recipient <recipient@example.net>\r\n"+
		"Subject: Test message\r\n"+
		"\r\n"+
		"Hello.\r\n")

	analyzer := newTestDMARCAuthAnalyzer(map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	})

	results := analyzer.AnalyzeAuthentication(email, "")
	if results.Dmarc == nil {
		t.Fatal("AnalyzeAuthentication() left Dmarc nil, want the verified verdict")
	}
	if results.Dmarc.Result != model.AuthResultResultPass {
		t.Errorf("AnalyzeAuthentication().Dmarc.Result = %q, want pass (details: %v)", results.Dmarc.Result, results.Dmarc.Details)
	}
}

// TestAnalyzeAuthenticationKeepsTrustedDMARCAuthResults is the important one: a
// trusted Authentication-Results already carries a dmarc= verdict, so our own
// evaluation must not overwrite it — that verdict is the receiver's own
// measurement, taken on the message as it stood there.
func TestAnalyzeAuthenticationKeepsTrustedDMARCAuthResults(t *testing.T) {
	email := parseTestEmail(t, "Authentication-Results: mx.example.net; dmarc=fail header.from=example.com\r\n"+
		"From: Sender <sender@example.com>\r\n"+
		"To: Recipient <recipient@example.net>\r\n"+
		"Subject: Test message\r\n"+
		"\r\n"+
		"Hello.\r\n")

	analyzer := newTestDMARCAuthAnalyzer(map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none"},
	})

	results := analyzer.AnalyzeAuthentication(email, "mx.example.net")
	if results.Dmarc == nil || results.Dmarc.Result != model.AuthResultResultFail {
		t.Fatalf("AnalyzeAuthentication().Dmarc = %+v, want the trusted fail to stand", results.Dmarc)
	}
}

// TestAnalyzeAuthenticationWithoutDMARCVerifier checks the analyzer built
// without a resolver stays what it always was: a reader of other servers'
// verdicts, which reaches no network of its own.
func TestAnalyzeAuthenticationWithoutDMARCVerifier(t *testing.T) {
	email := parseTestEmail(t, "From: Sender <sender@example.com>\r\n"+
		"To: Recipient <recipient@example.net>\r\n"+
		"Subject: Test message\r\n"+
		"\r\n"+
		"Hello.\r\n")

	results := NewAuthenticationAnalyzer("").AnalyzeAuthentication(email, "")
	if results.Dmarc != nil {
		t.Errorf("AnalyzeAuthentication().Dmarc = %+v, want nil without a verifier", results.Dmarc)
	}
}
