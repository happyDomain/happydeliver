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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

func TestParseMTASTSRecord(t *testing.T) {
	for record, wantErr := range map[string]bool{
		"v=STSv1; id=20240101T000000": false,
		"v=STSv1;id=abc123;":          false,
		"v=STSv1":                     true,
		"v=STSv1; id=":                true,
		"v=STSv1; id=has-dash":        true,
		"id=abc; v=STSv1":             true,
	} {
		if _, err := parseMTASTSRecord(record); (err != nil) != wantErr {
			t.Errorf("%q: err = %v, want error: %v", record, err, wantErr)
		}
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	tests := []struct {
		name, body string
		wantErr    bool
	}{
		{"valid", "version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n", false},
		{"LF only", "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n", false},
		{"none without mx", "version: STSv1\nmode: none\nmax_age: 86400\n", false},
		{"no version", "mode: enforce\nmx: mx.example.com\nmax_age: 86400\n", true},
		{"bad mode", "version: STSv1\nmode: strict\nmx: mx.example.com\nmax_age: 86400\n", true},
		{"max_age too large", "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 99999999\n", true},
		{"no mx", "version: STSv1\nmode: enforce\nmax_age: 86400\n", true},
		{"bad mx", "version: STSv1\nmode: enforce\nmx: *.*.example.com\nmax_age: 86400\n", true},
		{"garbage", "<html>not a policy</html>", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseMTASTSPolicy(tt.body, &model.MTASTSResult{}); (err != nil) != tt.wantErr {
				t.Errorf("err = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestMXPatternMatches(t *testing.T) {
	for _, tt := range []struct {
		pattern, host string
		want          bool
	}{
		{"mx.example.com", "mx.example.com", true},
		{"mx.example.com", "MX.Example.com.", true},
		{"*.example.net", "mx1.example.net", true},
		{"*.example.net", "a.b.example.net", false},
		{"*.example.net", "example.net", false},
		{"mx.example.com", "mx2.example.com", false},
	} {
		if got := mxPatternMatches(tt.pattern, tt.host); got != tt.want {
			t.Errorf("mxPatternMatches(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

// policyServer serves an MTA-STS policy over TLS, and returns a checker whose
// HTTP client reaches it for mta-sts.example.com.
func policyServer(t *testing.T, txt map[string][]string, handler http.HandlerFunc) *MailPolicyChecker {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	m := NewMailPolicyChecker(2*time.Second, 2*time.Second, &fakeResolver{txt: txt})
	client := srv.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client.Transport = transport
	client.CheckRedirect = m.httpClient.CheckRedirect
	m.httpClient = client
	return m
}

func servePolicy(body, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" || r.Host != "mta-sts.example.com" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write([]byte(body))
	}
}

func evaluate(policies *model.MailPolicies, hosts ...string) {
	var records []model.MXRecord
	for _, h := range hosts {
		records = append(records, model.MXRecord{Host: h + ".", Valid: true})
	}
	EvaluateMailPolicies(policies, "example.com", &records)
}

func TestCheckMTASTS(t *testing.T) {
	txt := map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=1"}}
	const policy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n"

	t.Run("valid and covering", func(t *testing.T) {
		m := policyServer(t, txt, servePolicy(policy, "text/plain; charset=utf-8"))
		policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
		evaluate(policies, "mx1.example.com")
		if policies.MtaSts.Status != model.MTASTSResultStatusValid || *policies.Penalty != 0 {
			t.Errorf("result = %+v, penalty %d, issues %v", policies.MtaSts, *policies.Penalty, issueTypes(deref(policies.Issues.MtaSts)))
		}
		if cov := deref(policies.MtaSts.MxCoverage); len(cov) != 1 || !cov[0].Covered {
			t.Errorf("coverage = %+v", cov)
		}
	})

	t.Run("enforce leaving an MX out", func(t *testing.T) {
		m := policyServer(t, txt, servePolicy(policy, "text/plain"))
		policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
		evaluate(policies, "mx1.example.com", "mx2.example.com")
		issue := hasIssue(deref(policies.Issues.MtaSts), model.IssueTypeMtaStsMxMismatch)
		if issue == nil || issue.Severity != model.IssueSeverityHigh || *policies.Penalty != mtaSTSPenaltyMismatch || policies.MtaSts.Status != model.MTASTSResultStatusInvalid {
			t.Errorf("issues = %+v, penalty = %d", deref(policies.Issues.MtaSts), *policies.Penalty)
		}
	})

	t.Run("testing leaving an MX out", func(t *testing.T) {
		m := policyServer(t, txt, servePolicy("version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 604800\n", "text/plain"))
		policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
		evaluate(policies, "mx2.example.com")
		issue := hasIssue(deref(policies.Issues.MtaSts), model.IssueTypeMtaStsMxMismatch)
		if issue == nil || issue.Severity != model.IssueSeverityMedium || *policies.Penalty != 0 {
			t.Errorf("issues = %+v, penalty = %d", deref(policies.Issues.MtaSts), *policies.Penalty)
		}
	})

	t.Run("wrong content type", func(t *testing.T) {
		m := policyServer(t, txt, servePolicy(policy, "text/html"))
		policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
		evaluate(policies, "mx1.example.com")
		if hasIssue(deref(policies.Issues.MtaSts), model.IssueTypeMtaStsPolicyUnreachable) == nil || *policies.Penalty != mtaSTSPenaltyUnreachable {
			t.Errorf("issues = %v, penalty = %d", issueTypes(deref(policies.Issues.MtaSts)), *policies.Penalty)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		m := policyServer(t, txt, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example.com/policy", http.StatusFound)
		})
		result := m.checkMTASTS(context.Background(), "example.com")
		if result.PolicyError == nil || result.Policy != nil {
			t.Errorf("result = %+v, want the redirect refused", result)
		}
	})

	t.Run("absent", func(t *testing.T) {
		m := policyServer(t, nil, servePolicy(policy, "text/plain"))
		policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
		evaluate(policies, "mx1.example.com")
		issue := hasIssue(deref(policies.Issues.MtaSts), model.IssueTypeMtaStsMissing)
		if policies.MtaSts.Status != model.MTASTSResultStatusAbsent || issue == nil || issue.Severity != model.IssueSeverityLow || *policies.Penalty != 0 {
			t.Errorf("result = %+v, issues = %+v", policies.MtaSts, deref(policies.Issues.MtaSts))
		}
	})
}

func TestCheckTLSRPT(t *testing.T) {
	tests := []struct {
		name    string
		txt     []string
		status  model.TLSRPTResultStatus
		penalty int
	}{
		{"valid", []string{"v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.net/tls"}, model.TLSRPTResultStatusValid, 0},
		{"absent", nil, model.TLSRPTResultStatusAbsent, 0},
		{"no rua", []string{"v=TLSRPTv1;"}, model.TLSRPTResultStatusInvalid, tlsRPTPenaltyInvalid},
		{"bad scheme", []string{"v=TLSRPTv1; rua=http://example.com/"}, model.TLSRPTResultStatusInvalid, tlsRPTPenaltyInvalid},
		{"two records", []string{"v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"}, model.TLSRPTResultStatusInvalid, tlsRPTPenaltyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt := map[string][]string{}
			if tt.txt != nil {
				txt["_smtp._tls.example.com"] = tt.txt
			}
			m := NewMailPolicyChecker(time.Second, time.Second, &fakeResolver{txt: txt})
			policies := &model.MailPolicies{TlsRpt: m.checkTLSRPT(context.Background(), "example.com")}
			evaluate(policies)
			if policies.TlsRpt.Status != tt.status || *policies.Penalty != tt.penalty {
				t.Errorf("result = %+v, penalty = %d", policies.TlsRpt, *policies.Penalty)
			}
		})
	}
}

func TestTLSRPTMissingWithMTASTS(t *testing.T) {
	policies := &model.MailPolicies{
		MtaSts: &model.MTASTSResult{Status: model.MTASTSResultStatusValid, Mode: utils.PtrTo(model.MTASTSResultModeEnforce), Mx: &[]string{"mx.example.com"}},
		TlsRpt: &model.TLSRPTResult{Status: model.TLSRPTResultStatusAbsent},
	}
	evaluate(policies, "mx.example.com")
	issue := hasIssue(deref(policies.Issues.TlsRpt), model.IssueTypeTlsRptMissing)
	if issue == nil || issue.Severity != model.IssueSeverityMedium {
		t.Errorf("issues = %+v, want a medium tls_rpt_missing", deref(policies.Issues.TlsRpt))
	}
}

func TestDomainOnlyScoreWithPolicies(t *testing.T) {
	f := &fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.1", "2001:db8::1"}},
		txt: map[string][]string{
			"example.com":        {"v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
		},
	}
	d := newFakeAnalyzer(f)
	results := d.AnalyzeDomainOnly("example.com")
	base, _ := d.CalculateDomainOnlyScore(results)
	got, _ := d.CalculateDomainOnlyScoreWithPolicies(results, &model.MailPolicies{Penalty: utils.PtrTo(20)})
	if got != base-20 {
		t.Errorf("score with a 20-point penalty = %d, want %d", got, base-20)
	}
}

func TestCheckMTASTSEdgeCases(t *testing.T) {
	const policy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n"
	tests := []struct {
		name    string
		txt     map[string][]string
		err     map[string]error
		body    string
		issue   model.IssueType
		penalty int
	}{
		{"two records", map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=1", "v=STSv1; id=2"}}, nil, policy, model.IssueTypeMtaStsInvalid, mtaSTSPenaltyInvalid},
		{"bad id", map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=not-valid!"}}, nil, policy, model.IssueTypeMtaStsInvalid, mtaSTSPenaltyInvalid},
		{"lookup failure", nil, map[string]error{"_mta-sts.example.com": &net.DNSError{Err: "server misbehaving", IsTemporary: true}}, policy, model.IssueTypeMtaStsInvalid, mtaSTSPenaltyInvalid},
		{"short max_age", map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=1"}}, nil, "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 3600\n", model.IssueTypeMtaStsMaxAgeShort, 0},
		{"mode none", map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=1"}}, nil, "version: STSv1\nmode: none\nmax_age: 86400\n", model.IssueTypeMtaStsModeTesting, 0},
		{"oversized policy", map[string][]string{"_mta-sts.example.com": {"v=STSv1; id=1"}}, nil, policy + strings.Repeat("#", mtaSTSMaxPolicySize), model.IssueTypeMtaStsPolicyUnreachable, mtaSTSPenaltyUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := policyServer(t, tt.txt, servePolicy(tt.body, "text/plain"))
			m.resolver = &fakeResolver{txt: tt.txt, err: tt.err}
			policies := &model.MailPolicies{MtaSts: m.checkMTASTS(context.Background(), "example.com")}
			evaluate(policies, "mx1.example.com")
			issue := hasIssue(deref(policies.Issues.MtaSts), tt.issue)
			if issue == nil || *policies.Penalty != tt.penalty {
				t.Errorf("issues = %v, penalty = %d; want %s costing %d", issueTypes(deref(policies.Issues.MtaSts)), *policies.Penalty, tt.issue, tt.penalty)
			}
		})
	}
}

// The policy is fetched through the guarded client of the BIMI assets: a
// domain pointing mta-sts.<domain> to an internal address gets nothing out
// of this instance.
func TestFetchMTASTSPolicyRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(servePolicy("version: STSv1\n", "text/plain"))
	defer srv.Close()

	m := NewMailPolicyChecker(time.Second, time.Second, &fakeResolver{})
	_, err := m.fetchMTASTSPolicy(context.Background(), srv.URL+"/.well-known/mta-sts.txt")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("err = %v, want the loopback address refused", err)
	}
}

// A policy published but broken takes away the A+ a valid BIMI record
// otherwise earns.
func TestDomainOnlyPoliciesPenaltyBlocksAPlus(t *testing.T) {
	d := newFakeAnalyzer(&fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.1", "2001:db8::1"}},
		txt: map[string][]string{
			"example.com":        {"v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
		},
	})
	results := d.AnalyzeDomainOnly("example.com")
	results.BimiRecord = &model.BIMIRecord{Valid: true}

	if _, grade := d.CalculateDomainOnlyScoreWithPolicies(results, &model.MailPolicies{Penalty: utils.PtrTo(0)}); grade != "A+" {
		t.Fatalf("grade without penalty = %s, want A+", grade)
	}
	if score, grade := d.CalculateDomainOnlyScoreWithPolicies(results, &model.MailPolicies{Penalty: utils.PtrTo(5)}); grade == "A+" || score != 95 {
		t.Errorf("score = %d, grade = %s; want 95 without A+", score, grade)
	}
}

// TestReceivedMailSkipsMailPolicies makes sure the analysis of a received
// message, and the DNS part of the domain test, never look up what belongs to
// the mail policies: those lookups are the MailPolicyChecker's only.
func TestReceivedMailSkipsMailPolicies(t *testing.T) {
	f := &fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.1"}},
		txt: map[string][]string{
			"example.com":        {"v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
		},
	}
	d := newFakeAnalyzer(f)

	email, err := mailmsg.Parse([]byte("From: Alice <alice@example.com>\r\nTo: test@example.org\r\nSubject: hi\r\nMessage-ID: <1@example.com>\r\nDate: Mon, 02 Jan 2026 15:04:05 +0000\r\n\r\nHello\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	headers := &model.HeaderAnalysis{DomainAlignment: &model.DomainAlignment{
		FromDomain:       utils.PtrTo("example.com"),
		ReturnPathDomain: utils.PtrTo("example.com"),
	}}
	d.AnalyzeDNS(email, headers, &model.ReceivedHop{Ip: utils.PtrTo("192.0.2.10"), From: utils.PtrTo("mx.example.com")})
	d.AnalyzeDomainOnly("example.com")

	for _, q := range f.queries {
		for _, forbidden := range []string{"_mta-sts.", "mta-sts.", "_smtp._tls.", "_25._tcp."} {
			if strings.Contains(q, forbidden) {
				t.Errorf("the shared DNS analysis queried %q", q)
			}
		}
	}
}
