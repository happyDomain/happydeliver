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

package mailservers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
	smtpchecker "git.happydns.org/checker-smtp/checker"
	tlschecker "git.happydns.org/checker-tls/checker"
	tlscontract "git.happydns.org/checker-tls/contract"
	"github.com/miekg/dns"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

type fakeResolver struct {
	mx    map[string][]*net.MX
	hosts map[string][]string
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if r, ok := f.mx[strings.TrimSuffix(name, ".")]; ok {
		return r, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	if r, ok := f.hosts[strings.TrimSuffix(name, ".")]; ok {
		return r, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, notFound(name)
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, notFound(addr)
}

// fakeSMTP stands for checker-smtp: it answers each target with the probes
// given for its addresses, and records what it was asked.
type fakeSMTP struct {
	mu      sync.Mutex
	asked   []sdk.CheckerOptions
	targets map[string][]smtpchecker.EndpointProbe
}

func (f *fakeSMTP) Key() sdk.ObservationKey { return smtpchecker.ObservationKeySMTP }

func (f *fakeSMTP) Collect(_ context.Context, opts sdk.CheckerOptions) (any, error) {
	f.mu.Lock()
	f.asked = append(f.asked, opts)
	f.mu.Unlock()
	var body struct {
		MX []struct{ Mx string } `json:"mx"`
	}
	if err := json.Unmarshal(opts["service"].(json.RawMessage), &body); err != nil || len(body.MX) != 1 {
		return nil, errors.New("unexpected service")
	}
	host := strings.TrimSuffix(body.MX[0].Mx, ".")
	return &smtpchecker.SMTPData{Domain: opts["domain"].(string), Endpoints: f.targets[host]}, nil
}

// fakeTLS stands for checker-tls, answering every endpoint with a valid
// certificate unless told otherwise.
type fakeTLS struct {
	probe func(ep tlscontract.TLSEndpoint) tlschecker.TLSProbe
}

func (f *fakeTLS) Key() sdk.ObservationKey { return tlschecker.ObservationKeyTLSProbes }

func (f *fakeTLS) Collect(_ context.Context, opts sdk.CheckerOptions) (any, error) {
	entries, _ := tlscontract.ParseEntries(opts[tlschecker.OptionEndpoints].([]sdk.DiscoveryEntry))
	data := &tlschecker.TLSData{Probes: map[string]tlschecker.TLSProbe{}}
	for _, e := range entries {
		data.Probes[e.Ref] = f.probe(e.Endpoint)
	}
	return data, nil
}

func goodCert(tlscontract.TLSEndpoint) tlschecker.TLSProbe {
	return tlschecker.TLSProbe{
		TLSHandshakeOK: true,
		ChainValid:     utils.PtrTo(true),
		HostnameMatch:  utils.PtrTo(true),
		NotAfter:       time.Now().Add(90 * 24 * time.Hour),
		Subject:        "mx.example.com",
	}
}

// healthy is what checker-smtp reports of a server doing everything right.
func healthy(target, ip string) smtpchecker.EndpointProbe {
	yes := true
	no := false
	return smtpchecker.EndpointProbe{
		Target: target, IP: ip, IsIPv6: strings.Contains(ip, ":"),
		TCPConnected: true, BannerReceived: true, BannerCode: 220, BannerLine: "220 " + target + " ESMTP",
		EHLOReceived: true, STARTTLSOffered: true, STARTTLSUpgraded: true, TLSVersion: "TLS 1.3",
		PTR: target, FCrDNSPass: true,
		NullSenderAccepted: &yes, PostmasterAccepted: &yes, OpenRelay: &no,
	}
}

func testProber(r *fakeResolver, smtp *fakeSMTP) *Prober {
	p := NewProber(Options{Timeout: time.Second, RelayRecipient: "relay-test@deliver.example.org", Witness: "witness.example.net"}, r, nil, nil)
	p.smtp = smtp
	p.tls = &fakeTLS{probe: goodCert}
	p.publicAddr = func(ip net.IP) bool { return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() }
	p.reachable = func(context.Context, string) bool { return true }
	return p
}

func TestProbeHealthyServers(t *testing.T) {
	r := &fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.25", "2001:db8::25"}},
	}
	smtp := &fakeSMTP{targets: map[string][]smtpchecker.EndpointProbe{
		"mx.example.com": {healthy("mx.example.com", "192.0.2.25"), healthy("mx.example.com", "2001:db8::25")},
	}}
	result := testProber(r, smtp).Probe(context.Background(), "example.com")

	if result.Status != model.MailServersResultStatusComplete || utils.Deref(result.Score) != 100 {
		t.Fatalf("status = %s, score = %v, issues = %+v", result.Status, utils.Deref(result.Score), deref(result.Issues))
	}
	// Without MTA-STS nor DANE, a perfect score is an A, not an A+
	if utils.Deref(result.Grade) != "A" {
		t.Errorf("grade = %s, want A", utils.Deref(result.Grade))
	}
	eps := (*result.Servers)[0].Endpoints
	if len(eps) != 2 || !eps[0].Probed || eps[0].Certificate == nil || !utils.Deref(eps[0].Certificate.ChainValid) {
		t.Errorf("endpoints = %+v", eps)
	}
	if got := smtp.asked[0]["test_probe_address"]; got != "relay-test@deliver.example.org" {
		t.Errorf("open relay recipient = %v", got)
	}
}

func TestProbeRefusesPrivateAddresses(t *testing.T) {
	r := &fakeResolver{
		mx: map[string][]*net.MX{"example.com": {
			{Host: "mx1.example.com.", Pref: 10},
			{Host: "mx2.example.com.", Pref: 20},
		}},
		hosts: map[string][]string{
			"mx1.example.com": {"192.0.2.25"},
			"mx2.example.com": {"192.0.2.26", "10.0.0.26"},
		},
	}
	smtp := &fakeSMTP{targets: map[string][]smtpchecker.EndpointProbe{
		// checker-smtp finding an address discover did not vet is ignored
		"mx1.example.com": {healthy("mx1.example.com", "192.0.2.25"), healthy("mx1.example.com", "127.0.0.1")},
	}}
	result := testProber(r, smtp).Probe(context.Background(), "example.com")

	for _, opts := range smtp.asked {
		if strings.Contains(string(opts["service"].(json.RawMessage)), "mx2") {
			t.Error("a host resolving to a private address was handed to checker-smtp")
		}
	}
	servers := *result.Servers
	if len(servers[0].Endpoints) != 1 {
		t.Errorf("mx1 endpoints = %+v, want the vetted address only", servers[0].Endpoints)
	}
	for _, ep := range servers[1].Endpoints {
		if ep.Probed || ep.SkipReason == nil {
			t.Errorf("mx2 endpoint %+v, want skipped", ep)
		}
	}
	if issue := findIssue(deref(result.Issues), model.IssueTypeSmtpProbeSkipped); issue == nil {
		t.Errorf("issues = %v, want smtp_probe_skipped", issueTypes(deref(result.Issues)))
	}
}

func TestProbeNullMX(t *testing.T) {
	r := &fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: ".", Pref: 0}}}}
	smtp := &fakeSMTP{}
	result := testProber(r, smtp).Probe(context.Background(), "example.com")
	if result.Status != model.MailServersResultStatusNullMx || result.Score != nil || len(smtp.asked) > 0 {
		t.Errorf("result = %+v, asked %d", result, len(smtp.asked))
	}
}

func TestProbeInconclusiveWhenPort25Blocked(t *testing.T) {
	r := &fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.25"}},
	}
	down := smtpchecker.EndpointProbe{Target: "mx.example.com", IP: "192.0.2.25", Error: "tcp: i/o timeout"}
	smtp := &fakeSMTP{targets: map[string][]smtpchecker.EndpointProbe{"mx.example.com": {down}}}

	p := testProber(r, smtp)
	p.reachable = func(context.Context, string) bool { return false }
	result := p.Probe(context.Background(), "example.com")
	if result.Status != model.MailServersResultStatusInconclusive || result.Score != nil {
		t.Errorf("status = %s, score = %v, want inconclusive and unscored", result.Status, result.Score)
	}

	// With the witness answering, the domain is to blame
	p.reachable = func(context.Context, string) bool { return true }
	result = p.Probe(context.Background(), "example.com")
	if result.Status != model.MailServersResultStatusComplete || utils.Deref(result.Score) > 30 {
		t.Errorf("status = %s, score = %v", result.Status, utils.Deref(result.Score))
	}
}

func TestProbeSkipsRelayTestOfOwnDomain(t *testing.T) {
	r := &fakeResolver{
		mx:    map[string][]*net.MX{"deliver.example.org": {{Host: "mx.deliver.example.org.", Pref: 10}}},
		hosts: map[string][]string{"mx.deliver.example.org": {"192.0.2.25"}},
	}
	smtp := &fakeSMTP{targets: map[string][]smtpchecker.EndpointProbe{"mx.deliver.example.org": {healthy("mx.deliver.example.org", "192.0.2.25")}}}
	result := testProber(r, smtp).Probe(context.Background(), "deliver.example.org")
	if smtp.asked[0]["test_open_relay"] != false || utils.Deref(result.OpenRelayTested) {
		t.Errorf("open relay test ran against the instance's own domain: %v", smtp.asked[0])
	}
}

func findIssue(issues []model.Issue, t model.IssueType) *model.Issue {
	for i := range issues {
		if issues[i].Type == t {
			return &issues[i]
		}
	}
	return nil
}

func issueTypes(issues []model.Issue) []model.IssueType {
	var out []model.IssueType
	for _, i := range issues {
		out = append(out, i.Type)
	}
	return out
}

// result builds a probed result of one MX with the given endpoints.
func resultOf(eps ...model.MailServerEndpoint) *model.MailServersResult {
	return &model.MailServersResult{
		Domain:  "example.com",
		Status:  model.MailServersResultStatusComplete,
		Servers: &[]model.MailServer{{Host: "mx.example.com", Priority: 10, Endpoints: eps}},
	}
}

func goodEndpoint(ip string) model.MailServerEndpoint {
	yes := true
	return model.MailServerEndpoint{
		Ip: ip, Ipv6: utils.PtrTo(strings.Contains(ip, ":")), Probed: true,
		TcpConnected: &yes, Banner: utils.PtrTo("220 mx.example.com"), Ehlo: &yes,
		StarttlsOffered: &yes, Starttls: &yes,
		Certificate: &model.MailServerCertificate{ChainValid: &yes, HostnameMatch: &yes, DaysLeft: utils.PtrTo(60)},
		Ptr:         utils.PtrTo("mx.example.com"), Fcrdns: &yes,
		NullSenderAccepted: &yes, PostmasterAccepted: &yes, OpenRelay: utils.PtrTo(false),
	}
}

func TestJudge(t *testing.T) {
	enforce := &model.MTASTSResult{Status: model.MTASTSResultStatusValid, Mode: utils.PtrTo(model.MTASTSResultModeEnforce), Mx: &[]string{"mx.example.com"}}
	testing_ := &model.MTASTSResult{Status: model.MTASTSResultStatusValid, Mode: utils.PtrTo(model.MTASTSResultModeTesting), Mx: &[]string{"mx.example.com"}}
	elsewhere := &model.MTASTSResult{Status: model.MTASTSResultStatusValid, Mode: utils.PtrTo(model.MTASTSResultModeEnforce), Mx: &[]string{"other.example.com"}}

	tests := []struct {
		name   string
		result func() *model.MailServersResult
		mtaSTS *model.MTASTSResult
		score  int
		grade  string
		want   model.IssueType
	}{
		{"perfect without policy", func() *model.MailServersResult {
			return resultOf(goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1"))
		}, nil, 100, "A", ""},
		{"perfect with MTA-STS enforce", func() *model.MailServersResult {
			return resultOf(goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1"))
		}, enforce, 100, "A+", ""},
		{"MTA-STS testing is not enough", func() *model.MailServersResult {
			return resultOf(goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1"))
		}, testing_, 100, "A", ""},
		{"MTA-STS enforce leaving the MX out", func() *model.MailServersResult {
			return resultOf(goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1"))
		}, elsewhere, 90, "A", model.IssueTypeMtaStsMxMismatch},
		{"IPv4 only", func() *model.MailServersResult { return resultOf(goodEndpoint("192.0.2.1")) }, nil, 95, "A", model.IssueTypeSmtpNoIpv6},
		{"no STARTTLS", func() *model.MailServersResult {
			ep := goodEndpoint("2001:db8::1")
			ep.StarttlsOffered, ep.Starttls, ep.Certificate = utils.PtrTo(false), utils.PtrTo(false), nil
			return resultOf(ep)
		}, nil, 70, "C", model.IssueTypeSmtpStarttlsMissing},
		{"bounces refused", func() *model.MailServersResult {
			ep := goodEndpoint("2001:db8::1")
			ep.NullSenderAccepted = utils.PtrTo(false)
			return resultOf(ep)
		}, nil, 90, "A", model.IssueTypeSmtpNullSenderRejected},
		{"open relay", func() *model.MailServersResult {
			ep := goodEndpoint("2001:db8::1")
			ep.OpenRelay = utils.PtrTo(true)
			return resultOf(ep)
		}, enforce, capCritical, "F", model.IssueTypeSmtpOpenRelay},
		{"AUTH before STARTTLS", func() *model.MailServersResult {
			ep := goodEndpoint("2001:db8::1")
			ep.AuthBeforeTls = &[]string{"PLAIN", "LOGIN"}
			return resultOf(ep)
		}, nil, capCritical, "F", model.IssueTypeSmtpAuthPlaintext},
		{"expired certificate", func() *model.MailServersResult {
			ep := goodEndpoint("2001:db8::1")
			ep.Certificate.DaysLeft = utils.PtrTo(-3)
			return resultOf(ep)
		}, nil, 85, "B", model.IssueTypeSmtpCertInvalid},
		{"DANE matching", func() *model.MailServersResult {
			a, b := goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1")
			a.Dane = utils.PtrTo(model.MailServerEndpointDaneMatch)
			b.Dane = utils.PtrTo(model.MailServerEndpointDaneMatch)
			r := resultOf(a, b)
			(*r.Servers)[0].TlsaRecords, (*r.Servers)[0].TlsaDnssec = utils.PtrTo(1), utils.PtrTo(true)
			return r
		}, nil, 100, "A+", ""},
		{"DANE mismatching", func() *model.MailServersResult {
			a, b := goodEndpoint("192.0.2.1"), goodEndpoint("2001:db8::1")
			a.Dane = utils.PtrTo(model.MailServerEndpointDaneMatch)
			b.Dane = utils.PtrTo(model.MailServerEndpointDaneMismatch)
			r := resultOf(a, b)
			(*r.Servers)[0].TlsaRecords, (*r.Servers)[0].TlsaDnssec = utils.PtrTo(1), utils.PtrTo(true)
			return r
		}, nil, 90, "A", model.IssueTypeSmtpDaneMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.result()
			judge(r, tt.mtaSTS, true)
			if utils.Deref(r.Score) != tt.score || string(utils.Deref(r.Grade)) != tt.grade {
				t.Errorf("score = %d, grade = %s; want %d, %s (issues %v)", utils.Deref(r.Score), utils.Deref(r.Grade), tt.score, tt.grade, issueTypes(deref(r.Issues)))
			}
			if tt.want != "" && findIssue(deref(r.Issues), tt.want) == nil {
				t.Errorf("issues = %v, want %s", issueTypes(deref(r.Issues)), tt.want)
			}
		})
	}
}

func TestEvaluateDANE(t *testing.T) {
	spki := sha256.Sum256([]byte("public key"))
	hash := hex.EncodeToString(spki[:])
	probe := tlschecker.TLSProbe{
		TLSHandshakeOK: true,
		ChainValid:     utils.PtrTo(false),
		HostnameMatch:  utils.PtrTo(true),
		Chain:          []tlschecker.CertInfo{{SPKISHA256: hash}},
	}
	tlsa := func(cert string) []*dns.TLSA {
		return []*dns.TLSA{{Usage: 3, Selector: 1, MatchingType: 1, Certificate: cert}}
	}

	data, err := collectDANE(context.Background(), "mx.example.com", tlsa(hash), true)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, msg := evaluateDANE(context.Background(), data, probe); verdict != model.MailServerEndpointDaneMatch {
		t.Errorf("matching record: verdict = %s (%s)", verdict, msg)
	}

	data, err = collectDANE(context.Background(), "mx.example.com", tlsa(strings.Repeat("ab", 32)), true)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, _ := evaluateDANE(context.Background(), data, probe); verdict != model.MailServerEndpointDaneMismatch {
		t.Errorf("other record: verdict = %s, want mismatch", verdict)
	}
}

// countingProber counts the probes it runs.
type countingProber struct {
	n     atomic.Int32
	delay time.Duration
}

func (c *countingProber) Probe(_ context.Context, domain string) *model.MailServersResult {
	c.n.Add(1)
	time.Sleep(c.delay)
	return &model.MailServersResult{Domain: domain, Status: model.MailServersResultStatusComplete}
}

func TestServiceCachesAndLimits(t *testing.T) {
	prober := &countingProber{delay: 20 * time.Millisecond}
	s := NewService(nil, time.Minute)
	s.prober = prober

	// Concurrent requests for one domain share a single probe
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if _, err := s.Check(context.Background(), "198.51.100.1", "Example.COM."); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := prober.n.Load(); n != 1 {
		t.Errorf("%d probes for concurrent requests, want 1", n)
	}

	// A cached result is served again without probing
	if _, err := s.Check(context.Background(), "198.51.100.2", "example.com"); err != nil || prober.n.Load() != 1 {
		t.Errorf("cached request probed again (err %v)", err)
	}

	// One client cannot probe more than its share
	prober.delay = 0
	var limited bool
	for i := range limitPerClient + 1 {
		_, err := s.Check(context.Background(), "198.51.100.3", "d"+string(rune('a'+i%26))+strings.Repeat("x", i/26)+".example.net")
		if errors.Is(err, ErrRateLimited) {
			limited = true
		}
	}
	if !limited {
		t.Error("a client was never rate limited")
	}

	// Nor can a domain be probed over and over once its cache expires
	now := time.Now()
	s.now = func() time.Time { return now }
	limited = false
	for i := range limitPerDomain + 1 {
		now = now.Add(2 * time.Minute)
		_, err := s.Check(context.Background(), "198.51.100."+string(rune('4'+i%5)), "busy.example.org")
		if errors.Is(err, ErrRateLimited) {
			limited = true
		}
	}
	if !limited {
		t.Error("a domain was never rate limited")
	}
}

func TestRelayRecipient(t *testing.T) {
	for domain, want := range map[string]string{
		"happydeliver.local":   "",
		"":                     "",
		"localhost":            "",
		"deliver.example.org":  "relay-test@deliver.example.org",
		"Deliver.Example.Org.": "relay-test@deliver.example.org",
		"box.home.arpa":        "",
		"bad domain.com":       "",
	} {
		if got := RelayRecipient(domain); got != want {
			t.Errorf("RelayRecipient(%q) = %q, want %q", domain, got, want)
		}
	}
}

// failingResolver fails every lookup for want of an answer.
type failingResolver struct{ *fakeResolver }

func (failingResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func TestProbeMXLookupFailure(t *testing.T) {
	smtp := &fakeSMTP{}
	p := testProber(&fakeResolver{}, smtp)
	p.resolver = failingResolver{&fakeResolver{}}
	result := p.Probe(context.Background(), "example.com")
	if result.Status != model.MailServersResultStatusInconclusive || result.Error == nil || len(smtp.asked) > 0 {
		t.Errorf("result = %+v", result)
	}
}

// fakeSecure answers TLSA queries from a map, with the AD flag given.
type fakeSecure struct {
	tlsa map[string][]*dns.TLSA
	ad   bool
}

func (f *fakeSecure) Query(_ context.Context, name string, _ uint16, _ bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.AuthenticatedData = f.ad
	for _, r := range f.tlsa[strings.TrimSuffix(name, ".")] {
		m.Answer = append(m.Answer, r)
	}
	return m, nil
}

func (f *fakeSecure) Address() string { return "192.0.2.53:53" }

func TestProbeDANEAndCertificates(t *testing.T) {
	spki := sha256.Sum256([]byte("public key"))
	hash := hex.EncodeToString(spki[:])
	r := &fakeResolver{
		mx:    map[string][]*net.MX{"example.com": {{Host: "mx.example.com.", Pref: 10}}},
		hosts: map[string][]string{"mx.example.com": {"192.0.2.25", "2001:db8::25"}},
	}
	smtp := &fakeSMTP{targets: map[string][]smtpchecker.EndpointProbe{
		"mx.example.com": {healthy("mx.example.com", "192.0.2.25"), healthy("mx.example.com", "2001:db8::25")},
	}}

	var mu sync.Mutex
	var dialed []tlscontract.TLSEndpoint
	tls := &fakeTLS{probe: func(ep tlscontract.TLSEndpoint) tlschecker.TLSProbe {
		mu.Lock()
		dialed = append(dialed, ep)
		mu.Unlock()
		p := goodCert(ep)
		p.Chain = []tlschecker.CertInfo{{SPKISHA256: hash}}
		return p
	}}
	tlsa := map[string][]*dns.TLSA{"_25._tcp.mx.example.com": {{Usage: 3, Selector: 1, MatchingType: 1, Certificate: hash}}}

	for _, tt := range []struct {
		name  string
		ad    bool
		want  model.MailServerEndpointDane
		grade string
	}{
		{"validated", true, model.MailServerEndpointDaneMatch, "A+"},
		{"not validated", false, model.MailServerEndpointDaneUnverified, "A"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dialed = nil
			p := testProber(r, smtp)
			p.tls = tls
			p.secure = &fakeSecure{tlsa: tlsa, ad: tt.ad}
			result := p.Probe(context.Background(), "example.com")

			srv := (*result.Servers)[0]
			for _, ep := range srv.Endpoints {
				if utils.Deref(ep.Dane) != tt.want {
					t.Errorf("%s: DANE = %v (%s), want %s", ep.Ip, utils.Deref(ep.Dane), utils.Deref(ep.DaneMessage), tt.want)
				}
			}
			if string(utils.Deref(result.Grade)) != tt.grade {
				t.Errorf("grade = %s, want %s", utils.Deref(result.Grade), tt.grade)
			}
			// checker-tls dials the vetted address, with the MX name as SNI
			for _, ep := range dialed {
				if net.ParseIP(ep.Host) == nil || ep.SNI != "mx.example.com" || ep.STARTTLS != "smtp" || ep.Port != 25 {
					t.Errorf("TLS endpoint = %+v, want an address dialed with the MX name as SNI", ep)
				}
			}
			if len(dialed) != 2 {
				t.Errorf("%d TLS probes, want one per address", len(dialed))
			}
		})
	}
}

func TestNewFromConfigDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DisableMXProbes = true
	if svc := NewFromConfig(cfg); svc != nil {
		t.Errorf("NewFromConfig with probes disabled = %v, want nil", svc)
	}
}

// A client leaving does not wait for the probe, which goes on for the
// cache and for the other clients.
func TestServiceClientLeaves(t *testing.T) {
	prober := &countingProber{delay: 100 * time.Millisecond}
	s := NewService(nil, time.Minute)
	s.prober = prober

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := s.Check(ctx, "198.51.100.1", "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the client's deadline", err)
	}
	result, err := s.Check(context.Background(), "198.51.100.2", "example.com")
	if err != nil || result == nil || prober.n.Load() != 1 {
		t.Errorf("result = %v, err = %v, %d probes; want the probe started for the first client", result, err, prober.n.Load())
	}
}
