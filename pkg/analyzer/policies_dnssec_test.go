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
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"git.happydns.org/happyDeliver/internal/model"
)

// fakeSecureResolver answers queries from a function of the question.
type fakeSecureResolver struct {
	answer func(name string, qtype uint16, cd bool) (*dns.Msg, error)
}

func (f *fakeSecureResolver) Query(_ context.Context, name string, qtype uint16, cd bool) (*dns.Msg, error) {
	return f.answer(strings.TrimSuffix(name, "."), qtype, cd)
}

func (f *fakeSecureResolver) Address() string { return "192.0.2.53:53" }

func reply(rcode int, ad bool, rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = rcode
	m.AuthenticatedData = ad
	m.Answer = rrs
	return m
}

func TestCheckDNSSEC(t *testing.T) {
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}}
	tests := []struct {
		name    string
		answer  func(string, uint16, bool) (*dns.Msg, error)
		status  model.DNSSECResultStatus
		issue   model.IssueType
		penalty int
	}{
		{"secure", func(string, uint16, bool) (*dns.Msg, error) { return reply(dns.RcodeSuccess, true), nil }, model.DNSSECResultStatusSecure, "", 0},
		{"insecure", func(string, uint16, bool) (*dns.Msg, error) { return reply(dns.RcodeSuccess, false), nil }, model.DNSSECResultStatusInsecure, model.IssueTypeDnssecUnsigned, 0},
		{"unvalidated", func(string, uint16, bool) (*dns.Msg, error) { return reply(dns.RcodeSuccess, false, sig), nil }, model.DNSSECResultStatusUnvalidated, model.IssueTypeDnssecUnvalidated, 0},
		{"broken", func(_ string, _ uint16, cd bool) (*dns.Msg, error) {
			if cd {
				return reply(dns.RcodeSuccess, false), nil
			}
			return reply(dns.RcodeServerFailure, false), nil
		}, model.DNSSECResultStatusBroken, model.IssueTypeDnssecBroken, dnssecPenaltyBroken},
		{"servfail either way", func(string, uint16, bool) (*dns.Msg, error) { return reply(dns.RcodeServerFailure, false), nil }, model.DNSSECResultStatusUnknown, model.IssueTypeDnssecUnvalidated, 0},
		{"timeout", func(string, uint16, bool) (*dns.Msg, error) { return nil, errors.New("i/o timeout") }, model.DNSSECResultStatusUnknown, model.IssueTypeDnssecUnvalidated, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMailPolicyChecker(time.Second, time.Second, &fakeResolver{}).WithSecureResolver(&fakeSecureResolver{answer: tt.answer})
			policies := &model.MailPolicies{Dnssec: m.checkDNSSEC(context.Background(), "example.com")}
			evaluate(policies)
			if policies.Dnssec.Status != tt.status || *policies.Penalty != tt.penalty {
				t.Errorf("result = %+v, penalty = %d", policies.Dnssec, *policies.Penalty)
			}
			issues := deref(policies.Issues.Dnssec)
			if tt.issue == "" && len(issues) > 0 || tt.issue != "" && hasIssue(issues, tt.issue) == nil {
				t.Errorf("issues = %v, want %q", issueTypes(issues), tt.issue)
			}
		})
	}
}

func TestCheckDANEHosts(t *testing.T) {
	f := &fakeResolver{mx: map[string][]*net.MX{"example.com": {{Host: "mx1.example.com.", Pref: 10}, {Host: "mx2.example.com.", Pref: 20}}}}
	secure := &fakeSecureResolver{answer: func(name string, qtype uint16, _ bool) (*dns.Msg, error) {
		if qtype == dns.TypeTLSA && name == "_25._tcp.mx1.example.com" {
			return reply(dns.RcodeSuccess, true, &dns.TLSA{Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypeTLSA}, Usage: 3, Selector: 1, MatchingType: 1, Certificate: "00"}), nil
		}
		return reply(dns.RcodeNameError, true), nil
	}}
	m := NewMailPolicyChecker(time.Second, time.Second, f).WithSecureResolver(secure)
	policies := m.Check(context.Background(), "example.com")
	if hosts := deref(policies.DaneHosts); len(hosts) != 1 || hosts[0] != "mx1.example.com" {
		t.Errorf("DANE hosts = %v, want [mx1.example.com]", hosts)
	}
}

func TestNewValidatingResolverAddress(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.53":        "192.0.2.53:53",
		"192.0.2.53:5353":   "192.0.2.53:5353",
		"2001:db8::53":      "[2001:db8::53]:53",
		"[2001:db8::53]:53": "[2001:db8::53]:53",
	} {
		r, err := NewValidatingResolver(addr, time.Second)
		if err != nil || r.Address() != want {
			t.Errorf("NewValidatingResolver(%q) = %v, %v; want %s", addr, r, err, want)
		}
	}
}

// localDNS serves handler on 127.0.0.1 over UDP and TCP, on the same port.
func localDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Skipf("cannot listen on TCP alongside UDP: %v", err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: ln, Handler: handler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() {
		udp.Shutdown()
		tcp.Shutdown()
	})
	return pc.LocalAddr().String()
}

// An answer truncated over UDP is asked again over TCP, as TLSA and signed
// answers often are.
func TestValidatingResolverRetriesOverTCP(t *testing.T) {
	addr := localDNS(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Truncated = true
		} else {
			m.AuthenticatedData = true
			m.Answer = append(m.Answer, &dns.TLSA{
				Hdr:   dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
				Usage: 3, Selector: 1, MatchingType: 1, Certificate: "00",
			})
		}
		if opt := req.IsEdns0(); opt == nil || !opt.Do() {
			m.Rcode = dns.RcodeRefused
		}
		w.WriteMsg(m)
	})

	r, err := NewValidatingResolver(addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := r.Query(context.Background(), "_25._tcp.mx.example.com", dns.TypeTLSA, false)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || !answer.AuthenticatedData || len(answer.Answer) != 1 {
		t.Errorf("answer = %v, want the TCP answer with the DO bit honored", answer)
	}
}
