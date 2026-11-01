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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// SecureResolver answers the lookups that need what net.Resolver hides: the
// DNSSEC flags of the answer, and record types it has no method for.
type SecureResolver interface {
	// Query asks name of type qtype with the DO bit set, checking
	// disabled (CD) when cd is true, and returns the whole answer.
	Query(ctx context.Context, name string, qtype uint16, cd bool) (*dns.Msg, error)
	// Address names the resolver asked, for the report.
	Address() string
}

// validatingResolver queries one resolver over UDP, retrying over TCP when
// the answer is truncated. The resolver has to validate DNSSEC for the AD
// flag to mean anything: a local unbound, or a trusted one.
type validatingResolver struct {
	addr    string
	timeout time.Duration
}

// NewValidatingResolver returns a SecureResolver asking addr ("host" or
// "host:port"). An empty addr takes the first nameserver of
// /etc/resolv.conf.
func NewValidatingResolver(addr string, timeout time.Duration) (SecureResolver, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cfg.Servers) == 0 {
			return nil, fmt.Errorf("no resolver configured and none found in /etc/resolv.conf")
		}
		addr = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	} else if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &validatingResolver{addr: addr, timeout: timeout}, nil
}

func (r *validatingResolver) Address() string { return r.addr }

// WithSecureResolver has the checker read DNSSEC and DANE through secure.
func (m *MailPolicyChecker) WithSecureResolver(secure SecureResolver) *MailPolicyChecker {
	m.secure = secure
	return m
}

func (r *validatingResolver) Query(ctx context.Context, name string, qtype uint16, cd bool) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	msg.AuthenticatedData = true
	msg.CheckingDisabled = cd
	msg.SetEdns0(4096, true)

	client := &dns.Client{Timeout: r.timeout}
	in, _, err := client.ExchangeContext(ctx, msg, r.addr)
	if err == nil && in.Truncated {
		client.Net = "tcp"
		in, _, err = client.ExchangeContext(ctx, msg, r.addr)
	}
	return in, err
}

// hasSignatures tells whether an answer carries RRSIG records, in its answer
// or authority section: the zone is signed, validated or not.
func hasSignatures(msg *dns.Msg) bool {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if _, ok := rr.(*dns.RRSIG); ok {
				return true
			}
		}
	}
	return false
}

// checkDNSSEC tells whether the zone of domain is signed and validates. The
// SOA of the name is asked for: it exists in every zone, at the apex or in
// the authority section of a negative answer, and so do its signatures.
func (m *MailPolicyChecker) checkDNSSEC(ctx context.Context, domain string) *model.DNSSECResult {
	result := &model.DNSSECResult{Status: model.DNSSECResultStatusUnknown}
	result.Resolver = utils.PtrTo(m.secure.Address())

	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()

	answer, err := m.secure.Query(ctx, domain, dns.TypeSOA, false)
	if err != nil {
		result.Error = utils.PtrTo(fmt.Sprintf("The lookup failed: %s", err))
		return result
	}

	switch {
	case answer.Rcode == dns.RcodeServerFailure:
		// Asked again without validation: if the zone answers then, it is
		// the validation that fails.
		retry, err := m.secure.Query(ctx, domain, dns.TypeSOA, true)
		if err == nil && (retry.Rcode == dns.RcodeSuccess || retry.Rcode == dns.RcodeNameError) {
			result.Status = model.DNSSECResultStatusBroken
			result.Error = utils.PtrTo("The resolver fails to validate the answer (SERVFAIL), but answers once validation is disabled: the DNSSEC chain of trust is broken.")
		} else {
			result.Error = utils.PtrTo("The resolver fails to answer (SERVFAIL), with or without validation.")
		}
	case answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError:
		result.Error = utils.PtrTo(fmt.Sprintf("The resolver answers %s.", dns.RcodeToString[answer.Rcode]))
	case answer.AuthenticatedData:
		result.Status = model.DNSSECResultStatusSecure
	case hasSignatures(answer):
		result.Status = model.DNSSECResultStatusUnvalidated
	default:
		result.Status = model.DNSSECResultStatusInsecure
	}
	return result
}

// checkDANEHosts tells which MX hosts of domain publish TLSA records for
// SMTP, that is deploy DANE (RFC 7672).
func (m *MailPolicyChecker) checkDANEHosts(ctx context.Context, domain string) []string {
	lookupCtx, cancel := context.WithTimeout(ctx, m.Timeout)
	mxs, err := m.resolver.LookupMX(lookupCtx, domain)
	cancel()
	if err != nil || isNullMX(mxs) {
		return nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var hosts []string
	seen := map[string]bool{}
	for _, mx := range mxs {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		if host == "" || seen[host] || net.ParseIP(host) != nil {
			continue
		}
		seen[host] = true
		wg.Go(func() {
			if len(m.lookupTLSA(ctx, host)) > 0 {
				mu.Lock()
				hosts = append(hosts, host)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return hosts
}

// lookupTLSA returns the TLSA records of SMTP on host.
func (m *MailPolicyChecker) lookupTLSA(ctx context.Context, host string) []*dns.TLSA {
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	answer, err := m.secure.Query(ctx, "_25._tcp."+host, dns.TypeTLSA, false)
	if err != nil || answer.Rcode != dns.RcodeSuccess {
		return nil
	}
	var records []*dns.TLSA
	for _, rr := range answer.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			records = append(records, t)
		}
	}
	return records
}

// dnssecPenaltyBroken is what a broken chain of trust costs: validating
// resolvers, those of Google, Cloudflare and most providers among them,
// cannot resolve the domain at all, its MX included.
const dnssecPenaltyBroken = 20

// dnssecIssues is what the DNSSEC state of domain calls for.
func dnssecIssues(result *model.DNSSECResult, domain string, charge policyCharge) {
	if result == nil {
		return
	}
	switch result.Status {
	case model.DNSSECResultStatusBroken:
		charge(dnssecPenaltyBroken, newIssue(model.IssueTypeDnssecBroken, model.IssueSeverityHigh, domain,
			fmt.Sprintf("DNSSEC validation of %s fails: validating resolvers answer SERVFAIL, so senders relying on them cannot find its MX, and its SPF, DKIM and DMARC records cannot be read.", domain),
			"Check the DS record at your registrar against the DNSKEY of the zone, and that the signatures have not expired; remove the DS record if you mean to stop signing."))
	case model.DNSSECResultStatusInsecure:
		charge(0, newIssue(model.IssueTypeDnssecUnsigned, model.IssueSeverityInfo, domain,
			fmt.Sprintf("The zone of %s is not signed with DNSSEC, so its records can be forged on the way, and DANE cannot be deployed for its mail servers. Optional: it does not affect the score.", domain),
			"Enable DNSSEC at your DNS host, then publish the DS record it gives you at your registrar."))
	case model.DNSSECResultStatusUnvalidated:
		charge(0, newIssue(model.IssueTypeDnssecUnvalidated, model.IssueSeverityInfo, domain,
			fmt.Sprintf("The zone of %s carries DNSSEC signatures, but the resolver this instance uses does not validate them, so whether they hold cannot be told.", domain),
			"Instance operators: point --dns-resolver to a validating resolver."))
	case model.DNSSECResultStatusUnknown:
		charge(0, newIssue(model.IssueTypeDnssecUnvalidated, model.IssueSeverityInfo, domain,
			fmt.Sprintf("Whether the zone of %s is signed could not be told: %s", domain, utils.Deref(result.Error)),
			"Test again later if the failure looks temporary."))
	}
}
