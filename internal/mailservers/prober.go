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

// Package mailservers probes the MX of a domain the way a sending server
// delivering to it would, for the Mail Servers section of the domain test.
// It drives the happyDomain checkers in process: checker-smtp for the SMTP
// conversation, checker-tls for the certificates, checker-dane for the TLSA
// records. Only the domain test calls it: the analysis of a received message
// never connects to any MX.
package mailservers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
	smtpchecker "git.happydns.org/checker-smtp/checker"
	tlschecker "git.happydns.org/checker-tls/checker"
	tlscontract "git.happydns.org/checker-tls/contract"
	"github.com/miekg/dns"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/analyzer"
	"git.happydns.org/happyDeliver/pkg/netguard"
)

// smtpPort is the port MX are delivered to.
const smtpPort = 25

// Options sets up a Prober.
type Options struct {
	// Timeout bounds the probe of one MX address.
	Timeout time.Duration
	// DNSTimeout bounds each DNS lookup.
	DNSTimeout time.Duration
	// HeloName is announced in EHLO. Empty leaves checker-smtp's own.
	HeloName string
	// RelayRecipient is the address the open relay test tries to send to:
	// one of the receiving domain of the instance, so that no third party
	// would ever get a stray message. Empty skips the test.
	RelayRecipient string
	// Witness is an MX host known to accept connections, asked when no MX
	// of the domain answers. Empty never concludes the probes inconclusive.
	Witness string
}

// Prober probes the mail servers of a domain.
type Prober struct {
	opts     Options
	resolver analyzer.DNSResolver
	// secure answers the TLSA lookups, with their DNSSEC flag. Nil leaves
	// DANE unchecked.
	secure analyzer.SecureResolver
	// policies reads the MTA-STS policy the servers are held to. Nil leaves
	// it unread.
	policies *analyzer.MailPolicyChecker
	smtp     sdk.ObservationProvider
	tls      sdk.ObservationProvider
	// publicAddr tells the addresses the probes may connect to.
	publicAddr func(net.IP) bool
	// reachable tells whether a TCP connection to host:25 succeeds, for
	// the witness.
	reachable func(ctx context.Context, host string) bool
	now       func() time.Time
}

// NewProber builds a prober over the checkers of happyDomain.
func NewProber(opts Options, resolver analyzer.DNSResolver, secure analyzer.SecureResolver, policies *analyzer.MailPolicyChecker) *Prober {
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if opts.DNSTimeout <= 0 {
		opts.DNSTimeout = 5 * time.Second
	}
	if resolver == nil {
		resolver = analyzer.NewStandardDNSResolver()
	}
	return &Prober{
		opts:       opts,
		resolver:   resolver,
		secure:     secure,
		policies:   policies,
		smtp:       smtpchecker.Provider(),
		tls:        tlschecker.Provider(),
		publicAddr: netguard.IsPublic,
		reachable:  dialSMTP,
		now:        time.Now,
	}
}

// dialSMTP tells whether host accepts TCP connections on port 25.
func dialSMTP(ctx context.Context, host string) bool {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(smtpPort)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// target is an MX host to probe, with the addresses it was found at.
type target struct {
	server *model.MailServer
	host   string
	addrs  map[string]*model.MailServerEndpoint
	safe   bool
	// certs is the TLS probe of each address, by canonical address.
	certs map[string]tlschecker.TLSProbe
}

// Probe connects to every MX address of domain and judges what it found.
func (p *Prober) Probe(ctx context.Context, domain string) *model.MailServersResult {
	result := &model.MailServersResult{
		Domain:   domain,
		Status:   model.MailServersResultStatusComplete,
		CachedAt: utils.PtrTo(p.now().UTC()),
	}

	// The MTA-STS policy is fetched while the servers are probed: the
	// verdict needs both, and neither waits on the other.
	var mtaSTS *model.MTASTSResult
	var policyWG sync.WaitGroup
	if p.policies != nil {
		policyWG.Go(func() { mtaSTS = p.policies.CheckMTASTS(ctx, domain) })
	}

	relayTested := p.relayRecipient(domain) != ""
	targets := p.discover(ctx, domain, result)
	if result.Status != model.MailServersResultStatusComplete {
		policyWG.Wait()
		judge(result, nil, relayTested)
		return result
	}

	var wg sync.WaitGroup
	for _, t := range targets {
		if !t.safe {
			continue
		}
		wg.Go(func() { p.probeTarget(ctx, domain, t) })
	}
	wg.Wait()

	p.probeCertificates(ctx, targets)
	if p.secure != nil {
		p.checkDANE(ctx, targets)
	}
	policyWG.Wait()

	if !anyConnected(result) && anyProbed(result) && p.opts.Witness != "" {
		wctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
		ok := p.reachable(wctx, p.opts.Witness)
		cancel()
		if !ok {
			result.Status = model.MailServersResultStatusInconclusive
			result.Error = utils.PtrTo("No MX of the domain answered on port 25, and neither did a server known to accept connections: this instance cannot reach port 25.")
		}
	}

	judge(result, mtaSTS, relayTested)
	return result
}

// relayRecipient is the recipient of the open relay test of domain, empty
// when the test cannot run: no recipient configured, or the domain tested
// being the one the recipient is in, which its MX rightly accept.
func (p *Prober) relayRecipient(domain string) string {
	r := p.opts.RelayRecipient
	if r == "" || strings.HasSuffix(strings.ToLower(r), "@"+strings.ToLower(domain)) {
		return ""
	}
	return r
}

// discover looks up the MX of domain and their addresses, refusing those not
// routable on the Internet: the probes never connect to them.
func (p *Prober) discover(ctx context.Context, domain string, result *model.MailServersResult) []*target {
	lookup, cancel := context.WithTimeout(ctx, p.opts.DNSTimeout)
	defer cancel()

	mxs, err := p.resolver.LookupMX(lookup, domain)
	if err == nil && len(mxs) == 1 && mxs[0].Pref == 0 && (mxs[0].Host == "." || mxs[0].Host == "") {
		result.Status = model.MailServersResultStatusNullMx
		return nil
	}
	if err != nil && !isNotFound(err) {
		result.Status = model.MailServersResultStatusInconclusive
		result.Error = utils.PtrTo(fmt.Sprintf("The MX records of %s could not be looked up: %s", domain, err))
		return nil
	}
	if err != nil || len(mxs) == 0 {
		// Implicit MX (RFC 5321 section 5.1): the domain's own address
		mxs = []*net.MX{{Host: domain, Pref: 0}}
		result.ImplicitMx = utils.PtrTo(true)
	}
	slices.SortStableFunc(mxs, func(a, b *net.MX) int { return int(a.Pref) - int(b.Pref) })

	var targets []*target
	seen := map[string]bool{}
	servers := []model.MailServer{}
	for _, mx := range mxs {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		servers = append(servers, model.MailServer{Host: host, Priority: int(mx.Pref), Endpoints: []model.MailServerEndpoint{}})
	}
	result.Servers = &servers

	for i := range servers {
		srv := &servers[i]
		t := &target{server: srv, host: srv.Host, addrs: map[string]*model.MailServerEndpoint{}, certs: map[string]tlschecker.TLSProbe{}}
		targets = append(targets, t)

		if net.ParseIP(srv.Host) != nil {
			srv.SkipReason = utils.PtrTo("An MX record must name a host, not an address (RFC 5321 section 5.1): senders do not deliver to it.")
			continue
		}
		addrs, err := p.resolver.LookupHost(lookup, srv.Host)
		if err != nil || len(addrs) == 0 {
			srv.SkipReason = utils.PtrTo(fmt.Sprintf("%s does not resolve to any address.", srv.Host))
			continue
		}

		t.safe = true
		for _, a := range addrs {
			ip := net.ParseIP(a)
			ep := model.MailServerEndpoint{Ip: a, Ipv6: utils.PtrTo(ip != nil && ip.To4() == nil)}
			if !p.publicAddr(ip) {
				ep.SkipReason = utils.PtrTo("Not routable on the Internet: no sender can reach it, and this instance does not connect to it.")
				t.safe = false
			}
			srv.Endpoints = append(srv.Endpoints, ep)
		}
		if !t.safe {
			// checker-smtp resolves the host again and connects to all its
			// addresses: a host with any private one is not handed to it.
			for j := range srv.Endpoints {
				if srv.Endpoints[j].SkipReason == nil {
					srv.Endpoints[j].SkipReason = utils.PtrTo("Not probed: the host also resolves to addresses not routable on the Internet.")
				}
			}
		}
		for j := range srv.Endpoints {
			t.addrs[canonicalIP(srv.Endpoints[j].Ip)] = &srv.Endpoints[j]
		}
	}

	if len(servers) == 0 || (utils.Deref(result.ImplicitMx) && len(servers[0].Endpoints) == 0) {
		result.Status = model.MailServersResultStatusNoMx
	}
	return targets
}

// isNotFound tells whether a lookup failed because the name or the record
// does not exist, rather than for want of an answer.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func canonicalIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// mxService is the svcs.MXs payload checker-smtp takes its targets from,
// instead of looking the MX up again.
func mxService(host string) json.RawMessage {
	body, _ := json.Marshal(map[string]any{
		"mx": []map[string]any{{"Preference": 0, "Mx": host + "."}},
	})
	return body
}

// probeTarget runs the SMTP conversation with every address of one MX host.
func (p *Prober) probeTarget(ctx context.Context, domain string, t *target) {
	opts := sdk.CheckerOptions{
		"domain":           domain,
		"service":          mxService(t.host),
		"timeout":          p.opts.Timeout.Seconds(),
		"test_null_sender": true,
		"test_postmaster":  true,
		"test_open_relay":  false,
	}
	if p.opts.HeloName != "" {
		opts["helo_name"] = p.opts.HeloName
	}
	if r := p.relayRecipient(domain); r != "" {
		opts["test_open_relay"] = true
		opts["test_probe_address"] = r
	}

	raw, err := p.smtp.Collect(ctx, opts)
	data, ok := raw.(*smtpchecker.SMTPData)
	if err != nil || !ok || data == nil {
		reason := "the SMTP probe could not run"
		if err != nil {
			reason += ": " + err.Error()
		}
		for _, ep := range t.addrs {
			ep.Error = utils.PtrTo(reason)
		}
		return
	}

	for _, probe := range data.Endpoints {
		// An address checker-smtp found that discover did not, the host
		// having changed its records in between, is not reported: it was
		// not vetted.
		ep, known := t.addrs[canonicalIP(probe.IP)]
		if !known || ep.SkipReason != nil {
			continue
		}
		fillEndpoint(ep, probe)
	}
}

// fillEndpoint copies what checker-smtp observed into the endpoint.
func fillEndpoint(ep *model.MailServerEndpoint, probe smtpchecker.EndpointProbe) {
	ep.Probed = true
	ep.LatencyMs = utils.PtrTo(int(probe.ElapsedMS))
	if probe.Error != "" {
		ep.Error = utils.PtrTo(probe.Error)
	}
	ep.TcpConnected = utils.PtrTo(probe.TCPConnected)
	if probe.BannerReceived {
		ep.Banner = utils.PtrTo(probe.BannerLine)
		if probe.BannerHostname != "" {
			ep.BannerHostname = utils.PtrTo(probe.BannerHostname)
		}
	}
	ep.Ehlo = utils.PtrTo(probe.EHLOReceived)
	if probe.EHLOHostname != "" {
		ep.EhloHostname = utils.PtrTo(probe.EHLOHostname)
	}
	if probe.EHLOFallbackHELO {
		ep.EhloFallbackHelo = utils.PtrTo(true)
	}
	if len(probe.Extensions) > 0 {
		exts := slices.Clone(probe.Extensions)
		ep.Extensions = &exts
	}
	if probe.EHLOReceived {
		ep.StarttlsOffered = utils.PtrTo(probe.STARTTLSOffered)
		ep.Starttls = utils.PtrTo(probe.STARTTLSUpgraded)
	}
	if probe.TLSVersion != "" {
		ep.TlsVersion = utils.PtrTo(probe.TLSVersion)
		ep.TlsCipher = utils.PtrTo(probe.TLSCipher)
	}
	if len(probe.AUTHPreTLS) > 0 {
		auth := slices.Clone(probe.AUTHPreTLS)
		ep.AuthBeforeTls = &auth
	}
	if probe.PTR != "" {
		ep.Ptr = utils.PtrTo(probe.PTR)
	}
	ep.Fcrdns = utils.PtrTo(probe.FCrDNSPass)
	if probe.NullSenderAccepted != nil {
		ep.NullSenderAccepted = utils.PtrTo(*probe.NullSenderAccepted)
		ep.NullSenderResponse = utils.PtrTo(probe.NullSenderResponse)
	}
	if probe.PostmasterAccepted != nil {
		ep.PostmasterAccepted = utils.PtrTo(*probe.PostmasterAccepted)
		ep.PostmasterResponse = utils.PtrTo(probe.PostmasterResponse)
	}
	if probe.OpenRelay != nil {
		ep.OpenRelay = utils.PtrTo(*probe.OpenRelay)
		ep.OpenRelayResponse = utils.PtrTo(probe.OpenRelayResponse)
	}
}

// probeCertificates has checker-tls look at the certificate of every address
// that completed STARTTLS. The address is dialed directly, with the MX name
// as SNI: no lookup stands between the vetting and the connection.
func (p *Prober) probeCertificates(ctx context.Context, targets []*target) {
	type pending struct {
		target *target
		ep     *model.MailServerEndpoint
	}
	var entries []sdk.DiscoveryEntry
	byRef := map[string]pending{}
	for _, t := range targets {
		for _, ep := range t.addrs {
			if !utils.Deref(ep.Starttls) {
				continue
			}
			entry, err := tlscontract.NewEntry(tlscontract.TLSEndpoint{
				Host:     ep.Ip,
				Port:     smtpPort,
				SNI:      t.host,
				STARTTLS: "smtp",
			})
			if err != nil {
				continue
			}
			entries = append(entries, entry)
			byRef[entry.Ref] = pending{target: t, ep: ep}
		}
	}
	if len(entries) == 0 {
		return
	}

	raw, err := p.tls.Collect(ctx, sdk.CheckerOptions{
		tlschecker.OptionEndpoints:      entries,
		tlschecker.OptionProbeTimeoutMs: int(p.opts.Timeout.Milliseconds()),
	})
	data, ok := raw.(*tlschecker.TLSData)
	if err != nil || !ok || data == nil {
		return
	}
	for ref, probe := range data.Probes {
		target, known := byRef[ref]
		if !known {
			continue
		}
		target.ep.Certificate = certificateOf(probe, p.now())
		target.target.certs[canonicalIP(target.ep.Ip)] = probe
	}
}

// certificateOf is what the report shows of a TLS probe.
func certificateOf(probe tlschecker.TLSProbe, now time.Time) *model.MailServerCertificate {
	if !probe.TLSHandshakeOK {
		if probe.HandshakeError == "" && probe.TCPError == "" {
			return nil
		}
		return &model.MailServerCertificate{ChainError: utils.PtrTo(firstNonEmpty(probe.HandshakeError, probe.TCPError))}
	}
	cert := &model.MailServerCertificate{
		Subject:       nonEmpty(probe.Subject),
		Issuer:        nonEmpty(probe.Issuer),
		ChainValid:    probe.ChainValid,
		HostnameMatch: probe.HostnameMatch,
		ChainError:    nonEmpty(probe.ChainVerifyErr),
	}
	if len(probe.DNSNames) > 0 {
		names := slices.Clone(probe.DNSNames)
		cert.DnsNames = &names
	}
	if !probe.NotAfter.IsZero() {
		cert.NotAfter = utils.PtrTo(probe.NotAfter)
		cert.DaysLeft = utils.PtrTo(int(probe.NotAfter.Sub(now).Hours() / 24))
	}
	return cert
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func anyConnected(result *model.MailServersResult) bool {
	for _, srv := range deref(result.Servers) {
		for _, ep := range srv.Endpoints {
			if utils.Deref(ep.TcpConnected) {
				return true
			}
		}
	}
	return false
}

func anyProbed(result *model.MailServersResult) bool {
	for _, srv := range deref(result.Servers) {
		for _, ep := range srv.Endpoints {
			if ep.Probed {
				return true
			}
		}
	}
	return false
}

// lookupTLSA returns the TLSA records of SMTP on host, and whether a
// validating resolver vouched for them.
func (p *Prober) lookupTLSA(ctx context.Context, host string) ([]*dns.TLSA, bool) {
	ctx, cancel := context.WithTimeout(ctx, p.opts.DNSTimeout)
	defer cancel()
	answer, err := p.secure.Query(ctx, "_25._tcp."+host, dns.TypeTLSA, false)
	if err != nil || answer.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	var records []*dns.TLSA
	for _, rr := range answer.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			records = append(records, t)
		}
	}
	return records, answer.AuthenticatedData
}

// deref is the list p points to, nil for none.
func deref[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
