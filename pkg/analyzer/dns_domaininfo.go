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
	"context"
	"errors"
	"flag"
	"log"
	"time"

	"git.happydns.org/happyDomain/pkg/domaininfo"
	"git.happydns.org/happyDomain/pkg/domaininfo/types"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/domainname"
	"git.happydns.org/happyDeliver/pkg/emaildata/disposable"
	"git.happydns.org/happyDeliver/pkg/emaildata/freemail"
)

// What the operator decided about reading registrations, declared here the
// way each attachment scanner declares its own flags: the analysis config
// need not know what a registry lookup is made of.
var (
	// domainInfoTimeout bounds one registration lookup. RDAP fetches the
	// IANA bootstrap file over HTTP before asking the registry, and a WHOIS
	// fallback can be slow, so it is longer than a DNS query's.
	domainInfoTimeout = 15 * time.Second

	// domainInfoDisabled leaves registrations unread, for an operator who
	// does not want outbound WHOIS from this instance.
	domainInfoDisabled bool
)

func init() {
	flag.DurationVar(&domainInfoTimeout, "domain-info-timeout", domainInfoTimeout, "Timeout when reading a sender domain's registration over RDAP or WHOIS")
	flag.BoolVar(&domainInfoDisabled, "disable-domain-info", domainInfoDisabled, "Do not read sender domain registrations over RDAP or WHOIS")
}

// defaultDomainInfoGetter is what an analyzer reads registrations with when
// nothing else is injected: happyDomain's lookup, behind a cache shared by
// every analyzer of the process. Registries rate-limit, and the same sender
// domain is tested over and over.
var defaultDomainInfoGetter = newDomainInfoCache(domaininfo.GetDomainInfo, domainInfoCacheTTL, domainInfoCacheSize).get

// domainInfoCacheTTL is how long a registration is trusted not to have
// changed. A day: a domain does not get registered twice in one.
const domainInfoCacheTTL = 24 * time.Hour

// domainInfoCacheSize bounds the cache, so that a stream of never-seen
// domains cannot grow it without end.
const domainInfoCacheSize = 4096

// What a sender domain costs the DNS score for what it is. A throwaway
// provider in the visible sender is what filters refuse outright; in the
// envelope alone it is a bounce address nobody will read, which is less.
const (
	penaltyDisposableFrom       = -25
	penaltyDisposableReturnPath = -10
)

// orgDomainOf is the organizational domain to ask a registry about: the one
// the headers analysis already worked out, and otherwise the one read off
// the domain itself. Both callers need it, and they must agree, or the same
// registration would be looked up twice under two names.
func orgDomainOf(domain, known string) string {
	if known != "" {
		return known
	}
	return domainname.Organizational(domain)
}

// checkDomainInfo reads what is known of a sender domain beyond its records.
// The information is about the organizational domain, which is what a
// registry answers for; the provider lists are asked about the domain itself,
// as a subdomain of a listed provider is still that provider.
func (d *DNSAnalyzer) checkDomainInfo(domain, orgDomain string) *model.SenderDomainInfo {
	if domain == "" {
		return nil
	}

	info := &model.SenderDomainInfo{
		Domain:     orgDomainOf(domain, orgDomain),
		Disposable: disposable.Is(domain),
	}
	d.readRegistration(info)
	// The free provider list holds throwaway providers too, being a list of
	// where anyone may open an address. A domain is one thing to the reader:
	// a throwaway provider is reported as that, and not also as a mailbox
	// provider.
	if !info.Disposable {
		info.FreeProvider = freemail.Is(domain)
	}

	return info
}

// calculateDomainInfoPenalty returns a non-positive value: what the sender
// domains cost for what they are, whatever their records say.
func calculateDomainInfoPenalty(results *model.DNSResults) (penalty int) {
	if results.FromDomainInfo != nil && results.FromDomainInfo.Disposable {
		penalty += penaltyDisposableFrom
	}
	if results.RpDomainInfo != nil && results.RpDomainInfo.Disposable {
		penalty += penaltyDisposableReturnPath
	}
	return
}

// readRegistration fills in what the registry publishes about the domain.
// A lookup that fails leaves the registration fields out and says why in
// error: a registry being down says nothing about the sender.
func (d *DNSAnalyzer) readRegistration(info *model.SenderDomainInfo) {
	if d.domainInfo == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.domainInfoTimeout)
	defer cancel()

	registration, err := d.domainInfo(ctx, info.Domain)
	switch {
	case errors.Is(err, types.ErrDomainDoesNotExist):
		info.Error = utils.PtrTo("domain is not registered")
		return
	case err != nil:
		log.Printf("registration of %s could not be read: %v", info.Domain, err)
		info.Error = utils.PtrTo("registration could not be read: " + err.Error())
		return
	case registration == nil:
		return
	}

	if registration.Registrar != "" && registration.Registrar != "Unknown" {
		info.Registrar = utils.PtrTo(registration.Registrar)
	}
	info.RegistrarUrl = registration.RegistrarURL
	info.CreationDate = registration.CreationDate
	info.ExpirationDate = registration.ExpirationDate
	if registration.CreationDate != nil {
		// Settled at analysis time, so that a report read later still says
		// how old the domain was when the message was sent.
		info.AgeDays = utils.PtrTo(max(0, int(time.Since(*registration.CreationDate).Hours()/24)))
	}
	if len(registration.Status) > 0 {
		info.Status = utils.PtrTo(registration.Status)
	}
	// The registrant's country is the one contact field kept: it says where
	// the sender is, which is what the reader wants of it, and nothing of
	// who they are.
	if registrant := registration.Contacts["registrant"]; registrant != nil && registrant.Country != "" {
		info.RegistrantCountry = utils.PtrTo(registrant.Country)
	}
}
