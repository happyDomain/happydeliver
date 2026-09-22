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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/domainname"
	"git.happydns.org/happyDeliver/pkg/emaildata/disposable"
	"git.happydns.org/happyDeliver/pkg/emaildata/freemail"
)

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
