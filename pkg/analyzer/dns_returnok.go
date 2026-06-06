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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// ReturnOKDomain.Status values, matching the schema enum. Kept as a plain string
// in the generated model (x-go-type) to avoid colliding with other "pass"/"fail"
// enums in the global enum namespace.
const (
	returnOKStatusPass = "pass"
	returnOKStatusWarn = "warn"
	returnOKStatusFail = "fail"
)

// domainCanReceive reports whether a domain can accept mail, looking up records
// in the same order as Fastmail's ReturnOK milter: MX first, then A/AAAA.
func (d *DNSAnalyzer) domainCanReceive(domain string) (hasMX, hasAddress bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	if mxRecords, err := d.resolver.LookupMX(ctx, domain); err == nil && len(mxRecords) > 0 {
		return true, false
	}

	if addrs, err := d.resolver.LookupHost(ctx, domain); err == nil && len(addrs) > 0 {
		return false, true
	}

	return false, false
}

// checkReturnOKDomain verifies that a domain can receive replies/bounces.
// It checks the domain itself, then falls back to its organizational domain
// (when different) the same way the ReturnOK milter retries the org domain.
func (d *DNSAnalyzer) checkReturnOKDomain(domain, orgDomain string) *model.ReturnOKDomain {
	if domain == "" {
		return nil
	}

	result := &model.ReturnOKDomain{Domain: domain}

	hasMX, hasAddress := d.domainCanReceive(domain)

	// Fall back to the organizational domain when the domain itself has nothing.
	if !hasMX && !hasAddress && orgDomain != "" && orgDomain != domain {
		if orgMX, orgAddr := d.domainCanReceive(orgDomain); orgMX || orgAddr {
			hasMX, hasAddress = orgMX, orgAddr
			result.OrgDomain = utils.PtrTo(orgDomain)
		}
	}

	result.HasMx = utils.PtrTo(hasMX)
	result.HasAddress = utils.PtrTo(hasAddress)

	switch {
	case hasMX:
		result.Status = returnOKStatusPass
	case hasAddress:
		result.Status = returnOKStatusWarn
	default:
		result.Status = returnOKStatusFail
	}

	return result
}

// calculateReturnOKPenalty returns a non-positive value: each sender domain that
// can receive neither replies nor bounces (status=fail) costs points, since
// those messages would be silently lost.
func calculateReturnOKPenalty(results *model.DNSResults) (penalty int) {
	if results.ReturnOk == nil {
		return 0
	}
	for _, dom := range []*model.ReturnOKDomain{results.ReturnOk.From, results.ReturnOk.ReturnPath} {
		if dom != nil && dom.Status == returnOKStatusFail {
			penalty -= 10
		}
	}
	return
}

// orgDomainOrEmpty dereferences an optional organizational domain pointer.
func orgDomainOrEmpty(orgDomain *string) string {
	if orgDomain == nil {
		return ""
	}
	return *orgDomain
}
