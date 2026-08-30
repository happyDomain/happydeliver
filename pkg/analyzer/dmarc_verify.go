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
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dmarc"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// DMARCVerifier evaluates DMARC alignment for a message, against the policy
// published in the DNS for the From domain.
//
// Unlike the Authentication-Results parsing, which reports what some other
// server claimed, this is a first-hand verdict: it is computed here, from the
// SPF and DKIM results already established for the message and the policy
// record fetched from the DNS, and cannot be forged by whoever supplied the
// message.
type DMARCVerifier struct {
	resolver DNSResolver
	timeout  time.Duration
}

// NewDMARCVerifier creates a verifier resolving DMARC policy records through
// resolver. A nil resolver disables verification: VerifyDMARC then reports
// nothing rather than reaching for the system resolver behind the caller's
// back.
func NewDMARCVerifier(resolver DNSResolver, timeout time.Duration) *DMARCVerifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DMARCVerifier{resolver: resolver, timeout: timeout}
}

// VerifyDMARC evaluates DMARC for a message whose visible sender domain is
// fromDomain, against the SPF result and the DKIM results already computed for
// it.
//
// It returns nil when there is nothing to judge: no From domain, no resolver,
// or no DMARC policy published for it (or its organizational domain) — a
// domain that publishes no policy is not covered by DMARC at all, which is not
// the same thing as failing it.
func (v *DMARCVerifier) VerifyDMARC(fromDomain string, spf *model.AuthResult, dkimResults []model.AuthResult) *model.AuthResult {
	if v == nil || v.resolver == nil || fromDomain == "" {
		return nil
	}

	record, lookedUpAt, err := v.lookupPolicy(fromDomain)
	if err != nil {
		if dmarc.IsTempFail(err) {
			return &model.AuthResult{
				Result:  model.AuthResultResultTemperror,
				Domain:  utils.PtrTo(fromDomain),
				Details: utils.PtrTo(err.Error()),
			}
		}
		if err == dmarc.ErrNoPolicy {
			return nil
		}
		return &model.AuthResult{
			Result:  model.AuthResultResultPermerror,
			Domain:  utils.PtrTo(fromDomain),
			Details: utils.PtrTo(err.Error()),
		}
	}

	spfAligned := spf != nil && spf.Result == model.AuthResultResultPass &&
		domainAligned(spf.Domain, fromDomain, record.SPFAlignment)
	dkimAligned := false
	for _, d := range dkimResults {
		if d.Result == model.AuthResultResultPass && domainAligned(d.Domain, fromDomain, record.DKIMAlignment) {
			dkimAligned = true
			break
		}
	}

	// Policy applies at the organizational domain, and the effective policy for
	// a message from a subdomain is sp= (falling back to p=) when the record was
	// only published there.
	policy := record.Policy
	if lookedUpAt != strings.ToLower(fromDomain) && record.SubdomainPolicy != "" {
		policy = record.SubdomainPolicy
	}

	result := model.AuthResultResultFail
	if spfAligned || dkimAligned {
		result = model.AuthResultResultPass
	}

	return &model.AuthResult{
		Result: result,
		Domain: utils.PtrTo(fromDomain),
		Details: utils.PtrTo(fmt.Sprintf(
			"p=%s spf=%s dkim=%s",
			policy, alignmentWord(spfAligned), alignmentWord(dkimAligned),
		)),
	}
}

// lookupPolicy fetches the DMARC record covering domain, falling back to the
// organizational domain when domain itself publishes none, per RFC 7489
// section 6.6.3. It returns the domain the record was actually found at,
// lower-cased, alongside the record.
func (v *DMARCVerifier) lookupPolicy(domain string) (*dmarc.Record, string, error) {
	opts := &dmarc.LookupOptions{LookupTXT: v.lookupTXT}

	record, err := dmarc.LookupWithOptions(domain, opts)
	if err == dmarc.ErrNoPolicy {
		if org := getOrganizationalDomain(domain); !strings.EqualFold(org, domain) {
			if orgRecord, orgErr := dmarc.LookupWithOptions(org, opts); orgErr == nil {
				return orgRecord, strings.ToLower(org), nil
			}
		}
	}
	if err != nil {
		return nil, "", err
	}

	return record, strings.ToLower(domain), nil
}

// lookupTXT adapts the analyzer's resolver to the signature go-msgauth expects.
func (v *DMARCVerifier) lookupTXT(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	return v.resolver.LookupTXT(ctx, domain)
}

// domainAligned reports whether authDomain, the domain an SPF or DKIM check
// authenticated, aligns with fromDomain under mode. Relaxed alignment (the
// default) compares organizational domains; strict alignment requires an exact
// match.
func domainAligned(authDomain *string, fromDomain string, mode dmarc.AlignmentMode) bool {
	if authDomain == nil {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(*authDomain, fromDomain)
	}
	return strings.EqualFold(getOrganizationalDomain(*authDomain), getOrganizationalDomain(fromDomain))
}

// alignmentWord renders an alignment outcome the way an Authentication-Results
// dmarc= comment does.
func alignmentWord(aligned bool) string {
	if aligned {
		return "pass"
	}
	return "fail"
}
