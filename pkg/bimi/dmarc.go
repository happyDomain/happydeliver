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

package bimi

import (
	"fmt"
	"strings"
)

// DMARC policy values, as published in the p= and sp= tags.
const (
	DMARCPolicyNone       = "none"
	DMARCPolicyQuarantine = "quarantine"
	DMARCPolicyReject     = "reject"
)

// DMARCPolicy describes the DMARC policy in force for an Author Domain: the
// precondition BIMI section 7.1 puts on any Indicator display, before an
// Assertion Record is even looked up. It is an input to validation, not a
// result of it: pkg/bimi does not resolve DMARC itself, so a caller that
// already holds the record fills this in from it.
type DMARCPolicy struct {
	// Found reports whether a valid DMARC record was resolved at all. A
	// malformed record is not found: it cannot make a message pass DMARC.
	Found bool
	// Domain is the domain the DMARC record was found at, which may be an
	// ancestor of the Author Domain when the lookup climbed to it.
	Domain string
	// Policy is the p= value: DMARCPolicyNone, DMARCPolicyQuarantine or
	// DMARCPolicyReject. Any other value is reported as unknown.
	Policy string
	// SubdomainPolicy is the sp= value, empty when the tag is absent.
	SubdomainPolicy string
	// Percentage is the pct= value, nil when the tag is absent, which is
	// not the same as pct=100 for section 7.1 item 9.
	Percentage *int
	// TestMode reports whether the record publishes t=y.
	TestMode bool
}

// inherited reports whether the DMARC record was found above the Author Domain
// rather than at it, which is the case where its sp= tag is what governs the
// Author Domain.
func (p *DMARCPolicy) inherited(authorDomain string) bool {
	if p.Domain == "" || authorDomain == "" {
		return false
	}
	return normalizeDomain(p.Domain) != normalizeDomain(authorDomain)
}

// applicable returns the policy governing authorDomain and the tag it is
// published under. A record found above the Author Domain governs it through
// its sp= tag when one is published, and through p= otherwise.
func (p *DMARCPolicy) applicable(authorDomain string) (policy, tag string) {
	if p.inherited(authorDomain) && p.SubdomainPolicy != "" {
		return strings.ToLower(p.SubdomainPolicy), "sp="
	}
	return strings.ToLower(p.Policy), "p="
}

// CheckDMARCEnforcement reports whether the DMARC policy in force lets BIMI
// processing happen at all. Section 7.1 makes an enforcing DMARC policy a
// precondition of Indicator display: under p=none, under a subdomain policy of
// sp=none, or under p=quarantine with a pct= other than 100, receivers MUST NOT
// perform BIMI processing, and no Indicator is ever displayed however compliant
// the Assertion Record and its assets are.
//
// authorDomain is the domain the analysis was requested for, which section 7.1
// reasons about, not the domain the BIMI record was eventually found at. A nil
// policy means the caller did not evaluate DMARC, and the check is skipped
// rather than assumed to pass.
func CheckDMARCEnforcement(p *DMARCPolicy, authorDomain string) Check {
	const (
		name        = "dmarc_enforcement"
		description = "DMARC at enforcement"
	)

	if p == nil {
		return newCheck(name, description, StatusSkipped,
			"DMARC was not evaluated: BIMI requires the Author Domain to publish a DMARC policy at enforcement, a precondition this analysis did not check")
	}

	if !p.Found {
		return newCheck(name, description, StatusFail,
			fmt.Sprintf("No valid DMARC record was found for %s: a message is only considered for BIMI once it passes DMARC, so no Indicator will be displayed. Publish a DMARC record with p=quarantine or p=reject.", authorDomain))
	}

	policy, tag := p.applicable(authorDomain)

	var errs, warnings, infos []string

	switch policy {
	case DMARCPolicyQuarantine, DMARCPolicyReject:
		// Nothing to report here: pct= and t= below can undo an otherwise
		// enforcing policy, and the observation is only true once they have
		// had their say, so it is emitted at the end.

	case DMARCPolicyNone:
		if tag == "sp=" {
			errs = append(errs, fmt.Sprintf("The DMARC record at %s publishes sp=none, which is the policy governing the subdomain %s: receivers must not perform BIMI processing for it, so the Indicator will never be displayed whatever the record and the logo are worth. Publish a DMARC record at %s with p=quarantine or p=reject, or raise sp= on the parent record.",
				p.Domain, authorDomain, authorDomain))
		} else {
			errs = append(errs, fmt.Sprintf("%s publishes p=none: receivers must not perform BIMI processing for it, so the Indicator will never be displayed whatever the record and the logo are worth. Raise the policy to p=quarantine or p=reject.",
				p.Domain))
		}

	default:
		errs = append(errs, fmt.Sprintf("The DMARC record at %s publishes no usable %s policy (found %q): BIMI requires an enforcing policy of quarantine or reject.",
			p.Domain, tag, p.Policy))
	}

	// Section 7.1 item 9: a quarantine policy only qualifies when it applies
	// to the whole mail stream. The tag being absent is not the same as
	// pct=100, which is why Percentage is a pointer.
	if policy == DMARCPolicyQuarantine && p.Percentage != nil && *p.Percentage != 100 {
		errs = append(errs, fmt.Sprintf("The quarantine policy defines pct=%d: BIMI requires pct=100 under a quarantine policy, so no Indicator will be displayed. Remove the pct= tag, which DMARCbis drops, or set it to 100.",
			*p.Percentage))
	}

	// Not one of the conditions section 7.1 enumerates, but a policy the
	// Domain Owner asks receivers not to apply cannot be a policy at
	// enforcement.
	if p.TestMode {
		errs = append(errs, fmt.Sprintf("The DMARC record at %s publishes t=y: it asks receivers to treat the policy as a test and not to apply it, so the policy is not at enforcement and no Indicator will be displayed. Remove the t= tag once the policy is meant to apply.",
			p.Domain))
	}

	// The record governs this domain through p=, so its sp= only reaches
	// the domains below. They are not what was analysed here, but they will
	// silently display nothing.
	if !p.inherited(authorDomain) && strings.EqualFold(p.SubdomainPolicy, DMARCPolicyNone) {
		warnings = append(warnings, fmt.Sprintf("The record also publishes sp=none, which turns BIMI off for every subdomain of %s: mail sent from a subdomain will display no Indicator, even one publishing a BIMI record of its own.",
			p.Domain))
	}

	// Section 7.1 item 9 only names quarantine, so a partial reject policy
	// is not a failure, but a receiver applying it to part of the stream
	// only is not obviously going to display an Indicator for the rest.
	if policy == DMARCPolicyReject && p.Percentage != nil && *p.Percentage != 100 {
		warnings = append(warnings, fmt.Sprintf("The reject policy defines pct=%d, a tag DMARCbis removes: BIMI only requires pct=100 under a quarantine policy, but receivers applying the policy to part of the mail stream may not display the Indicator for the rest.",
			*p.Percentage))
	}

	if len(errs) == 0 && (policy == DMARCPolicyQuarantine || policy == DMARCPolicyReject) {
		infos = append(infos, fmt.Sprintf("The %s%s policy published at %s governs %s, which satisfies the BIMI enforcement requirement",
			tag, policy, p.Domain, authorDomain))
	}

	return newCheckWithSeverities(name, description, statusFor(errs, warnings), errs, warnings, infos)
}
