// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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
	"fmt"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

// DefaultBIMIAssetsTimeout caps the wall time the logo and VMC downloads may
// together add to a report. Each fetch keeps its own budget
// (bimi.DefaultFetchTimeout), but the report is generated synchronously on the
// delivery path: without an overall ceiling, two dead URLs published in a
// single TXT record stall a delivery for the sum of the per-fetch timeouts.
const DefaultBIMIAssetsTimeout = 45 * time.Second

func (d *DNSAnalyzer) bimiAssetsTimeout() time.Duration {
	if d.BIMIAssetsTimeout > 0 {
		return d.BIMIAssetsTimeout
	}
	return DefaultBIMIAssetsTimeout
}

// checkBIMIRecord looks up and validates the BIMI record for a domain and
// selector. The actual validation lives in the reusable pkg/bimi package;
// this method adapts its result to the API model.
//
// localPart is the local-part of the sending address, empty when the analysis
// has no message to take one from. A record publishing an lps= tag serves a
// different Indicator per mailbox, so without it the record reported is the
// one the selector alone leads to, which is not necessarily the one a receiver
// would act on for a given sender.
//
// dmarc is this domain's DMARC record, already analysed: BIMI section 7.1 makes
// an enforcing DMARC policy a precondition of Indicator display, so a compliant
// record under p=none is still a record no receiver will act on.
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector, localPart string, dmarc *model.DMARCRecord) *model.BIMIRecord {
	validator := &bimi.Validator{
		HTTPClient: d.bimiHTTPClient,
		Resolver:   d.resolver,
		// Discovery falls back to the organizational domain, and the VMC
		// is allowed to name it rather than the exact sender: both must
		// agree with the notion DMARC alignment uses elsewhere in the
		// report, including for the names the PSL cannot resolve.
		OrganizationalDomain: domainname.Organizational,
		VMCRoots:             d.VMCRoots,
	}

	// Bound Assertion Record discovery by d.Timeout, however many queries it
	// takes (a domain with no record of its own also queries its
	// organizational domain), and the asset downloads by their own, larger
	// budget: pulling a file from a slow host is not the same wait as a TXT
	// query, and sharing a single deadline would fail a slow-but-valid VMC
	// once the logo download consumed most of it.
	lookupCtx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	rec, err := validator.LookupForLocalPart(lookupCtx, domain, selector, localPart)
	if err != nil {
		msg := "No BIMI record found"
		if !errors.Is(err, bimi.ErrNoRecord) {
			msg = fmt.Sprintf("Failed to lookup BIMI record: %s", formatDNSError(err))
		}
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo(msg),
		}
	}

	if rec.Valid {
		assetsCtx, cancelAssets := context.WithTimeout(context.Background(), d.bimiAssetsTimeout())
		defer cancelAssets()
		validator.ValidateAssets(assetsCtx, rec, bimiDMARCPolicy(dmarc))
	}

	return bimiRecordToModel(rec)
}

// bimiDMARCPolicy converts the analysed DMARC record into the policy input
// pkg/bimi needs for BIMI section 7.1. A nil record means DMARC was not
// analysed at all, which leaves the check skipped rather than failed; a record
// that did not validate is not a policy, since it cannot make a message pass
// DMARC, so Found stays false.
func bimiDMARCPolicy(rec *model.DMARCRecord) *bimi.DMARCPolicy {
	if rec == nil {
		return nil
	}

	return &bimi.DMARCPolicy{
		Found:           rec.Valid,
		Domain:          utils.Deref(rec.Domain),
		Policy:          string(utils.Deref(rec.Policy)),
		SubdomainPolicy: string(utils.Deref(rec.SubdomainPolicy)),
		Percentage:      utils.ClonePtr(rec.Percentage),
		TestMode:        utils.Deref(rec.TestMode),
	}
}

// bimiRecordToModel converts a *bimi.Record into the API *model.BIMIRecord.
func bimiRecordToModel(r *bimi.Record) *model.BIMIRecord {
	m := &model.BIMIRecord{
		Selector:    r.Selector,
		Domain:      r.Domain,
		RecordValid: utils.PtrTo(r.RecordValid),
		Valid:       r.Valid,
		LogoUrl:     utils.PtrTo(r.LogoURL),
		VmcUrl:      utils.PtrTo(r.VMCURL),
	}
	m.RecordDomain = utils.PtrToNonZero(r.RecordDomain)
	m.RequestedSelector = utils.PtrToNonZero(r.RequestedSelector)
	m.AvatarPreference = utils.PtrToNonZero(r.AvatarPreference)
	m.Record = utils.PtrToNonZero(r.Record)
	m.Error = utils.PtrToNonZero(r.Error)

	if r.LocalPartSelector {
		m.LocalPartSelector = utils.PtrTo(true)
		// An lps= tag published without a prefix matches every
		// local-part, so the empty list is meaningful: send it rather
		// than omitting the field, which would read as no list at all.
		prefixes := r.LocalPartPrefixes
		if prefixes == nil {
			prefixes = []string{}
		}
		m.LocalPartPrefixes = &prefixes
	}
	if len(r.Checks) > 0 {
		m.Checks = utils.PtrTo(bimiChecksToModel(r.Checks))
	}
	if r.VMC != nil {
		m.Vmc = bimiVMCToModel(r.VMC)
	}
	return m
}

func bimiChecksToModel(checks []bimi.Check) []model.BIMICheck {
	out := make([]model.BIMICheck, len(checks))
	for i, c := range checks {
		out[i] = model.BIMICheck{
			Name:        c.Name,
			Description: c.Description,
			Status:      model.BIMICheckStatus(c.Status),
		}
		if len(c.Messages) > 0 {
			messages := make([]model.BIMICheckMessage, len(c.Messages))
			for j, m := range c.Messages {
				messages[j] = model.BIMICheckMessage{
					Text:     m.Text,
					Severity: model.BIMICheckMessageSeverity(m.Severity),
				}
			}
			out[i].Messages = &messages
		}
	}
	return out
}

func bimiVMCToModel(v *bimi.VMCInfo) *model.VMCInfo {
	m := &model.VMCInfo{
		Valid:                    v.Valid,
		HasBimiEku:               v.HasBimiEku,
		IssuerHasBimiEku:         v.IssuerHasBimiEku,
		HasLogotype:              v.HasLogotype,
		LogoHashVerified:         v.LogoHashVerified,
		HasCrlDistributionPoints: v.HasCRLDistributionPoints,
		SctCount:                 v.SCTCount,
		ChainTrusted:             v.ChainTrusted,
		LogoMatches:              v.LogoMatches,
	}
	m.Issuer = utils.PtrToNonZero(v.Issuer)
	m.Subject = utils.PtrToNonZero(v.Subject)
	m.SerialNumber = utils.PtrToNonZero(v.SerialNumber)
	m.LogoHashAlgorithm = utils.PtrToNonZero(v.LogoHashAlgorithm)
	m.LogoMediaType = utils.PtrToNonZero(v.LogoMediaType)
	m.ChainLength = utils.PtrToNonZero(v.ChainLength)
	m.Error = utils.PtrToNonZero(v.Error)

	if !v.NotBefore.IsZero() {
		m.NotBefore = utils.PtrTo(v.NotBefore)
	}
	if !v.NotAfter.IsZero() {
		m.NotAfter = utils.PtrTo(v.NotAfter)
	}
	if len(v.SanDomains) > 0 {
		m.SanDomains = utils.PtrTo(v.SanDomains)
	}
	return m
}

// bimiCheckFixes is what to change for each BIMI check that fails, by the
// check's name.
var bimiCheckFixes = map[string]string{
	"record_tags":      "fix the tags of the record",
	"logo_fetch":       "serve the logo over HTTPS at the l= URL, as image/svg+xml",
	"logo_xml":         "make the logo a well-formed SVG file",
	"logo_svg_tiny_ps": "convert the logo to the SVG Tiny Portable/Secure profile",
	"vmc":              "check the mark certificate published at the a= URL",
}

// dmarcEnforced tells whether a DMARC record is at enforcement, which BIMI
// requires before anything else.
func dmarcEnforced(dmarc *model.DMARCRecord) bool {
	return dmarc != nil && dmarc.Valid && dmarc.Policy != nil &&
		(*dmarc.Policy == "quarantine" || *dmarc.Policy == "reject")
}

// bimiLocation is the name a BIMI record is published under.
func bimiLocation(record *model.BIMIRecord, domain string) string {
	selector := "default"
	if record != nil {
		if record.Selector != "" {
			selector = record.Selector
		}
		if record.Domain != "" {
			domain = record.Domain
		}
	}
	return fmt.Sprintf("%s._bimi.%s", selector, domain)
}

// bimiCheckMessages is what a check of the record says at the given severity.
func bimiCheckMessages(check model.BIMICheck, severity model.BIMICheckMessageSeverity) (texts []string) {
	if check.Messages != nil {
		for _, m := range *check.Messages {
			if m.Severity == severity {
				texts = append(texts, m.Text)
			}
		}
	}
	return
}

// bimiIssues is what the BIMI record of the From domain calls for, read off
// the checks run on it. BIMI is optional, so all of it costs nothing here: a
// published record says what keeps it from being displayed, and a domain
// without one is offered it once its DMARC policy is enforced, which BIMI
// requires.
func bimiIssues(record *model.BIMIRecord, dmarc *model.DMARCRecord, domain string) []model.Issue {
	if record == nil {
		return nil
	}
	c := checkScore{score: 100}
	if record.Record != nil {
		for _, issue := range bimiRecordIssues(record, domain) {
			c.note(issue)
		}
	} else if dmarcEnforced(dmarc) {
		c.note(bimiMissingIssue(record, domain))
	}
	if c.issues == nil {
		return []model.Issue{}
	}
	return c.issues
}

// bimiMissingIssue offers BIMI to a domain whose DMARC policy is enforced.
func bimiMissingIssue(record *model.BIMIRecord, domain string) model.Issue {
	if record != nil && record.Domain != "" {
		domain = record.Domain
	}
	return newIssue(model.IssueTypeBimiMissing, model.IssueSeverityLow, bimiLocation(record, domain),
		"Your DMARC policy is enforced, which is what BIMI requires: supporting mailboxes could display your brand logo next to your messages. The authentication score counts BIMI.",
		fmt.Sprintf(`Publish a BIMI record at %s pointing to your logo in SVG Tiny PS format. If you do not want a logo, publish "v=BIMI1; l=; a=" instead to decline explicitly: it also keeps mail clients from falling back to a parent domain's record, and earns most of the points.`, bimiLocation(record, domain)))
}

// bimiRecordIssues is what a published BIMI record calls for, each issue
// uncharged: what keeps it from being displayed, the record that cannot be
// read, the checks that fail, and those that pass with a reservation.
func bimiRecordIssues(record *model.BIMIRecord, domain string) (issues []model.Issue) {
	if record == nil || record.Record == nil {
		return nil
	}
	location := bimiLocation(record, domain)
	var checks []model.BIMICheck
	if record.Checks != nil {
		checks = *record.Checks
	}

	for _, check := range checks {
		if check.Name == "dmarc_enforcement" && check.Status == model.BIMICheckStatusFail {
			message := strings.TrimSpace("Receivers only consider BIMI once the DMARC policy is at enforcement, however compliant the record and the logo are. " + strings.Join(bimiCheckMessages(check, model.BIMICheckMessageSeverityError), " "))
			issues = append(issues, newIssue(model.IssueTypeBimiDmarcNotEnforced, model.IssueSeverityLow, location, message,
				"Move the DMARC policy to p=quarantine or p=reject, with no pct= below 100 and no t=y."))
		}
	}

	if record.RecordValid != nil && !*record.RecordValid {
		message := "Receivers cannot parse the BIMI record and ignore it."
		if record.Error != nil {
			message = *record.Error
		}
		return append(issues, newIssue(model.IssueTypeBimiInvalid, model.IssueSeverityLow, location, message,
			`Fix the syntax of the record: "v=BIMI1; l=<logo URL>; a=<certificate URL>".`))
	}

	var failed, fixes []string
	for _, check := range checks {
		if check.Status != model.BIMICheckStatusFail || check.Name == "dmarc_enforcement" {
			continue
		}
		what := check.Description
		if what == "" {
			what = check.Name
		}
		failed = append(failed, strings.Join(append([]string{what}, bimiCheckMessages(check, model.BIMICheckMessageSeverityError)...), ": "))
		if fix, ok := bimiCheckFixes[check.Name]; ok {
			fixes = append(fixes, fix)
		}
	}
	if len(failed) > 0 || !record.Valid {
		message := strings.Join(failed, " ")
		if message == "" && record.Error != nil {
			message = *record.Error
		}
		if message == "" {
			message = "The BIMI record or its assets did not validate."
		}
		advice := "Check the detailed BIMI checks below."
		if len(fixes) > 0 {
			advice = strings.Join(fixes, "; ") + "."
			advice = strings.ToUpper(advice[:1]) + advice[1:]
		}
		issues = append(issues, newIssue(model.IssueTypeBimiUnverified, model.IssueSeverityLow, location, message, advice))
	}

	for _, check := range checks {
		if check.Status != model.BIMICheckStatusWarning {
			continue
		}
		message := strings.Join(bimiCheckMessages(check, model.BIMICheckMessageSeverityWarning), " ")
		// A certificate that was fetched and parsed is not a missing one:
		// whatever the warning says (a Content-Type, an expiry close by),
		// it is a reservation about that certificate, reported as such.
		if check.Name == "vmc" && record.Vmc == nil && record.VmcUrl == nil {
			if message == "" {
				message = "No mark certificate vouches for the logo, and most mailbox providers only display one that has it."
			}
			issues = append(issues, newIssue(model.IssueTypeBimiVmcMissing, model.IssueSeverityLow, location, message,
				"Obtain a Verified or Common Mark Certificate for the logo and publish its URL in a=."))
			continue
		}
		what := check.Description
		if what == "" {
			what = check.Name
		}
		if message == "" {
			message = fmt.Sprintf("%s has a reservation.", what)
		} else {
			message = fmt.Sprintf("%s: %s", what, message)
		}
		issues = append(issues, newIssue(model.IssueTypeBimiCheckWarning, model.IssueSeverityLow, check.Name, message, ""))
	}

	return issues
}
