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
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// What each verdict weighs in the authentication score, as
// CalculateAuthenticationScore counts it.
const (
	authWeightSPF          = 30
	authWeightDKIM         = 30
	authWeightDMARC        = 30
	authWeightBIMI         = 10
	authWeightSPFHelo      = 5
	authWeightIPRev        = 7
	authWeightXGoogleDKIM  = 12
	authWeightXAlignedFrom = 5
	authWeightXTLS         = 10
)

// chargedIssues charges what the scoring of a verdict took off, out of the
// check's own 100 points, to the first of its issues, the others costing
// nothing, and weighs it into points of the section score.
func chargedIssues(lost, weight int, issues ...model.Issue) *[]model.Issue {
	charged := make([]model.Issue, len(issues))
	for i, issue := range issues {
		penalty := 0
		if i == 0 {
			penalty = lost
		}
		issue.Penalty = &penalty
		charged[i] = issue
	}
	return weighIssues(charged, weight, 100)
}

// ReportIssues sets what each authentication verdict calls for changing,
// charged what its scoring takes off the authentication score: the issue
// says why a verdict costs what it costs. dns is what the records of the
// sender say, which tell why a verdict came out the way it did; source tells
// whose verdicts they are.
func (a *AuthenticationAnalyzer) ReportIssues(results *model.AuthenticationResults, dns *model.DNSResults, source model.ReportSource) {
	if results == nil {
		return
	}
	uploaded := source == model.ReportSourceUploaded
	issues := &model.AuthenticationIssues{}
	results.Issues = issues

	// No verdict at all: not the sender's doing either way, but the reader
	// has to know why the grade says nothing, and what to do to get one.
	if !a.hasRequiredResults(results) {
		issue := newIssue(model.IssueTypeAuthUnavailable, model.IssueSeverityInfo, "",
			"No Authentication-Results header from this instance was found, which is a server-side configuration issue, not a problem with your email.",
			"Contact the administrator of this instance.")
		if uploaded {
			issue = newIssue(model.IssueTypeAuthUnavailable, model.IssueSeverityMedium, "",
				"The uploaded file carries no Authentication-Results header, so nothing says whether the message was authenticated.",
				"Send the message to a test address instead of uploading it, so the checks run on delivery.")
		}
		issues.Details = chargedIssues(0, 0, issue)
		return
	}

	if dns == nil {
		dns = &model.DNSResults{}
	}

	issues.Spf = chargedIssues(100-a.calculateSPFScore(results), authWeightSPF, spfVerdictIssues(results, dns, uploaded)...)
	issues.Dkim = chargedIssues(100-a.calculateDKIMScore(results), authWeightDKIM, dkimVerdictIssues(results, dns, uploaded)...)
	issues.Dmarc = chargedIssues(100-a.calculateDMARCScore(results), authWeightDMARC, dmarcVerdictIssues(results, dns, uploaded)...)
	issues.Bimi = chargedIssues(100-a.calculateBIMIScore(results), authWeightBIMI, bimiVerdictIssues(results, dns)...)

	// The verdicts that only take points off
	if results.SpfHelo != nil {
		issues.SpfHelo = chargedIssues(-a.calculateSPFHeloScore(results), authWeightSPFHelo, spfHeloVerdictIssues(results.SpfHelo)...)
	}
	if results.Iprev != nil {
		issues.Iprev = chargedIssues(100-a.calculateIPRevScore(results), authWeightIPRev, iprevVerdictIssues(results.Iprev, dns)...)
	}
	if results.XGoogleDkim != nil {
		issues.XGoogleDkim = chargedIssues(-a.calculateXGoogleDKIMScore(results), authWeightXGoogleDKIM, xGoogleDKIMVerdictIssues(results.XGoogleDkim)...)
	}
	if results.XAlignedFrom != nil {
		issues.XAlignedFrom = chargedIssues(-a.calculateXAlignedFromScore(results), authWeightXAlignedFrom, xAlignedFromVerdictIssues(results.XAlignedFrom)...)
	}
	if results.XTls != nil {
		issues.XTls = chargedIssues(-a.calculateXTLSScore(results), authWeightXTLS, xTLSVerdictIssues(results.XTls)...)
	}

	// ARC only matters for forwarded mail, and is never scored
	if results.Arc != nil {
		var arc []model.Issue
		if results.Arc.Result == model.ARCResultResultFail {
			arc = append(arc, newIssue(model.IssueTypeArcFail, model.IssueSeverityLow, "",
				"An intermediary sealed the message with ARC, but the chain is broken.",
				"If the message went through a mailing list or forwarder you operate, check its ARC signing configuration."))
		}
		issues.Arc = chargedIssues(0, 0, arc...)
	}
}

// unevaluatedIssue says that the receiver reported no verdict for a
// mechanism the score requires, which counts as missing.
func unevaluatedIssue(mechanism string, uploaded bool) model.Issue {
	if uploaded {
		return newIssue(model.IssueTypeAuthUnevaluated, model.IssueSeverityMedium, mechanism,
			fmt.Sprintf("The server that received the uploaded message recorded no %s verdict, so it counts as missing in the grade even if your setup is correct.", mechanism),
			"Send the message to a test address instead of uploading it to have every mechanism checked.")
	}
	return newIssue(model.IssueTypeAuthUnevaluated, model.IssueSeverityInfo, mechanism,
		fmt.Sprintf("This instance reported no %s verdict for the message, which is a server-side configuration issue, not a problem with your email.", mechanism),
		"Contact the administrator of this instance.")
}

// envelopeDomain is the domain SPF was checked for.
func envelopeDomain(spf *model.AuthResult, dns *model.DNSResults) string {
	if spf != nil && spf.Domain != nil && *spf.Domain != "" {
		return *spf.Domain
	}
	if dns.RpDomain != nil && *dns.RpDomain != "" {
		return *dns.RpDomain
	}
	if dns.FromDomain != "" {
		return dns.FromDomain
	}
	return "the envelope sender domain"
}

func spfVerdictIssues(results *model.AuthenticationResults, dns *model.DNSResults, uploaded bool) []model.Issue {
	spf := results.Spf
	if spf == nil {
		if results.SpfHelo != nil {
			return []model.Issue{newIssue(model.IssueTypeAuthUnevaluated, model.IssueSeverityInfo, "SPF",
				"The receiver only checked the HELO identity, so it reported no verdict for the envelope sender.", "")}
		}
		return []model.Issue{unevaluatedIssue("SPF", uploaded)}
	}

	domain := envelopeDomain(spf, dns)
	server := "the server that sent this message"
	if dns.SenderIp != nil && *dns.SenderIp != "" {
		server = fmt.Sprintf("%s (%s)", server, *dns.SenderIp)
	}
	authorise := fmt.Sprintf("Add %s, or the include: mechanism your email provider documents, to the SPF record of %s.", server, domain)

	switch spf.Result {
	case model.AuthResultResultPass:
		return nil
	case model.AuthResultResultFail:
		return []model.Issue{newIssue(model.IssueTypeSpfFail, model.IssueSeverityCritical, domain,
			fmt.Sprintf("The SPF record of %s does not authorize the server that sent this message, and asks receivers to reject it.", domain), authorise)}
	case model.AuthResultResultSoftfail:
		return []model.Issue{newIssue(model.IssueTypeSpfSoftfail, model.IssueSeverityHigh, domain,
			fmt.Sprintf("The SPF record of %s does not authorize the server that sent this message.", domain), authorise)}
	case model.AuthResultResultNeutral:
		return []model.Issue{newIssue(model.IssueTypeSpfNeutral, model.IssueSeverityMedium, domain,
			fmt.Sprintf("The SPF record of %s neither authorizes nor rejects the server that sent this message.", domain), authorise)}
	case model.AuthResultResultPermerror:
		return []model.Issue{newIssue(model.IssueTypeSpfPermerror, model.IssueSeverityHigh, domain,
			"Receivers hit a permanent error evaluating the SPF record: a syntax error, or more than 10 DNS lookups once every include: is followed.",
			"Fix the syntax of the record and keep the total number of include:, a, mx, ptr, exists and redirect= lookups under 10.")}
	case model.AuthResultResultTemperror:
		return []model.Issue{newIssue(model.IssueTypeSpfTemperror, model.IssueSeverityMedium, domain,
			"A DNS error prevented the receiver from fetching the SPF record.",
			"Check that the DNS servers of your domain answer reliably, then send another test.")}
	case model.AuthResultResultNone:
		return []model.Issue{newIssue(model.IssueTypeSpfMissing, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s publishes no SPF record, so receivers cannot tell which servers may send its mail.", domain),
			fmt.Sprintf(`Publish a TXT record on %s listing your sending servers, ending with -all: for instance "v=spf1 include:<your provider> -all".`, domain))}
	default:
		return []model.Issue{newIssue(model.IssueTypeSpfFail, model.IssueSeverityHigh, domain,
			fmt.Sprintf("The receiver reported %s for the SPF record of %s.", spf.Result, domain), authorise)}
	}
}

func dkimVerdictIssues(results *model.AuthenticationResults, dns *model.DNSResults, uploaded bool) []model.Issue {
	if results.Dkim == nil || len(*results.Dkim) == 0 {
		return []model.Issue{unevaluatedIssue("DKIM", uploaded)}
	}

	// One passing signature is all DMARC needs, so a failing one next to it
	// is a leftover to clean up rather than a problem.
	var passing bool
	var failing, others []model.AuthResult
	for _, dkim := range *results.Dkim {
		switch dkim.Result {
		case model.AuthResultResultPass:
			passing = true
		case model.AuthResultResultNone:
			others = append(others, dkim)
		default:
			failing = append(failing, dkim)
			others = append(others, dkim)
		}
	}

	signer := func(dkim model.AuthResult) string {
		domain := utils.Deref(dkim.Domain)
		if domain == "" {
			return "an unnamed domain"
		}
		if dkim.Selector != nil && *dkim.Selector != "" {
			return fmt.Sprintf("%s (selector %s)", domain, *dkim.Selector)
		}
		return domain
	}

	switch {
	case passing && len(others) == 0:
		return nil
	case passing:
		var names []string
		for _, dkim := range others {
			names = append(names, fmt.Sprintf("%s (%s)", signer(dkim), dkim.Result))
		}
		return []model.Issue{newIssue(model.IssueTypeDkimExtraFail, model.IssueSeverityLow, utils.Deref(others[0].Domain),
			fmt.Sprintf("Another signature passes, so the message is authenticated, but the one of %s does not verify.", strings.Join(names, ", ")),
			"Fix or remove the failing signature: some filters count every broken signature against the message.")}
	case len(failing) == 0:
		return []model.Issue{newIssue(model.IssueTypeDkimMissing, model.IssueSeverityHigh, dns.FromDomain,
			"Without a DKIM signature, DMARC can only rely on SPF, which does not survive forwarding.",
			"Enable DKIM signing on your mail server or email provider, and publish the public key it gives you in DNS.")}
	}

	allTemporary := true
	for _, dkim := range failing {
		allTemporary = allTemporary && dkim.Result == model.AuthResultResultTemperror
	}
	if allTemporary {
		return []model.Issue{newIssue(model.IssueTypeDkimTemperror, model.IssueSeverityMedium, utils.Deref(failing[0].Domain),
			"A DNS error prevented the receiver from fetching the public key.",
			"Check that the DNS servers of the signing domain answer reliably, then send another test.")}
	}

	failed := failing[0]
	for _, dkim := range failing {
		if dkim.Domain != nil {
			failed = dkim
			break
		}
	}
	return []model.Issue{newIssue(model.IssueTypeDkimFail, model.IssueSeverityCritical, utils.Deref(failed.Domain),
		fmt.Sprintf("The signature of %s does not match the message or the published key.", signer(failed)),
		"Check that the public key published in DNS matches the private key your server signs with, and that nothing rewrites the message after it was signed (footer, link tracking, line wrapping).")}
}

func dmarcVerdictIssues(results *model.AuthenticationResults, dns *model.DNSResults, uploaded bool) []model.Issue {
	dmarc := results.Dmarc
	if dmarc == nil {
		return []model.Issue{unevaluatedIssue("DMARC", uploaded)}
	}
	domain := dns.FromDomain
	if domain == "" {
		domain = utils.Deref(dmarc.Domain)
	}

	switch dmarc.Result {
	case model.AuthResultResultPass:
		return nil
	case model.AuthResultResultNone:
		return []model.Issue{newIssue(model.IssueTypeDmarcMissing, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s publishes no DMARC policy. Gmail and Yahoo require one from bulk senders.", domain),
			fmt.Sprintf(`Publish a TXT record at _dmarc.%s, starting with "v=DMARC1; p=none; rua=mailto:<address>" to collect reports, then move to p=quarantine and p=reject once all your mail passes.`, domain))}
	case model.AuthResultResultPermerror:
		return []model.Issue{newIssue(model.IssueTypeDmarcPermerror, model.IssueSeverityHigh, domain,
			"The receiver reported a permanent error reading the DMARC record.",
			"Check the syntax of the TXT record at _dmarc of your domain.")}
	case model.AuthResultResultTemperror:
		return []model.Issue{newIssue(model.IssueTypeDmarcTemperror, model.IssueSeverityMedium, domain,
			"The receiver reported a temporary error reading the DMARC record.",
			"Check that the DNS servers of your domain answer reliably, then send another test.")}
	default:
		within := ""
		if domain != "" {
			within = fmt.Sprintf(" (%s)", domain)
		}
		return []model.Issue{newIssue(model.IssueTypeDmarcFail, model.IssueSeverityCritical, domain,
			fmt.Sprintf("Neither SPF nor DKIM passed for a domain aligned with the From domain%s. Receivers apply the domain's DMARC policy to this message.", within),
			"Sign with a DKIM key of the From domain (or one of its subdomains), or send with a Return-Path on that domain authorized by its SPF record.")}
	}
}

// bimiVerdictIssues says why the BIMI verdict cost points: before DMARC is
// enforced, that is the step; after it, what the record calls for, or the
// record to publish.
func bimiVerdictIssues(results *model.AuthenticationResults, dns *model.DNSResults) []model.Issue {
	result := model.AuthResultResultNone
	if results.Bimi != nil {
		result = results.Bimi.Result
	}
	record := dns.BimiRecord
	location := bimiLocation(record, dns.FromDomain)

	switch {
	case result == model.AuthResultResultPass:
		return nil
	case !dmarcEnforced(dns.DmarcRecord):
		return []model.Issue{newIssue(model.IssueTypeBimiDmarcNotEnforced, model.IssueSeverityLow, location,
			"Receivers only display a brand logo for a domain whose DMARC policy is at enforcement. The authentication score counts BIMI.",
			"Move the DMARC policy to p=quarantine or p=reject first; publish a BIMI record once it is.")}
	case result == model.AuthResultResultDeclined:
		return []model.Issue{newIssue(model.IssueTypeBimiDeclined, model.IssueSeverityInfo, location,
			"Your domain declines BIMI, which earns most of its points; a logo would earn the rest.",
			"Publish a BIMI record pointing to your logo in SVG Tiny PS format if you want it displayed.")}
	case record != nil && record.Record != nil && record.Valid:
		return []model.Issue{newIssue(model.IssueTypeBimiNotHonored, model.IssueSeverityLow, location,
			fmt.Sprintf(`Your BIMI record validates here, but the server that checked this message reported "%s" for it. The authentication score counts BIMI.`, result),
			"Most mailbox providers only show a logo backed by a mark certificate (VMC or CMC), and from senders with an established reputation: check the certificate in the BIMI details.")}
	case record != nil && record.Record != nil:
		if issues := bimiRecordIssues(record, dns.FromDomain); len(issues) > 0 {
			return issues
		}
		return []model.Issue{newIssue(model.IssueTypeBimiNotHonored, model.IssueSeverityLow, location,
			fmt.Sprintf(`The server that checked this message reported "%s" for your BIMI record. The authentication score counts BIMI.`, result),
			"Check the BIMI details with the DNS records.")}
	default:
		return []model.Issue{bimiMissingIssue(record, dns.FromDomain)}
	}
}

func spfHeloVerdictIssues(helo *model.AuthResult) []model.Issue {
	if helo.Result != model.AuthResultResultFail && helo.Result != model.AuthResultResultSoftfail {
		return nil
	}
	host := utils.Deref(helo.Domain)
	announced := ""
	if host != "" {
		announced = fmt.Sprintf(" (%s)", host)
	}
	return []model.Issue{newIssue(model.IssueTypeSpfHeloFail, model.IssueSeverityLow, host,
		fmt.Sprintf("The hostname the server announced%s publishes an SPF policy that does not authorize the sending IP.", announced),
		`Fix the SPF record of that hostname, typically "v=spf1 a -all" so it authorizes its own address.`)}
}

func iprevVerdictIssues(iprev *model.IPRevResult, dns *model.DNSResults) []model.Issue {
	ip := utils.Deref(iprev.Ip)
	if ip == "" {
		ip = utils.Deref(dns.SenderIp)
	}
	what := ip
	if what == "" {
		what = "The sending IP"
	}

	switch iprev.Result {
	case model.IPRevResultResultPass:
		return nil
	case model.IPRevResultResultFail:
		return []model.Issue{newIssue(model.IssueTypeIprevFail, model.IssueSeverityHigh, ip,
			fmt.Sprintf("%s has no PTR record pointing to a hostname that resolves back to it. Many receivers reject such mail outright.", what),
			"Ask whoever owns the IP address (your hosting provider or ISP) to set its PTR record to your mail server's hostname, and make sure that hostname resolves back to the same IP.")}
	default:
		return []model.Issue{newIssue(model.IssueTypeIprevError, model.IssueSeverityMedium, ip,
			fmt.Sprintf("The receiver could not check the reverse DNS of %s (%s).", what, iprev.Result),
			"Check that the reverse DNS of the sending IP answers reliably, then send another test.")}
	}
}

func xGoogleDKIMVerdictIssues(google *model.AuthResult) []model.Issue {
	switch google.Result {
	case model.AuthResultResultFail:
		return []model.Issue{newIssue(model.IssueTypeXGoogleDkimFail, model.IssueSeverityMedium, utils.Deref(google.Domain),
			"The message went through Gmail's infrastructure and was modified after Google signed it.",
			"Check for software that rewrites messages after they leave Gmail or Google Workspace.")}
	case model.AuthResultResultPermerror:
		return []model.Issue{newIssue(model.IssueTypeXGoogleDkimFail, model.IssueSeverityMedium, utils.Deref(google.Domain),
			"The message went through Gmail's infrastructure, and Google's internal signature cannot be evaluated: it is malformed, or was mangled after Google signed it.",
			"Check for software that rewrites headers after messages leave Gmail or Google Workspace.")}
	}
	return nil
}

func xAlignedFromVerdictIssues(aligned *model.AuthResult) []model.Issue {
	if aligned.Result != model.AuthResultResultFail {
		return nil
	}
	return []model.Issue{newIssue(model.IssueTypeXAlignedFromFail, model.IssueSeverityLow, utils.Deref(aligned.Domain),
		"The receiver found the envelope sender and the From address in different domains.",
		"Send with a Return-Path on the From domain or one of its subdomains.")}
}

func xTLSVerdictIssues(tls *model.AuthResult) []model.Issue {
	if tls.Result == model.AuthResultResultPass {
		return nil
	}
	return []model.Issue{newIssue(model.IssueTypeTlsMissing, model.IssueSeverityMedium, "",
		"The server that delivered this message did not encrypt the connection.",
		"Enable STARTTLS on your outbound mail server. Gmail and Yahoo require it from bulk senders.")}
}
