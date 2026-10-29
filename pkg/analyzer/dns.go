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
	"crypto/x509"
	"net/http"
	"slices"
	"sync"
	"time"

	"git.happydns.org/happyDomain/pkg/domaininfo/types"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"

	"git.happydns.org/happyDeliver/pkg/grade"
	"git.happydns.org/happyDeliver/pkg/ipinfo"
	"git.happydns.org/happyDeliver/pkg/ipinfo/cymru"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// DNSAnalyzer analyzes DNS records for email domains
type DNSAnalyzer struct {
	Timeout  time.Duration
	resolver DNSResolver
	// ipOrigin says where the sending address comes from. Nil leaves the
	// question unasked.
	ipOrigin ipinfo.Source
	// domainInfo reads what the registry publishes about a sender domain.
	// Nil leaves registrations unread.
	domainInfo types.Getter
	// domainInfoTimeout bounds one registration lookup.
	domainInfoTimeout time.Duration
	// bimiHTTPClient fetches BIMI logo/VMC assets. The only files
	// DNSAnalyzer downloads are published by the domain under analysis, so
	// they go through the guarded client of pkg/bimi rather than a bare
	// one, with its own timeout: the DNS budget is no measure of a file
	// download.
	bimiHTTPClient *http.Client
	// BIMIAssetsTimeout caps the total time the BIMI asset downloads may add to
	// an analysis. Zero means DefaultBIMIAssetsTimeout.
	BIMIAssetsTimeout time.Duration
	// VMCRoots is the set of trust anchors a Verified Mark Certificate chain
	// must lead to (see bimi.LoadVMCRoots). A nil pool leaves the issuer's
	// legitimacy unexamined, which the report says rather than hides.
	VMCRoots *x509.CertPool
}

// NewDNSAnalyzer creates a new DNS analyzer with configurable timeout
func NewDNSAnalyzer(timeout time.Duration, vmcRoots *x509.CertPool) *DNSAnalyzer {
	return NewDNSAnalyzerWithResolver(timeout, vmcRoots, NewStandardDNSResolver())
}

// NewDNSAnalyzerWithResolver creates a new DNS analyzer with a custom resolver.
// If resolver is nil, a StandardDNSResolver will be used.
func NewDNSAnalyzerWithResolver(timeout time.Duration, vmcRoots *x509.CertPool, resolver DNSResolver) *DNSAnalyzer {
	if timeout == 0 {
		timeout = 10 * time.Second // Default timeout
	}
	if resolver == nil {
		resolver = NewStandardDNSResolver()
	}
	d := &DNSAnalyzer{
		Timeout:           timeout,
		resolver:          resolver,
		ipOrigin:          cymru.New(resolver),
		domainInfoTimeout: domainInfoTimeout,
		bimiHTTPClient:    bimi.NewHTTPClient(0),
		VMCRoots:          vmcRoots,
	}
	if !domainInfoDisabled {
		d.domainInfo = defaultDomainInfoGetter
	}
	return d
}

// WithDomainInfo sets what the analyzer reads registrations with, and how
// long it waits for one. A nil getter leaves registrations unread. Tests
// hand over a fake; the default is happyDomain's lookup behind a cache.
func (d *DNSAnalyzer) WithDomainInfo(getter types.Getter, timeout time.Duration) *DNSAnalyzer {
	d.domainInfo = getter
	if timeout > 0 {
		d.domainInfoTimeout = timeout
	}
	return d
}

// populateInboundHopResults stores the sender IP, its PTR/forward records and
// the announced HELO name from inboundHop into results. It does not depend on
// the From domain, so it must run on every path through AnalyzeDNS.
func (d *DNSAnalyzer) populateInboundHopResults(results *model.DNSResults, inboundHop *model.ReceivedHop) {
	if inboundHop == nil || inboundHop.Ip == nil || *inboundHop.Ip == "" {
		return
	}

	senderIP := *inboundHop.Ip
	results.SenderIp = &senderIP
	ptrRecords, forwardRecords := d.checkPTRAndForward(senderIP)
	if len(ptrRecords) > 0 {
		results.PtrRecords = &ptrRecords
	}
	if len(forwardRecords) > 0 {
		results.PtrForwardRecords = &forwardRecords
	}
	results.SenderOrigin = d.checkSenderOrigin(senderIP)

	// Record the announced HELO name and whether it matches the PTR record
	if inboundHop.From != nil && *inboundHop.From != "" {
		helo := *inboundHop.From
		results.HeloHostname = &helo
		if len(ptrRecords) > 0 {
			match := checkHeloPtrMatch(helo, ptrRecords)
			results.HeloPtrMatch = &match
		}
	}
}

// AnalyzeDNS performs DNS validation for the email's domain.
//
// inboundHop, as picked by InboundHop, provides the sender IP used for
// PTR/FCrDNS verification and the announced HELO name. It may be nil.
func (d *DNSAnalyzer) AnalyzeDNS(email *mailmsg.Message, headersResults *model.HeaderAnalysis, inboundHop *model.ReceivedHop) *model.DNSResults {
	// Extract domain from From address
	if headersResults.DomainAlignment.FromDomain == nil || *headersResults.DomainAlignment.FromDomain == "" {
		results := &model.DNSResults{
			Errors: &[]string{"Unable to extract domain from email"},
		}
		// Populate it even when the rest of the analysis cannot run, so its
		// absence isn't mistaken for a report predating this feature.
		d.populateInboundHopResults(results, inboundHop)
		return results
	}
	fromDomain := *headersResults.DomainAlignment.FromDomain

	results := &model.DNSResults{
		FromDomain: fromDomain,
		RpDomain:   headersResults.DomainAlignment.ReturnPathDomain,
	}

	// Determine which domain to check SPF for (Return-Path domain)
	// SPF validates the envelope sender (Return-Path), not the From header
	spfDomain := fromDomain
	if results.RpDomain != nil {
		spfDomain = *results.RpDomain
	}

	d.populateInboundHopResults(results, inboundHop)

	// What the sender domains are, beyond their records. The Return-Path is
	// read on its own only when it is another organization's: the same
	// registrar answers for both otherwise. Then it is a second registry to
	// wait on, and neither answer depends on the other, so the two are asked
	// at once rather than one registry timeout after the other.
	fromOrgDomain := orgDomainOf(fromDomain, utils.Deref(headersResults.DomainAlignment.FromOrgDomain))
	var domainInfoWG sync.WaitGroup
	if results.RpDomain != nil && *results.RpDomain != "" {
		rpDomain := *results.RpDomain
		if rpOrgDomain := orgDomainOf(rpDomain, utils.Deref(headersResults.DomainAlignment.ReturnPathOrgDomain)); rpOrgDomain != fromOrgDomain {
			domainInfoWG.Go(func() {
				results.RpDomainInfo = d.checkDomainInfo(rpDomain, rpOrgDomain)
			})
		}
	}
	results.FromDomainInfo = d.checkDomainInfo(fromDomain, fromOrgDomain)
	domainInfoWG.Wait()

	// Check MX records for From domain (where replies would go)
	results.FromMxRecords = d.checkMXRecords(fromDomain)

	// Check MX records for Return-Path domain (where bounces would go)
	// Only check if Return-Path domain is different from From domain
	if results.RpDomain != nil && *results.RpDomain != fromDomain {
		results.RpMxRecords = d.checkMXRecords(*results.RpDomain)
	}

	// Verify the sender domains can actually receive replies/bounces (MX, with
	// A/AAAA fallback), mirroring the ReturnOK milter check.
	results.ReturnOk = &model.ReturnOK{
		From: d.checkReturnOKDomain(fromDomain, utils.Deref(headersResults.DomainAlignment.FromOrgDomain)),
	}
	if results.RpDomain != nil && *results.RpDomain != "" {
		results.ReturnOk.ReturnPath = d.checkReturnOKDomain(*results.RpDomain, utils.Deref(headersResults.DomainAlignment.ReturnPathOrgDomain))
	}

	// Check SPF records (for Return-Path domain - this is the envelope sender)
	// SPF validates the MAIL FROM command, which corresponds to Return-Path
	results.SpfRecords = d.checkSPFRecords(spfDomain)

	// Check whether the announced HELO hostname publishes a policy of its own,
	// which lets receivers authenticate the HELO identity as well. Purely
	// informational: it is a recommendation, never a failure. Skipped entirely
	// when nothing publishable was announced, as no record could be recommended.
	if results.HeloHostname != nil {
		if helo := heloLookupName(*results.HeloHostname); helo != "" {
			results.HeloSpfRecord = d.checkHeloSPFRecord(helo)
		}
	}

	// Check DKIM records by parsing DKIM-Signature headers directly
	for _, sig := range email.DKIMSignatures() {
		dkimRecord := d.checkDKIMRecord(sig)
		if dkimRecord != nil {
			if results.DkimRecords == nil {
				results.DkimRecords = new([]model.DKIMRecord)
			}
			*results.DkimRecords = append(*results.DkimRecords, *dkimRecord)
		}
	}

	// Check DMARC record (for From domain - DMARC protects the visible sender)
	// DMARC validates alignment between SPF/DKIM and the From domain
	results.DmarcRecord = d.checkDMARCRecord(fromDomain)

	// Check BIMI record (for From domain - branding is based on visible sender).
	// The local-part goes with it: a record publishing an lps= tag reserves a
	// distinct Indicator for the mailboxes it names, so discovery must know
	// which mailbox sent this message to land on the record a receiver would
	// act on.
	results.BimiRecord = d.checkBIMIRecord(fromDomain, "default", mailmsg.LocalPart(email.GetHeaderValue("From")), results.DmarcRecord)

	return results
}

// AnalyzeBIMIOnly validates the BIMI Assertion Record a domain publishes under
// the given selector, without any message to take a sender from. The DMARC
// record is looked up first and returned alongside: BIMI section 7.1 makes an
// enforcing policy a precondition of Indicator display, so the BIMI verdict
// cannot be reached without it, and the caller has to be able to show why.
//
// selector defaults to "default", the one a message carrying no BIMI-Selector
// header is served. localPart may be empty; supplying one lets discovery follow
// the lps= tag of a record that serves a different Indicator per mailbox.
func (d *DNSAnalyzer) AnalyzeBIMIOnly(domain, selector, localPart string) (*model.BIMIRecord, *model.DMARCRecord) {
	if selector == "" {
		selector = "default"
	}

	dmarc := d.checkDMARCRecord(domain)

	return d.checkBIMIRecord(domain, selector, localPart, dmarc), dmarc
}

// BIMIOnlyIssues is what the BIMI and DMARC records of domain call for
// changing, outside of any test: nothing is scored, so each issue costs points
// of its check itself.
func (d *DNSAnalyzer) BIMIOnlyIssues(domain string, bimiRecord *model.BIMIRecord, dmarc *model.DMARCRecord) *model.DNSIssues {
	_, issues := d.calculateDMARCScore(&model.DNSResults{FromDomain: domain, DmarcRecord: dmarc})
	return &model.DNSIssues{
		Dmarc: issueList(issues),
		Bimi:  optionalIssueList(bimiIssues(bimiRecord, dmarc, domain)),
	}
}

// AnalyzeDomainOnly performs DNS validation for a domain without email context
// This is useful for checking domain configuration without sending an actual email
func (d *DNSAnalyzer) AnalyzeDomainOnly(domain string) *model.DNSResults {
	results := &model.DNSResults{
		FromDomain: domain,
	}

	results.FromDomainInfo = d.checkDomainInfo(domain, "")

	// Check MX records
	results.FromMxRecords = d.checkMXRecords(domain)

	// Check SPF records
	results.SpfRecords = d.checkSPFRecords(domain)

	// Verify the domain can receive replies/bounces (MX, with A/AAAA fallback)
	results.ReturnOk = &model.ReturnOK{
		From: d.checkReturnOKDomain(domain, ""),
	}

	// Check DMARC record
	results.DmarcRecord = d.checkDMARCRecord(domain)

	// Check BIMI record with default selector. There is no message here, so
	// no sending address either: a local-part selector cannot be resolved,
	// and the record reported is the one the default selector leads to.
	results.BimiRecord = d.checkBIMIRecord(domain, "default", "", results.DmarcRecord)

	return results
}

// CalculateDomainOnlyScore calculates the DNS score for domain-only tests
// Returns a score from 0-100 where higher is better
// This version excludes PTR and DKIM checks since they require email context
func (d *DNSAnalyzer) CalculateDomainOnlyScore(results *model.DNSResults) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// MX Records: 30 points (only one domain to check)
	mxScore, mxFrom, mxRP := d.calculateMXScore(results)
	score += 30 * mxScore / 100

	// SPF Records: 30 points
	spfScore, spfIssues := d.calculateSPFScore(results)
	score += 30 * spfScore / 100

	// DMARC Record: 40 points
	dmarcScore, dmarcIssues := d.calculateDMARCScore(results)
	score += 40 * dmarcScore / 100

	results.Issues = &model.DNSIssues{
		MxFrom: weighIssues(mxFrom, 30, 100),
		Spf:    weighIssues(spfIssues, 30, 100),
		Dmarc:  weighIssues(dmarcIssues, 40, 100),
	}
	d.addSectionIssues(results, mxRP, 30, 100)
	results.Issues.Bimi = optionalIssueList(bimiIssues(results.BimiRecord, results.DmarcRecord, results.FromDomain))

	// Penalty when a sender domain cannot receive replies/bounces at all
	score += calculateReturnOKPenalty(results)

	// Penalty for what the sender domains are, whatever their records say
	score += calculateDomainInfoPenalty(results)

	// BIMI Record: only bonus
	if results.BimiRecord != nil && results.BimiRecord.Valid {
		if score >= 100 {
			return 100, "A+"
		}
	}

	// Ensure score doesn't exceed maximum
	if score > 100 {
		score = 100
	}

	// Ensure score is non-negative
	if score < 0 {
		score = 0
	}

	return score, grade.Kind(score)
}

// CalculateDNSScore calculates the DNS score from records results
// Returns a score from 0-100 where higher is better
// senderIP is the original sender IP address used for FCrDNS verification
func (d *DNSAnalyzer) CalculateDNSScore(results *model.DNSResults, senderIP string) (int, string) {
	if results == nil {
		return 0, ""
	}

	// Each check is weighted equally at 20 points. PTR/FCrDNS can only be
	// verified when a sender IP was recovered from the Received chain (e.g.
	// unavailable for uploaded EMLs): when there's no IP to check, exclude it
	// from the average instead of counting it as a 0/20 failure for
	// something that was never actually testable.
	mxScore, mxFrom, mxRP := d.calculateMXScore(results)
	spfScore, spfIssues := d.calculateSPFScore(results)
	dkimScore, dkimIssues := d.calculateDKIMScore(results)
	dmarcScore, dmarcIssues := d.calculateDMARCScore(results)

	weightedScore := 20 * mxScore
	weightedScore += 20 * spfScore
	weightedScore += 20 * dkimScore
	weightedScore += 20 * dmarcScore
	totalWeight := 80

	var ptrIssues []model.Issue
	if senderIP != "" {
		var ptrScore int
		ptrScore, ptrIssues = d.calculatePTRScore(results, senderIP)
		weightedScore += 20 * ptrScore
		totalWeight += 20
	}

	// Penalties are counted out of each check's own 100 points; the section
	// weighs every check the same.
	results.Issues = &model.DNSIssues{
		MxFrom: weighIssues(mxFrom, 20, totalWeight),
		Spf:    weighIssues(spfIssues, 20, totalWeight),
		Dkim:   weighIssues(dkimIssues, 20, totalWeight),
		Dmarc:  weighIssues(dmarcIssues, 20, totalWeight),
	}
	if results.HeloSpfRecord != nil {
		results.Issues.HeloSpf = issueList(heloSPFIssues(results))
	}
	if senderIP != "" {
		ptr := weighIssues(ptrIssues, 20, totalWeight)
		results.Issues.Ptr = issueList(issuesOfType(*ptr, model.IssueTypePtrMissing, model.IssueTypePtrMultiple))
		results.Issues.Fcrdns = issueList(issuesOfType(*ptr, model.IssueTypeFcrdnsMismatch))
		results.Issues.HeloPtr = issueList(issuesOfType(*ptr, model.IssueTypeHeloPtrMismatch))
	}
	d.addSectionIssues(results, mxRP, 20, totalWeight)
	results.Issues.Bimi = optionalIssueList(bimiIssues(results.BimiRecord, results.DmarcRecord, results.FromDomain))

	score := weightedScore / totalWeight

	// Penalty when a sender domain cannot receive replies/bounces at all
	score += calculateReturnOKPenalty(results)

	// Penalty for what the sender domains are, whatever their records say
	score += calculateDomainInfoPenalty(results)

	// BIMI Record
	// BIMI is optional but indicates advanced email branding
	if results.BimiRecord != nil && results.BimiRecord.Valid {
		if score >= 100 {
			return 100, "A+"
		}
	}

	// Ensure score doesn't exceed maximum
	if score > 100 {
		score = 100
	}

	// Ensure score is non-negative
	if score < 0 {
		score = 0
	}

	return score, grade.Of(score)
}

// addSectionIssues completes the issues of results with those of a
// Return-Path on another domain, weighed as the MX check, with those
// charged to the section itself: what the sender domains are, and whether
// they can receive mail, told along with their MX records; and with the
// lookups that failed, which cost nothing.
func (d *DNSAnalyzer) addSectionIssues(results *model.DNSResults, mxRP []model.Issue, weight, total int) {
	issues := results.Issues

	if mxRP != nil || (results.RpDomain != nil && *results.RpDomain != "" && *results.RpDomain != results.FromDomain) {
		issues.MxReturnPath = weighIssues(mxRP, weight, total)
	}
	if results.ReturnOk != nil {
		if issues.MxReturnPath != nil {
			chargeUnreachable(issues.MxFrom, results.ReturnOk.From)
			chargeUnreachable(issues.MxReturnPath, results.ReturnOk.ReturnPath)
		} else {
			// One domain for both: losing its replies and its bounces alike
			chargeUnreachable(issues.MxFrom, results.ReturnOk.From, results.ReturnOk.ReturnPath)
		}
	}

	// Lookups that failed are not the sender's doing, but they are what the
	// checks could not see.
	if results.Errors != nil {
		var lookups []model.Issue
		for _, failure := range *results.Errors {
			lookups = append(lookups, newIssue(model.IssueTypeDnsLookupFailed, model.IssueSeverityInfo, "", failure,
				"Checks relying on this lookup may be incomplete; test again later if the failure looks temporary."))
		}
		issues.Lookups = optionalIssueList(lookups)
	}

	from, rp := domainInfoIssues(results)
	if results.FromDomainInfo != nil {
		issues.RegistrationFrom = issueList(from)
	}
	if results.RpDomainInfo != nil {
		issues.RegistrationReturnPath = issueList(rp)
	}
}

// issueList is the list of a check that ran, empty rather than nil when it
// found nothing.
func issueList(issues []model.Issue) *[]model.Issue {
	if issues == nil {
		return &[]model.Issue{}
	}
	return &issues
}

// optionalIssueList is the list of a check that may not have run: nil when
// it did not.
func optionalIssueList(issues []model.Issue) *[]model.Issue {
	if issues == nil {
		return nil
	}
	return &issues
}

// issuesOfType keeps the issues of the given types, in order.
func issuesOfType(issues []model.Issue, types ...model.IssueType) []model.Issue {
	kept := []model.Issue{}
	for _, issue := range issues {
		if slices.Contains(types, issue.Type) {
			kept = append(kept, issue)
		}
	}
	return kept
}
