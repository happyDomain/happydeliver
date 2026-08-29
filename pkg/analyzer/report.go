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
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"github.com/google/uuid"
)

// ReportGenerator generates comprehensive deliverability reports
type ReportGenerator struct {
	authAnalyzer    *AuthenticationAnalyzer
	spamAnalyzer    *SpamAssassinAnalyzer
	rspamdAnalyzer  *RspamdAnalyzer
	dnsAnalyzer     *DNSAnalyzer
	rblChecker      *DNSListChecker
	dnswlChecker    *DNSListChecker
	contentAnalyzer *ContentAnalyzer
	headerAnalyzer  *HeaderAnalyzer
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(
	receiverHostname string,
	dnsTimeout time.Duration,
	httpTimeout time.Duration,
	rbls []string,
	dnswls []string,
	checkAllIPs bool,
	rspamdAPIURL string,
) *ReportGenerator {
	return &ReportGenerator{
		authAnalyzer:    NewAuthenticationAnalyzer(receiverHostname),
		spamAnalyzer:    NewSpamAssassinAnalyzer(),
		rspamdAnalyzer:  NewRspamdAnalyzer(LoadRspamdSymbols(rspamdAPIURL)),
		dnsAnalyzer:     NewDNSAnalyzer(dnsTimeout),
		rblChecker:      NewRBLChecker(dnsTimeout, rbls, checkAllIPs),
		dnswlChecker:    NewDNSWLChecker(dnsTimeout, dnswls, checkAllIPs),
		contentAnalyzer: NewContentAnalyzer(httpTimeout),
		headerAnalyzer:  NewHeaderAnalyzer(),
	}
}

// AnalysisOptions describes where the message being analyzed comes from.
//
// It matters because every authentication verdict is read from Authentication-Results
// headers: for a message received by this instance those headers were written by our own
// milter, while for a message the user supplied they were written by whichever server
// originally handled it.
type AnalysisOptions struct {
	// Source is where the message comes from. The zero value is treated as
	// model.ReportSourceReceived.
	Source model.ReportSource
}

// sourceOrDefault returns the source to record, defaulting to a received message.
func (o AnalysisOptions) sourceOrDefault() model.ReportSource {
	if o.Source == "" {
		return model.ReportSourceReceived
	}

	return o.Source
}

// AnalysisResults contains all intermediate analysis results
type AnalysisResults struct {
	Email          *EmailMessage
	Source         model.ReportSource
	AuthservID     string
	AuthservIDs    []string
	Authentication *model.AuthenticationResults
	Content        *ContentResults
	DNS            *model.DNSResults
	Headers        *model.HeaderAnalysis
	RBL            *DNSListResults
	DNSWL          *DNSListResults
	SpamAssassin   *model.SpamAssassinResult
	Rspamd         *model.RspamdResult
}

// AnalyzeEmail performs complete email analysis
func (r *ReportGenerator) AnalyzeEmail(email *EmailMessage, opts AnalysisOptions) *AnalysisResults {
	results := &AnalysisResults{
		Email:       email,
		Source:      opts.sourceOrDefault(),
		AuthservIDs: email.AuthservIDs(),
	}

	// A message we received ourselves is only trusted through our own authserv-id; for any
	// other source, trust the topmost Authentication-Results header, written by the last
	// server that handled the message.
	if results.Source == model.ReportSourceReceived {
		results.AuthservID = r.authAnalyzer.receiverHostname
	} else if len(results.AuthservIDs) > 0 {
		results.AuthservID = results.AuthservIDs[0]
	}

	// Run all analyzers
	results.Authentication = r.authAnalyzer.AnalyzeAuthentication(email, results.AuthservID)
	results.Headers = r.headerAnalyzer.GenerateHeaderAnalysis(email, results.Authentication)
	// The hop the DNS analysis takes the sender IP and HELO name from, flagged
	// in the published chain so clients read the selection instead of
	// reconstructing it.
	var inboundHop *model.ReceivedHop
	if results.Headers != nil && results.Headers.ReceivedChain != nil {
		chain := *results.Headers.ReceivedChain
		if i := InboundHopIndex(chain, results.Source); i >= 0 {
			chain[i].Inbound = utils.PtrTo(true)
			inboundHop = &chain[i]
		}
	}
	// Fall back to the received chain's inbound TLS when no x-tls header was present. Only valid
	// for a message we received ourselves: for an uploaded .eml, the topmost Received header
	// could be an internal hop of the original provider, not the arrival at the recipient's
	// server.
	if results.Source == model.ReportSourceReceived && results.Authentication != nil && results.Headers != nil {
		r.authAnalyzer.ReconcileXTLS(results.Authentication, results.Headers.ReceivedChain)
	}
	results.DNS = r.dnsAnalyzer.AnalyzeDNS(email, results.Headers, inboundHop)
	results.RBL = r.rblChecker.CheckEmail(email)
	results.DNSWL = r.dnswlChecker.CheckEmail(email)

	spamHeaders := email.SpamScannerHeaders()
	results.SpamAssassin = r.spamAnalyzer.AnalyzeSpamAssassin(spamHeaders.For(ScannerSpamAssassin))
	results.Rspamd = r.rspamdAnalyzer.AnalyzeRspamd(spamHeaders.For(ScannerRspamd))

	results.Content = r.contentAnalyzer.AnalyzeContent(email)

	return results
}

// GenerateReport creates a complete API report from analysis results
func (r *ReportGenerator) GenerateReport(testID uuid.UUID, results *AnalysisResults) *model.Report {
	reportID := uuid.New()
	now := time.Now()

	report := &model.Report{
		Id:        utils.UUIDToBase32(reportID),
		TestId:    utils.UUIDToBase32(testID),
		CreatedAt: now,
	}

	// Record where the message came from, and which authority produced the authentication
	// verdicts, so consumers can tell a sender problem from an unavailable measurement.
	report.Source = utils.PtrTo(results.Source)
	if results.AuthservID != "" {
		report.AuthservId = utils.PtrTo(results.AuthservID)
	}
	if len(results.AuthservIDs) > 0 {
		report.AuthservIdsFound = utils.PtrTo(results.AuthservIDs)
	}

	// Calculate scores directly from analyzers (no more checks array)
	dnsScore := 0
	var dnsGrade string
	if results.DNS != nil {
		// Sender IP used for FCrDNS verification: the one AnalyzeDNS actually
		// looked up, so the score and the reported sender_ip cannot diverge.
		var senderIP string
		if results.DNS.SenderIp != nil {
			senderIP = *results.DNS.SenderIp
		}
		dnsScore, dnsGrade = r.dnsAnalyzer.CalculateDNSScore(results.DNS, senderIP)
	}

	authScore := 0
	var authGrade string
	if results.Authentication != nil {
		authScore, authGrade = r.authAnalyzer.CalculateAuthenticationScore(results.Authentication)
	}

	contentScore := 0
	var contentGrade string
	if results.Content != nil {
		contentScore, contentGrade = r.contentAnalyzer.CalculateContentScore(results.Content)
	}

	headerScore := 0
	var headerGrade rune
	if results.Headers != nil {
		headerScore, headerGrade = r.headerAnalyzer.CalculateHeaderScore(results.Headers)
	}

	blacklistScore := 0
	var blacklistGrade string
	var whitelistGrade string
	if results.RBL != nil {
		blacklistScore, blacklistGrade = r.rblChecker.CalculateScore(results.RBL, false)
		_, whitelistGrade = r.dnswlChecker.CalculateScore(results.DNSWL, true)
	}

	saScore, saGrade := r.spamAnalyzer.CalculateSpamAssassinScore(results.SpamAssassin)
	rspamdScore, rspamdGrade := r.rspamdAnalyzer.CalculateRspamdScore(results.Rspamd)

	// Combine SpamAssassin and rspamd scores 50/50.
	// If only one filter ran (the other returns "" grade), use that filter's score alone.
	var spamScore int
	var spamGrade string
	switch {
	case saGrade == "" && rspamdGrade == "":
		spamScore = 0
		spamGrade = ""
	case saGrade == "":
		spamScore = rspamdScore
		spamGrade = rspamdGrade
	case rspamdGrade == "":
		spamScore = saScore
		spamGrade = saGrade
	default:
		spamScore = (saScore + rspamdScore) / 2
		spamGrade = MinGrade(saGrade, rspamdGrade)
	}

	report.Summary = &model.ScoreSummary{
		DnsScore:            dnsScore,
		DnsGrade:            model.ScoreSummaryDnsGrade(dnsGrade),
		AuthenticationScore: authScore,
		AuthenticationGrade: model.ScoreSummaryAuthenticationGrade(authGrade),
		BlacklistScore:      blacklistScore,
		BlacklistGrade:      model.ScoreSummaryBlacklistGrade(MinGrade(blacklistGrade, whitelistGrade)),
		ContentScore:        contentScore,
		ContentGrade:        model.ScoreSummaryContentGrade(contentGrade),
		HeaderScore:         headerScore,
		HeaderGrade:         model.ScoreSummaryHeaderGrade(headerGrade),
		SpamScore:           spamScore,
		SpamGrade:           model.ScoreSummarySpamGrade(spamGrade),
	}

	// Add authentication results
	report.Authentication = results.Authentication

	// Add content analysis
	if results.Content != nil {
		contentAnalysis := r.contentAnalyzer.GenerateContentAnalysis(results.Content)
		report.ContentAnalysis = contentAnalysis
	}

	// Add DNS records
	if results.DNS != nil {
		report.DnsResults = results.DNS
	}

	// Add headers results
	report.HeaderAnalysis = results.Headers

	// Add blacklist checks as a map of IP -> array of BlacklistCheck
	if results.RBL != nil && len(results.RBL.Checks) > 0 {
		report.Blacklists = &results.RBL.Checks
	}

	// Add whitelist checks as a map of IP -> array of BlacklistCheck (informational only)
	if results.DNSWL != nil && len(results.DNSWL.Checks) > 0 {
		report.Whitelists = &results.DNSWL.Checks
	}

	// Add SpamAssassin result with individual deliverability score
	if results.SpamAssassin != nil {
		saGradeTyped := model.SpamAssassinResultDeliverabilityGrade(saGrade)
		results.SpamAssassin.DeliverabilityScore = utils.PtrTo(saScore)
		results.SpamAssassin.DeliverabilityGrade = &saGradeTyped
	}
	report.Spamassassin = results.SpamAssassin

	// Add rspamd result with individual deliverability score
	if results.Rspamd != nil {
		rspamdGradeTyped := model.RspamdResultDeliverabilityGrade(rspamdGrade)
		results.Rspamd.DeliverabilityScore = utils.PtrTo(rspamdScore)
		results.Rspamd.DeliverabilityGrade = &rspamdGradeTyped
	}
	report.Rspamd = results.Rspamd

	// Add raw headers
	if results.Email != nil && results.Email.RawHeaders != "" {
		report.RawHeaders = &results.Email.RawHeaders
	}

	// Calculate overall score as mean of the category scores that actually
	// ran. A category reports an empty (or NUL, for the header rune-based
	// grade) grade when it did not run at all, in which case its score is
	// just a placeholder 0 that must not be averaged in as if it were the
	// worst possible result.
	categoryResults := []struct {
		score int
		grade string
	}{
		{report.Summary.DnsScore, string(report.Summary.DnsGrade)},
		{report.Summary.AuthenticationScore, string(report.Summary.AuthenticationGrade)},
		{report.Summary.BlacklistScore, string(report.Summary.BlacklistGrade)},
		{report.Summary.ContentScore, string(report.Summary.ContentGrade)},
		{report.Summary.HeaderScore, string(report.Summary.HeaderGrade)},
		{report.Summary.SpamScore, string(report.Summary.SpamGrade)},
	}

	var totalScore int
	var categoryCount int
	var categoryGrades []string
	for _, c := range categoryResults {
		if c.grade == "" || c.grade[0] == 0 {
			continue
		}
		totalScore += c.score
		categoryCount++
		categoryGrades = append(categoryGrades, c.grade)
	}

	if categoryCount > 0 {
		report.Score = totalScore / categoryCount
	} else {
		report.Score = 0
	}

	report.Grade = ScoreToReportGrade(report.Score)
	if report.Score >= 100 {
		hasLessThanA := false

		for _, grade := range categoryGrades {
			if grade[0] != 'A' {
				hasLessThanA = true
			}
		}

		if !hasLessThanA {
			report.Grade = "A+"
		}
	} else {
		var minusGrade byte = 0
		for _, grade := range categoryGrades {
			if grade[0]-'A' > minusGrade {
				minusGrade = grade[0] - 'A'
			}
		}

		report.Grade = model.ReportGrade(string([]byte{'A' + minusGrade}))
	}

	return report
}

// GenerateRawEmail returns the raw email message as a string
func (r *ReportGenerator) GenerateRawEmail(email *EmailMessage) string {
	if email == nil {
		return ""
	}

	raw := email.RawHeaders
	if email.RawBody != "" {
		raw += "\n" + email.RawBody
	}

	return raw
}
