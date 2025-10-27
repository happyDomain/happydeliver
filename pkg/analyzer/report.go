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

	"git.happydns.org/happyDeliver/internal/api"
	"git.happydns.org/happyDeliver/internal/utils"
	"github.com/google/uuid"
)

// ReportGenerator generates comprehensive deliverability reports
type ReportGenerator struct {
	authAnalyzer    *AuthenticationAnalyzer
	spamAnalyzer    *SpamAssassinAnalyzer
	dnsAnalyzer     *DNSAnalyzer
	rblChecker      *RBLChecker
	contentAnalyzer *ContentAnalyzer
	headerAnalyzer  *HeaderAnalyzer
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(
	dnsTimeout time.Duration,
	httpTimeout time.Duration,
	rbls []string,
	checkAllIPs bool,
) *ReportGenerator {
	return &ReportGenerator{
		authAnalyzer:    NewAuthenticationAnalyzer(),
		spamAnalyzer:    NewSpamAssassinAnalyzer(),
		dnsAnalyzer:     NewDNSAnalyzer(dnsTimeout),
		rblChecker:      NewRBLChecker(dnsTimeout, rbls, checkAllIPs),
		contentAnalyzer: NewContentAnalyzer(httpTimeout),
		headerAnalyzer:  NewHeaderAnalyzer(),
	}
}

// AnalysisResults contains all intermediate analysis results
type AnalysisResults struct {
	Email          *EmailMessage
	Authentication *api.AuthenticationResults
	Content        *ContentResults
	DNS            *api.DNSResults
	Headers        *api.HeaderAnalysis
	RBL            *RBLResults
	SpamAssassin   *api.SpamAssassinResult
}

// AnalyzeEmail performs complete email analysis
func (r *ReportGenerator) AnalyzeEmail(email *EmailMessage) *AnalysisResults {
	results := &AnalysisResults{
		Email: email,
	}

	// Run all analyzers
	results.Authentication = r.authAnalyzer.AnalyzeAuthentication(email)
	results.Headers = r.headerAnalyzer.GenerateHeaderAnalysis(email)
	results.DNS = r.dnsAnalyzer.AnalyzeDNS(email, results.Authentication, results.Headers)
	results.RBL = r.rblChecker.CheckEmail(email)
	results.SpamAssassin = r.spamAnalyzer.AnalyzeSpamAssassin(email)
	results.Content = r.contentAnalyzer.AnalyzeContent(email)

	return results
}

// GenerateReport creates a complete API report from analysis results
func (r *ReportGenerator) GenerateReport(testID uuid.UUID, results *AnalysisResults) *api.Report {
	reportID := uuid.New()
	now := time.Now()

	report := &api.Report{
		Id:        utils.UUIDToBase32(reportID),
		TestId:    utils.UUIDToBase32(testID),
		CreatedAt: now,
	}

	// Calculate scores directly from analyzers (no more checks array)
	dnsScore := 0
	var dnsGrade string
	if results.DNS != nil {
		// Extract sender IP from received chain for FCrDNS verification
		var senderIP string
		if results.Headers != nil && results.Headers.ReceivedChain != nil && len(*results.Headers.ReceivedChain) > 0 {
			firstHop := (*results.Headers.ReceivedChain)[0]
			if firstHop.Ip != nil {
				senderIP = *firstHop.Ip
			}
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
	if results.RBL != nil {
		blacklistScore, blacklistGrade = r.rblChecker.CalculateRBLScore(results.RBL)
	}

	spamScore := 0
	var spamGrade string
	if results.SpamAssassin != nil {
		spamScore, spamGrade = r.spamAnalyzer.CalculateSpamAssassinScore(results.SpamAssassin)
	}

	report.Summary = &api.ScoreSummary{
		DnsScore:            dnsScore,
		DnsGrade:            api.ScoreSummaryDnsGrade(dnsGrade),
		AuthenticationScore: authScore,
		AuthenticationGrade: api.ScoreSummaryAuthenticationGrade(authGrade),
		BlacklistScore:      blacklistScore,
		BlacklistGrade:      api.ScoreSummaryBlacklistGrade(blacklistGrade),
		ContentScore:        contentScore,
		ContentGrade:        api.ScoreSummaryContentGrade(contentGrade),
		HeaderScore:         headerScore,
		HeaderGrade:         api.ScoreSummaryHeaderGrade(headerGrade),
		SpamScore:           spamScore,
		SpamGrade:           api.ScoreSummarySpamGrade(spamGrade),
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

	// Add SpamAssassin result
	report.Spamassassin = results.SpamAssassin

	// Add raw headers
	if results.Email != nil && results.Email.RawHeaders != "" {
		report.RawHeaders = &results.Email.RawHeaders
	}

	// Calculate overall score as mean of all category scores
	categoryScores := []int{
		report.Summary.DnsScore,
		report.Summary.AuthenticationScore,
		report.Summary.BlacklistScore,
		report.Summary.ContentScore,
		report.Summary.HeaderScore,
		report.Summary.SpamScore,
	}

	var totalScore int
	var categoryCount int
	for _, score := range categoryScores {
		totalScore += score
		categoryCount++
	}

	if categoryCount > 0 {
		report.Score = totalScore / categoryCount
	} else {
		report.Score = 0
	}

	report.Grade = ScoreToReportGrade(report.Score)
	categoryGrades := []string{
		string(report.Summary.DnsGrade),
		string(report.Summary.AuthenticationGrade),
		string(report.Summary.BlacklistGrade),
		string(report.Summary.ContentGrade),
		string(report.Summary.HeaderGrade),
		string(report.Summary.SpamGrade),
	}
	if report.Score >= 100 {
		hasLessThanA := false

		for _, grade := range categoryGrades {
			if len(grade) < 1 || grade[0] != 'A' {
				hasLessThanA = true
			}
		}

		if !hasLessThanA {
			report.Grade = "A+"
		}
	} else {
		var minusGrade byte = 0
		for _, grade := range categoryGrades {
			if len(grade) == 0 {
				minusGrade = 255
				break
			} else if grade[0]-'A' > minusGrade {
				minusGrade = grade[0] - 'A'
			}
		}

		if minusGrade < 255 {
			report.Grade = api.ReportGrade(string([]byte{'A' + minusGrade}))
		}
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
