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
	scorer          *DeliverabilityScorer
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(
	dnsTimeout time.Duration,
	httpTimeout time.Duration,
	rbls []string,
) *ReportGenerator {
	return &ReportGenerator{
		authAnalyzer:    NewAuthenticationAnalyzer(),
		spamAnalyzer:    NewSpamAssassinAnalyzer(),
		dnsAnalyzer:     NewDNSAnalyzer(dnsTimeout),
		rblChecker:      NewRBLChecker(dnsTimeout, rbls),
		contentAnalyzer: NewContentAnalyzer(httpTimeout),
		headerAnalyzer:  NewHeaderAnalyzer(),
		scorer:          NewDeliverabilityScorer(),
	}
}

// AnalysisResults contains all intermediate analysis results
type AnalysisResults struct {
	Email          *EmailMessage
	Authentication *api.AuthenticationResults
	Content        *ContentResults
	DNS            *DNSResults
	Headers        *api.HeaderAnalysis
	RBL            *RBLResults
	SpamAssassin   *SpamAssassinResult
}

// AnalyzeEmail performs complete email analysis
func (r *ReportGenerator) AnalyzeEmail(email *EmailMessage) *AnalysisResults {
	results := &AnalysisResults{
		Email: email,
	}

	// Run all analyzers
	results.Authentication = r.authAnalyzer.AnalyzeAuthentication(email)
	results.Content = r.contentAnalyzer.AnalyzeContent(email)
	results.DNS = r.dnsAnalyzer.AnalyzeDNS(email, results.Authentication)
	results.Headers = r.headerAnalyzer.GenerateHeaderAnalysis(email)
	results.RBL = r.rblChecker.CheckEmail(email)
	results.SpamAssassin = r.spamAnalyzer.AnalyzeSpamAssassin(email)

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
	authScore := 0
	if results.Authentication != nil {
		authScore = r.authAnalyzer.CalculateAuthenticationScore(results.Authentication)
	}

	contentScore := 0
	if results.Content != nil {
		contentScore = r.contentAnalyzer.CalculateContentScore(results.Content)
	}

	headerScore := 0
	if results.Headers != nil {
		headerScore = r.headerAnalyzer.CalculateHeaderScore(results.Headers)
	}

	blacklistScore := 0
	if results.RBL != nil {
		blacklistScore = r.rblChecker.CalculateRBLScore(results.RBL)
	}

	spamScore := 0
	if results.SpamAssassin != nil {
		spamScore = r.scorer.CalculateSpamScore(results.SpamAssassin)
	}

	report.Summary = &api.ScoreSummary{
		AuthenticationScore: authScore,
		BlacklistScore:      blacklistScore,
		ContentScore:        contentScore,
		HeaderScore:         headerScore,
		SpamScore:           spamScore,
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
		dnsRecords := r.buildDNSRecords(results.DNS)
		if len(dnsRecords) > 0 {
			report.DnsRecords = &dnsRecords
		}
	}

	// Add headers results
	report.HeaderAnalysis = results.Headers

	// Add blacklist checks as a map of IP -> array of BlacklistCheck
	if results.RBL != nil && len(results.RBL.Checks) > 0 {
		report.Blacklists = &results.RBL.Checks
	}

	// Add SpamAssassin result
	if results.SpamAssassin != nil {
		report.Spamassassin = &api.SpamAssassinResult{
			Score:         float32(results.SpamAssassin.Score),
			RequiredScore: float32(results.SpamAssassin.RequiredScore),
			IsSpam:        results.SpamAssassin.IsSpam,
		}

		if len(results.SpamAssassin.Tests) > 0 {
			report.Spamassassin.Tests = &results.SpamAssassin.Tests
		}

		if results.SpamAssassin.RawReport != "" {
			report.Spamassassin.Report = &results.SpamAssassin.RawReport
		}
	}

	// Add raw headers
	if results.Email != nil && results.Email.RawHeaders != "" {
		report.RawHeaders = &results.Email.RawHeaders
	}

	// Calculate overall score as mean of all category scores
	categoryScores := []int{
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

	return report
}

// buildDNSRecords converts DNS analysis results to API DNS records
func (r *ReportGenerator) buildDNSRecords(dns *DNSResults) []api.DNSRecord {
	records := []api.DNSRecord{}

	if dns == nil {
		return records
	}

	// MX records
	if len(dns.MXRecords) > 0 {
		for _, mx := range dns.MXRecords {
			status := api.Found
			if !mx.Valid {
				if mx.Error != "" {
					status = api.Missing
				} else {
					status = api.Invalid
				}
			}

			record := api.DNSRecord{
				Domain:     dns.Domain,
				RecordType: api.MX,
				Status:     status,
			}

			if mx.Host != "" {
				value := mx.Host
				record.Value = &value
			}

			records = append(records, record)
		}
	}

	// SPF record
	if dns.SPFRecord != nil {
		status := api.Found
		if !dns.SPFRecord.Valid {
			if dns.SPFRecord.Record == "" {
				status = api.Missing
			} else {
				status = api.Invalid
			}
		}

		record := api.DNSRecord{
			Domain:     dns.Domain,
			RecordType: api.SPF,
			Status:     status,
		}

		if dns.SPFRecord.Record != "" {
			record.Value = &dns.SPFRecord.Record
		}

		records = append(records, record)
	}

	// DKIM records
	for _, dkim := range dns.DKIMRecords {
		status := api.Found
		if !dkim.Valid {
			if dkim.Record == "" {
				status = api.Missing
			} else {
				status = api.Invalid
			}
		}

		record := api.DNSRecord{
			Domain:     dkim.Domain,
			RecordType: api.DKIM,
			Status:     status,
		}

		if dkim.Record != "" {
			// Include selector in value for clarity
			value := dkim.Record
			record.Value = &value
		}

		records = append(records, record)
	}

	// DMARC record
	if dns.DMARCRecord != nil {
		status := api.Found
		if !dns.DMARCRecord.Valid {
			if dns.DMARCRecord.Record == "" {
				status = api.Missing
			} else {
				status = api.Invalid
			}
		}

		record := api.DNSRecord{
			Domain:     dns.Domain,
			RecordType: api.DMARC,
			Status:     status,
		}

		if dns.DMARCRecord.Record != "" {
			record.Value = &dns.DMARCRecord.Record
		}

		records = append(records, record)
	}

	return records
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
