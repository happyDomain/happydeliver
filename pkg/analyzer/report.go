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
		scorer:          NewDeliverabilityScorer(),
	}
}

// AnalysisResults contains all intermediate analysis results
type AnalysisResults struct {
	Email          *EmailMessage
	Authentication *api.AuthenticationResults
	SpamAssassin   *SpamAssassinResult
	DNS            *DNSResults
	RBL            *RBLResults
	Content        *ContentResults
	Score          *ScoringResult
}

// AnalyzeEmail performs complete email analysis
func (r *ReportGenerator) AnalyzeEmail(email *EmailMessage) *AnalysisResults {
	results := &AnalysisResults{
		Email: email,
	}

	// Run all analyzers
	results.Authentication = r.authAnalyzer.AnalyzeAuthentication(email)
	results.SpamAssassin = r.spamAnalyzer.AnalyzeSpamAssassin(email)
	results.DNS = r.dnsAnalyzer.AnalyzeDNS(email, results.Authentication)
	results.RBL = r.rblChecker.CheckEmail(email)
	results.Content = r.contentAnalyzer.AnalyzeContent(email)

	// Calculate overall score
	results.Score = r.scorer.CalculateScore(
		results.Authentication,
		results.SpamAssassin,
		results.RBL,
		results.Content,
		email,
	)

	return results
}

// GenerateReport creates a complete API report from analysis results
func (r *ReportGenerator) GenerateReport(testID uuid.UUID, results *AnalysisResults) *api.Report {
	reportID := uuid.New()
	now := time.Now()

	report := &api.Report{
		Id:        utils.UUIDToBase32(reportID),
		TestId:    utils.UUIDToBase32(testID),
		Score:     results.Score.OverallScore,
		Grade:     ScoreToReportGrade(results.Score.OverallScore),
		CreatedAt: now,
	}

	// Build score summary
	report.Summary = &api.ScoreSummary{
		AuthenticationScore: results.Score.AuthScore,
		SpamScore:           results.Score.SpamScore,
		BlacklistScore:      results.Score.BlacklistScore,
		ContentScore:        results.Score.ContentScore,
		HeaderScore:         results.Score.HeaderScore,
	}

	// Collect all checks from different analyzers
	checks := []api.Check{}

	// Authentication checks
	if results.Authentication != nil {
		authChecks := r.authAnalyzer.GenerateAuthenticationChecks(results.Authentication)
		checks = append(checks, authChecks...)
	}

	// DNS checks
	if results.DNS != nil {
		dnsChecks := r.dnsAnalyzer.GenerateDNSChecks(results.DNS)
		checks = append(checks, dnsChecks...)
	}

	// RBL checks
	if results.RBL != nil {
		rblChecks := r.rblChecker.GenerateRBLChecks(results.RBL)
		checks = append(checks, rblChecks...)
	}

	// SpamAssassin checks
	if results.SpamAssassin != nil {
		spamChecks := r.spamAnalyzer.GenerateSpamAssassinChecks(results.SpamAssassin)
		checks = append(checks, spamChecks...)
	}

	// Content checks
	if results.Content != nil {
		contentChecks := r.contentAnalyzer.GenerateContentChecks(results.Content)
		checks = append(checks, contentChecks...)
	}

	// Header checks
	headerChecks := r.scorer.GenerateHeaderChecks(results.Email)
	checks = append(checks, headerChecks...)

	report.Checks = checks

	// Add authentication results
	report.Authentication = results.Authentication

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

	// Add DNS records
	if results.DNS != nil {
		dnsRecords := r.buildDNSRecords(results.DNS)
		if len(dnsRecords) > 0 {
			report.DnsRecords = &dnsRecords
		}
	}

	// Add blacklist checks
	if results.RBL != nil && len(results.RBL.Checks) > 0 {
		blacklistChecks := make([]api.BlacklistCheck, 0, len(results.RBL.Checks))
		for _, check := range results.RBL.Checks {
			blCheck := api.BlacklistCheck{
				Ip:     check.IP,
				Rbl:    check.RBL,
				Listed: check.Listed,
			}
			if check.Response != "" {
				blCheck.Response = &check.Response
			}
			blacklistChecks = append(blacklistChecks, blCheck)
		}
		report.Blacklists = &blacklistChecks
	}

	// Add raw headers
	if results.Email != nil && results.Email.RawHeaders != "" {
		report.RawHeaders = &results.Email.RawHeaders
	}

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

// GetRecommendations returns actionable recommendations based on the score
func (r *ReportGenerator) GetRecommendations(results *AnalysisResults) []string {
	if results == nil || results.Score == nil {
		return []string{}
	}

	return results.Score.Recommendations
}

// GetScoreSummaryText returns a human-readable score summary
func (r *ReportGenerator) GetScoreSummaryText(results *AnalysisResults) string {
	if results == nil || results.Score == nil {
		return ""
	}

	return r.scorer.GetScoreSummary(results.Score)
}
