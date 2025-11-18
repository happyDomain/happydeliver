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
)

// DNSAnalyzer analyzes DNS records for email domains
type DNSAnalyzer struct {
	Timeout  time.Duration
	resolver DNSResolver
}

// NewDNSAnalyzer creates a new DNS analyzer with configurable timeout
func NewDNSAnalyzer(timeout time.Duration) *DNSAnalyzer {
	return NewDNSAnalyzerWithResolver(timeout, NewStandardDNSResolver())
}

// NewDNSAnalyzerWithResolver creates a new DNS analyzer with a custom resolver.
// If resolver is nil, a StandardDNSResolver will be used.
func NewDNSAnalyzerWithResolver(timeout time.Duration, resolver DNSResolver) *DNSAnalyzer {
	if timeout == 0 {
		timeout = 10 * time.Second // Default timeout
	}
	if resolver == nil {
		resolver = NewStandardDNSResolver()
	}
	return &DNSAnalyzer{
		Timeout:  timeout,
		resolver: resolver,
	}
}

// AnalyzeDNS performs DNS validation for the email's domain
func (d *DNSAnalyzer) AnalyzeDNS(email *EmailMessage, authResults *api.AuthenticationResults, headersResults *api.HeaderAnalysis) *api.DNSResults {
	// Extract domain from From address
	if headersResults.DomainAlignment.FromDomain == nil || *headersResults.DomainAlignment.FromDomain == "" {
		return &api.DNSResults{
			Errors: &[]string{"Unable to extract domain from email"},
		}
	}
	fromDomain := *headersResults.DomainAlignment.FromDomain

	results := &api.DNSResults{
		FromDomain: fromDomain,
		RpDomain:   headersResults.DomainAlignment.ReturnPathDomain,
	}

	// Determine which domain to check SPF for (Return-Path domain)
	// SPF validates the envelope sender (Return-Path), not the From header
	spfDomain := fromDomain
	if results.RpDomain != nil {
		spfDomain = *results.RpDomain
	}

	// Store sender IP for later use in scoring
	var senderIP string
	if headersResults.ReceivedChain != nil && len(*headersResults.ReceivedChain) > 0 {
		firstHop := (*headersResults.ReceivedChain)[0]
		if firstHop.Ip != nil && *firstHop.Ip != "" {
			senderIP = *firstHop.Ip
			ptrRecords, forwardRecords := d.checkPTRAndForward(senderIP)
			if len(ptrRecords) > 0 {
				results.PtrRecords = &ptrRecords
			}
			if len(forwardRecords) > 0 {
				results.PtrForwardRecords = &forwardRecords
			}
		}
	}

	// Check MX records for From domain (where replies would go)
	results.FromMxRecords = d.checkMXRecords(fromDomain)

	// Check MX records for Return-Path domain (where bounces would go)
	// Only check if Return-Path domain is different from From domain
	if results.RpDomain != nil && *results.RpDomain != fromDomain {
		results.RpMxRecords = d.checkMXRecords(*results.RpDomain)
	}

	// Check SPF records (for Return-Path domain - this is the envelope sender)
	// SPF validates the MAIL FROM command, which corresponds to Return-Path
	results.SpfRecords = d.checkSPFRecords(spfDomain)

	// Check DKIM records (from authentication results)
	// DKIM can be for any domain, but typically the From domain
	if authResults != nil && authResults.Dkim != nil {
		for _, dkim := range *authResults.Dkim {
			if dkim.Domain != nil && dkim.Selector != nil {
				dkimRecord := d.checkDKIMRecord(*dkim.Domain, *dkim.Selector)
				if dkimRecord != nil {
					if results.DkimRecords == nil {
						results.DkimRecords = new([]api.DKIMRecord)
					}
					*results.DkimRecords = append(*results.DkimRecords, *dkimRecord)
				}
			}
		}
	}

	// Check DMARC record (for From domain - DMARC protects the visible sender)
	// DMARC validates alignment between SPF/DKIM and the From domain
	results.DmarcRecord = d.checkDMARCRecord(fromDomain)

	// Check BIMI record (for From domain - branding is based on visible sender)
	results.BimiRecord = d.checkBIMIRecord(fromDomain, "default")

	// Check DNSSEC status (for From domain)
	dnssecEnabled, err := d.resolver.IsDNSSECEnabled(nil, fromDomain)
	if err == nil {
		results.DnssecEnabled = &dnssecEnabled
	}

	return results
}

// AnalyzeDomainOnly performs DNS validation for a domain without email context
// This is useful for checking domain configuration without sending an actual email
func (d *DNSAnalyzer) AnalyzeDomainOnly(domain string) *api.DNSResults {
	results := &api.DNSResults{
		FromDomain: domain,
	}

	// Check MX records
	results.FromMxRecords = d.checkMXRecords(domain)

	// Check SPF records
	results.SpfRecords = d.checkSPFRecords(domain)

	// Check DMARC record
	results.DmarcRecord = d.checkDMARCRecord(domain)

	// Check BIMI record with default selector
	results.BimiRecord = d.checkBIMIRecord(domain, "default")

	// Check DNSSEC status
	dnssecEnabled, err := d.resolver.IsDNSSECEnabled(nil, domain)
	if err == nil {
		results.DnssecEnabled = &dnssecEnabled
	}

	return results
}

// CalculateDomainOnlyScore calculates the DNS score for domain-only tests
// Returns a score from 0-100 where higher is better
// This version excludes PTR and DKIM checks since they require email context
func (d *DNSAnalyzer) CalculateDomainOnlyScore(results *api.DNSResults) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// MX Records: 30 points (only one domain to check)
	mxScore := d.calculateMXScore(results)
	// Since calculateMXScore checks both From and RP domains,
	// and we only have From domain, we use the full score
	score += 30 * mxScore / 100

	// SPF Records: 30 points
	score += 30 * d.calculateSPFScore(results) / 100

	// DMARC Record: 40 points
	score += 40 * d.calculateDMARCScore(results) / 100

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

	return score, ScoreToGradeKind(score)
}

// CalculateDNSScore calculates the DNS score from records results
// Returns a score from 0-100 where higher is better
// senderIP is the original sender IP address used for FCrDNS verification
func (d *DNSAnalyzer) CalculateDNSScore(results *api.DNSResults, senderIP string) (int, string) {
	if results == nil {
		return 0, ""
	}

	score := 0

	// DNSSEC: 10 points
	if results.DnssecEnabled != nil && *results.DnssecEnabled {
		score += 10
	}

	// PTR and Forward DNS: 20 points
	score += 20 * d.calculatePTRScore(results, senderIP) / 100

	// MX Records: 10 points (5 for From domain, 5 for Return-Path domain)
	score += 10 * d.calculateMXScore(results) / 100

	// SPF Records: 20 points
	score += 20 * d.calculateSPFScore(results) / 100

	// DKIM Records: 20 points
	score += 20 * d.calculateDKIMScore(results) / 100

	// DMARC Record: 20 points
	score += 20 * d.calculateDMARCScore(results) / 100

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

	return score, ScoreToGrade(score)
}
