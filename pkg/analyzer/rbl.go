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
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

// RBLChecker checks IP addresses against DNS-based blacklists
type RBLChecker struct {
	Timeout  time.Duration
	RBLs     []string
	resolver *net.Resolver
}

// DefaultRBLs is a list of commonly used RBL providers
var DefaultRBLs = []string{
	"zen.spamhaus.org",       // Spamhaus combined list
	"bl.spamcop.net",         // SpamCop
	"dnsbl.sorbs.net",        // SORBS
	"b.barracudacentral.org", // Barracuda
	"cbl.abuseat.org",        // CBL (Composite Blocking List)
	"dnsbl-1.uceprotect.net", // UCEPROTECT Level 1
}

// NewRBLChecker creates a new RBL checker with configurable timeout and RBL list
func NewRBLChecker(timeout time.Duration, rbls []string) *RBLChecker {
	if timeout == 0 {
		timeout = 5 * time.Second // Default timeout
	}
	if len(rbls) == 0 {
		rbls = DefaultRBLs
	}
	return &RBLChecker{
		Timeout: timeout,
		RBLs:    rbls,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// RBLResults represents the results of RBL checks
type RBLResults struct {
	Checks      []RBLCheck
	IPsChecked  []string
	ListedCount int
}

// RBLCheck represents a single RBL check result
type RBLCheck struct {
	IP       string
	RBL      string
	Listed   bool
	Response string
	Error    string
}

// CheckEmail checks all IPs found in the email headers against RBLs
func (r *RBLChecker) CheckEmail(email *EmailMessage) *RBLResults {
	results := &RBLResults{}

	// Extract IPs from Received headers
	ips := r.extractIPs(email)
	if len(ips) == 0 {
		return results
	}

	results.IPsChecked = ips

	// Check each IP against all RBLs
	for _, ip := range ips {
		for _, rbl := range r.RBLs {
			check := r.checkIP(ip, rbl)
			results.Checks = append(results.Checks, check)
			if check.Listed {
				results.ListedCount++
			}
		}
	}

	return results
}

// extractIPs extracts IP addresses from Received headers
func (r *RBLChecker) extractIPs(email *EmailMessage) []string {
	var ips []string
	seenIPs := make(map[string]bool)

	// Get all Received headers
	receivedHeaders := email.Header["Received"]

	// Regex patterns for IP addresses
	// Match IPv4: xxx.xxx.xxx.xxx
	ipv4Pattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Look for IPs in Received headers
	for _, received := range receivedHeaders {
		// Find all IPv4 addresses
		matches := ipv4Pattern.FindAllString(received, -1)
		for _, match := range matches {
			// Skip private/reserved IPs
			if !r.isPublicIP(match) {
				continue
			}
			// Avoid duplicates
			if !seenIPs[match] {
				ips = append(ips, match)
				seenIPs[match] = true
			}
		}
	}

	// If no IPs found in Received headers, try X-Originating-IP
	if len(ips) == 0 {
		originatingIP := email.Header.Get("X-Originating-IP")
		if originatingIP != "" {
			// Extract IP from formats like "[192.0.2.1]" or "192.0.2.1"
			cleanIP := strings.TrimSuffix(strings.TrimPrefix(originatingIP, "["), "]")
			// Remove any whitespace
			cleanIP = strings.TrimSpace(cleanIP)
			matches := ipv4Pattern.FindString(cleanIP)
			if matches != "" && r.isPublicIP(matches) {
				ips = append(ips, matches)
			}
		}
	}

	return ips
}

// isPublicIP checks if an IP address is public (not private, loopback, or reserved)
func (r *RBLChecker) isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check if it's a private network
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// Additional checks for reserved ranges
	// 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
	if ip.IsUnspecified() {
		return false
	}

	return true
}

// checkIP checks a single IP against a single RBL
func (r *RBLChecker) checkIP(ip, rbl string) RBLCheck {
	check := RBLCheck{
		IP:  ip,
		RBL: rbl,
	}

	// Reverse the IP for DNSBL query
	reversedIP := r.reverseIP(ip)
	if reversedIP == "" {
		check.Error = "Failed to reverse IP address"
		return check
	}

	// Construct DNSBL query: reversed-ip.rbl-domain
	query := fmt.Sprintf("%s.%s", reversedIP, rbl)

	// Perform DNS lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, query)
	if err != nil {
		// Most likely not listed (NXDOMAIN)
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				check.Listed = false
				return check
			}
		}
		// Other DNS errors
		check.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		return check
	}

	// If we got a response, check the return code
	if len(addrs) > 0 {
		check.Response = addrs[0] // Return code (e.g., 127.0.0.2)

		// Check for RBL error codes: 127.255.255.253, 127.255.255.254, 127.255.255.255
		// These indicate RBL operational issues, not actual listings
		if addrs[0] == "127.255.255.253" || addrs[0] == "127.255.255.254" || addrs[0] == "127.255.255.255" {
			check.Listed = false
			check.Error = fmt.Sprintf("RBL %s returned error code %s (RBL operational issue)", rbl, addrs[0])
		} else {
			// Normal listing response
			check.Listed = true
		}
	}

	return check
}

// reverseIP reverses an IPv4 address for DNSBL queries
// Example: 192.0.2.1 -> 1.2.0.192
func (r *RBLChecker) reverseIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Convert to IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "" // IPv6 not supported yet
	}

	// Reverse the octets
	return fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
}

// GetBlacklistScore calculates the blacklist contribution to deliverability
func (r *RBLChecker) GetBlacklistScore(results *RBLResults) int {
	if results == nil || len(results.IPsChecked) == 0 {
		// No IPs to check, give benefit of doubt
		return 100
	}

	return 100 - results.ListedCount*100/len(r.RBLs)
}

// GenerateRBLChecks generates check results for RBL analysis
func (r *RBLChecker) GenerateRBLChecks(results *RBLResults) []api.Check {
	var checks []api.Check

	if results == nil {
		return checks
	}

	// If no IPs were checked, add a warning
	if len(results.IPsChecked) == 0 {
		checks = append(checks, api.Check{
			Category: api.Blacklist,
			Name:     "RBL Check",
			Status:   api.CheckStatusWarn,
			Score:    50,
			Grade:    ScoreToCheckGrade(50),
			Message:  "No public IP addresses found to check",
			Severity: api.PtrTo(api.CheckSeverityLow),
			Advice:   api.PtrTo("Unable to extract sender IP from email headers"),
		})
		return checks
	}

	// Create a summary check
	summaryCheck := r.generateSummaryCheck(results)
	checks = append(checks, summaryCheck)

	// Create individual checks for each listing and RBL errors
	for _, check := range results.Checks {
		if check.Listed {
			detailCheck := r.generateListingCheck(&check)
			checks = append(checks, detailCheck)
		} else if check.Error != "" && strings.Contains(check.Error, "RBL operational issue") {
			// Generate info check for RBL errors
			detailCheck := r.generateRBLErrorCheck(&check)
			checks = append(checks, detailCheck)
		}
	}

	return checks
}

// generateSummaryCheck creates an overall RBL summary check
func (r *RBLChecker) generateSummaryCheck(results *RBLResults) api.Check {
	check := api.Check{
		Category: api.Blacklist,
		Name:     "RBL Summary",
	}

	score := r.GetBlacklistScore(results)
	check.Score = score
	check.Grade = ScoreToCheckGrade(score)

	totalChecks := len(results.Checks)
	listedCount := results.ListedCount

	if listedCount == 0 {
		check.Status = api.CheckStatusPass
		check.Message = fmt.Sprintf("Not listed on any blacklists (%d RBLs checked)", len(r.RBLs))
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your sending IP has a good reputation")
	} else if listedCount == 1 {
		check.Status = api.CheckStatusWarn
		check.Message = fmt.Sprintf("Listed on 1 blacklist (out of %d checked)", totalChecks)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("You're listed on one blacklist. Review the specific listing and request delisting if appropriate")
	} else if listedCount <= 3 {
		check.Status = api.CheckStatusWarn
		check.Message = fmt.Sprintf("Listed on %d blacklists (out of %d checked)", listedCount, totalChecks)
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Multiple blacklist listings detected. This will significantly impact deliverability. Review each listing and take corrective action")
	} else {
		check.Status = api.CheckStatusFail
		check.Message = fmt.Sprintf("Listed on %d blacklists (out of %d checked)", listedCount, totalChecks)
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		check.Advice = api.PtrTo("Your IP is listed on multiple blacklists. This will severely impact email deliverability. Investigate the cause and request delisting from each RBL")
	}

	// Add details about IPs checked
	if len(results.IPsChecked) > 0 {
		details := fmt.Sprintf("IPs checked: %s", strings.Join(results.IPsChecked, ", "))
		check.Details = &details
	}

	return check
}

// generateListingCheck creates a check for a specific RBL listing
func (r *RBLChecker) generateListingCheck(rblCheck *RBLCheck) api.Check {
	check := api.Check{
		Category: api.Blacklist,
		Name:     fmt.Sprintf("RBL: %s", rblCheck.RBL),
		Status:   api.CheckStatusFail,
		Score:    0,
		Grade:    ScoreToCheckGrade(0),
	}

	check.Message = fmt.Sprintf("IP %s is listed on %s", rblCheck.IP, rblCheck.RBL)

	// Determine severity based on which RBL
	if strings.Contains(rblCheck.RBL, "spamhaus") {
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		advice := fmt.Sprintf("Listed on Spamhaus, a widely-used blocklist. Visit https://check.spamhaus.org/ to check details and request delisting")
		check.Advice = &advice
	} else if strings.Contains(rblCheck.RBL, "spamcop") {
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		advice := fmt.Sprintf("Listed on SpamCop. Visit http://www.spamcop.net/bl.shtml to request delisting")
		check.Advice = &advice
	} else {
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		advice := fmt.Sprintf("Listed on %s. Contact the RBL operator for delisting procedures", rblCheck.RBL)
		check.Advice = &advice
	}

	// Add response code details
	if rblCheck.Response != "" {
		details := fmt.Sprintf("Response: %s", rblCheck.Response)
		check.Details = &details
	}

	return check
}

// generateRBLErrorCheck creates an info-level check for RBL operational errors
func (r *RBLChecker) generateRBLErrorCheck(rblCheck *RBLCheck) api.Check {
	check := api.Check{
		Category: api.Blacklist,
		Name:     fmt.Sprintf("RBL: %s", rblCheck.RBL),
		Status:   api.CheckStatusInfo,
		Score:    0, // No penalty for RBL operational issues
		Grade:    ScoreToCheckGrade(-1),
		Severity: api.PtrTo(api.CheckSeverityInfo),
	}

	check.Message = fmt.Sprintf("RBL %s returned an error code for IP %s", rblCheck.RBL, rblCheck.IP)

	advice := fmt.Sprintf("The RBL %s is experiencing operational issues (error code: %s).", rblCheck.RBL, rblCheck.Response)
	check.Advice = &advice

	if rblCheck.Response != "" {
		details := fmt.Sprintf("Error code: %s (RBL operational issue, not a listing)", rblCheck.Response)
		check.Details = &details
	}

	return check
}

// GetUniqueListedIPs returns a list of unique IPs that are listed on at least one RBL
func (r *RBLChecker) GetUniqueListedIPs(results *RBLResults) []string {
	seenIPs := make(map[string]bool)
	var listedIPs []string

	for _, check := range results.Checks {
		if check.Listed && !seenIPs[check.IP] {
			listedIPs = append(listedIPs, check.IP)
			seenIPs[check.IP] = true
		}
	}

	return listedIPs
}

// GetRBLsForIP returns all RBLs that list a specific IP
func (r *RBLChecker) GetRBLsForIP(results *RBLResults, ip string) []string {
	var rbls []string

	for _, check := range results.Checks {
		if check.IP == ip && check.Listed {
			rbls = append(rbls, check.RBL)
		}
	}

	return rbls
}
