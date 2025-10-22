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
	Checks      map[string][]api.BlacklistCheck // Map of IP -> list of RBL checks for that IP
	IPsChecked  []string
	ListedCount int
}

// CheckEmail checks all IPs found in the email headers against RBLs
func (r *RBLChecker) CheckEmail(email *EmailMessage) *RBLResults {
	results := &RBLResults{
		Checks: make(map[string][]api.BlacklistCheck),
	}

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
			results.Checks[ip] = append(results.Checks[ip], check)
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
func (r *RBLChecker) checkIP(ip, rbl string) api.BlacklistCheck {
	check := api.BlacklistCheck{
		Rbl: rbl,
	}

	// Reverse the IP for DNSBL query
	reversedIP := r.reverseIP(ip)
	if reversedIP == "" {
		check.Error = api.PtrTo("Failed to reverse IP address")
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
		check.Error = api.PtrTo(fmt.Sprintf("DNS lookup failed: %v", err))
		return check
	}

	// If we got a response, check the return code
	if len(addrs) > 0 {
		check.Response = api.PtrTo(addrs[0]) // Return code (e.g., 127.0.0.2)

		// Check for RBL error codes: 127.255.255.253, 127.255.255.254, 127.255.255.255
		// These indicate RBL operational issues, not actual listings
		if addrs[0] == "127.255.255.253" || addrs[0] == "127.255.255.254" || addrs[0] == "127.255.255.255" {
			check.Listed = false
			check.Error = api.PtrTo(fmt.Sprintf("RBL %s returned error code %s (RBL operational issue)", rbl, addrs[0]))
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

// CalculateRBLScore calculates the blacklist contribution to deliverability
func (r *RBLChecker) CalculateRBLScore(results *RBLResults) (int, string) {
	if results == nil || len(results.IPsChecked) == 0 {
		// No IPs to check, give benefit of doubt
		return 100, ""
	}

	percentage := 100 - results.ListedCount*100/len(r.RBLs)
	return percentage, ScoreToGrade(percentage)
}

// GetUniqueListedIPs returns a list of unique IPs that are listed on at least one RBL
func (r *RBLChecker) GetUniqueListedIPs(results *RBLResults) []string {
	var listedIPs []string

	for ip, rblChecks := range results.Checks {
		for _, check := range rblChecks {
			if check.Listed {
				listedIPs = append(listedIPs, ip)
				break // Only add the IP once
			}
		}
	}

	return listedIPs
}

// GetRBLsForIP returns all RBLs that list a specific IP
func (r *RBLChecker) GetRBLsForIP(results *RBLResults, ip string) []string {
	var rbls []string

	if rblChecks, exists := results.Checks[ip]; exists {
		for _, check := range rblChecks {
			if check.Listed {
				rbls = append(rbls, check.Rbl)
			}
		}
	}

	return rbls
}
