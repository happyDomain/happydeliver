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
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

// DNSListChecker checks IP addresses against DNS-based block/allow lists.
// It handles both RBL (blacklist) and DNSWL (whitelist) semantics via flags.
type DNSListChecker struct {
	Timeout          time.Duration
	Lists            []string
	CheckAllIPs      bool // Check all IPs found in headers, not just the first one
	filterErrorCodes bool // When true (RBL mode), treat 127.255.255.253/254/255 as operational errors
	resolver         *net.Resolver
	informationalSet map[string]bool // Lists whose hits don't count toward the score
}

// DefaultRBLs is a list of commonly used RBL providers
var DefaultRBLs = []string{
	"zen.spamhaus.org",       // Spamhaus combined list
	"bl.spamcop.net",         // SpamCop
	"dnsbl.sorbs.net",        // SORBS
	"b.barracudacentral.org", // Barracuda
	"cbl.abuseat.org",        // CBL (Composite Blocking List)
	"dnsbl-1.uceprotect.net", // UCEPROTECT Level 1
	"dnsbl-2.uceprotect.net", // UCEPROTECT Level 2 (informational)
	"dnsbl-3.uceprotect.net", // UCEPROTECT Level 3 (informational)
	"psbl.surriel.com",       // PSBL
	"dnsbl.dronebl.org",      // DroneBL
	"bl.mailspike.net",       // Mailspike BL
	"z.mailspike.net",        // Mailspike Z
	"bl.rbl-dns.com",         // RBL-DNS
	"bl.nszones.com",         // NSZones
}

// DefaultInformationalRBLs lists RBLs that are checked but not counted in the score.
// These are typically broader lists where being listed is less definitive.
var DefaultInformationalRBLs = []string{
	"dnsbl-2.uceprotect.net", // UCEPROTECT Level 2: entire netblocks, may cause false positives
	"dnsbl-3.uceprotect.net", // UCEPROTECT Level 3: entire ASes, too broad for scoring
}

// DefaultDNSWLs is a list of commonly used DNSWL providers
var DefaultDNSWLs = []string{
	"list.dnswl.org",   // DNSWL.org — the main DNS whitelist
	"swl.spamhaus.org", // Spamhaus Safe Whitelist
}

// NewRBLChecker creates a new RBL checker with configurable timeout and RBL list
func NewRBLChecker(timeout time.Duration, rbls []string, checkAllIPs bool) *DNSListChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if len(rbls) == 0 {
		rbls = DefaultRBLs
	}
	informationalSet := make(map[string]bool, len(DefaultInformationalRBLs))
	for _, rbl := range DefaultInformationalRBLs {
		informationalSet[rbl] = true
	}
	return &DNSListChecker{
		Timeout:          timeout,
		Lists:            rbls,
		CheckAllIPs:      checkAllIPs,
		filterErrorCodes: true,
		resolver:         &net.Resolver{PreferGo: true},
		informationalSet: informationalSet,
	}
}

// NewDNSWLChecker creates a new DNSWL checker with configurable timeout and DNSWL list
func NewDNSWLChecker(timeout time.Duration, dnswls []string, checkAllIPs bool) *DNSListChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if len(dnswls) == 0 {
		dnswls = DefaultDNSWLs
	}
	return &DNSListChecker{
		Timeout:          timeout,
		Lists:            dnswls,
		CheckAllIPs:      checkAllIPs,
		filterErrorCodes: false,
		resolver:         &net.Resolver{PreferGo: true},
		informationalSet: make(map[string]bool),
	}
}

// DNSListResults represents the results of DNS list checks
type DNSListResults struct {
	Checks              map[string][]api.BlacklistCheck // Map of IP -> list of checks for that IP
	IPsChecked          []string
	ListedCount         int // Total listings including informational entries
	RelevantListedCount int // Listings on scoring (non-informational) lists only
}

// CheckEmail checks all IPs found in the email headers against the configured lists
func (r *DNSListChecker) CheckEmail(email *EmailMessage) *DNSListResults {
	results := &DNSListResults{
		Checks: make(map[string][]api.BlacklistCheck),
	}

	ips := r.extractIPs(email)
	if len(ips) == 0 {
		return results
	}

	results.IPsChecked = ips

	for _, ip := range ips {
		for _, list := range r.Lists {
			check := r.checkIP(ip, list)
			results.Checks[ip] = append(results.Checks[ip], check)
			if check.Listed {
				results.ListedCount++
				if !r.informationalSet[list] {
					results.RelevantListedCount++
				}
			}
		}

		if !r.CheckAllIPs {
			break
		}
	}

	return results
}

// CheckIP checks a single IP address against all configured lists in parallel
func (r *DNSListChecker) CheckIP(ip string) ([]api.BlacklistCheck, int, error) {
	if !r.isPublicIP(ip) {
		return nil, 0, fmt.Errorf("invalid or non-public IP address: %s", ip)
	}

	checks := make([]api.BlacklistCheck, len(r.Lists))
	var wg sync.WaitGroup

	for i, list := range r.Lists {
		wg.Add(1)
		go func(i int, list string) {
			defer wg.Done()
			checks[i] = r.checkIP(ip, list)
		}(i, list)
	}
	wg.Wait()

	listedCount := 0
	for _, check := range checks {
		if check.Listed {
			listedCount++
		}
	}

	return checks, listedCount, nil
}

// extractIPs extracts IP addresses from Received headers
func (r *DNSListChecker) extractIPs(email *EmailMessage) []string {
	var ips []string
	seenIPs := make(map[string]bool)

	receivedHeaders := email.Header["Received"]
	ipv4Pattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	for _, received := range receivedHeaders {
		matches := ipv4Pattern.FindAllString(received, -1)
		for _, match := range matches {
			if !r.isPublicIP(match) {
				continue
			}
			if !seenIPs[match] {
				ips = append(ips, match)
				seenIPs[match] = true
			}
		}
	}

	if len(ips) == 0 {
		originatingIP := email.Header.Get("X-Originating-IP")
		if originatingIP != "" {
			cleanIP := strings.TrimSuffix(strings.TrimPrefix(originatingIP, "["), "]")
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
func (r *DNSListChecker) isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	if ip.IsUnspecified() {
		return false
	}

	return true
}

// checkIP checks a single IP against a single DNS list
func (r *DNSListChecker) checkIP(ip, list string) api.BlacklistCheck {
	check := api.BlacklistCheck{
		Rbl: list,
	}

	reversedIP := r.reverseIP(ip)
	if reversedIP == "" {
		check.Error = api.PtrTo("Failed to reverse IP address")
		return check
	}

	query := fmt.Sprintf("%s.%s", reversedIP, list)

	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				check.Listed = false
				return check
			}
		}
		check.Error = api.PtrTo(fmt.Sprintf("DNS lookup failed: %v", err))
		return check
	}

	if len(addrs) > 0 {
		check.Response = api.PtrTo(addrs[0])

		// In RBL mode, 127.255.255.253/254/255 indicate operational errors, not real listings.
		if r.filterErrorCodes && (addrs[0] == "127.255.255.253" || addrs[0] == "127.255.255.254" || addrs[0] == "127.255.255.255") {
			check.Listed = false
			check.Error = api.PtrTo(fmt.Sprintf("RBL %s returned error code %s (RBL operational issue)", list, addrs[0]))
		} else {
			check.Listed = true
		}
	}

	return check
}

// reverseIP reverses an IPv4 address for DNSBL/DNSWL queries
// Example: 192.0.2.1 -> 1.2.0.192
func (r *DNSListChecker) reverseIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return "" // IPv6 not supported yet
	}

	return fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
}

// CalculateScore calculates the list contribution to deliverability.
// Informational lists are not counted in the score.
func (r *DNSListChecker) CalculateScore(results *DNSListResults, forWhitelist bool) (int, string) {
	scoringListCount := len(r.Lists) - len(r.informationalSet)

	if forWhitelist {
		if results.ListedCount >= scoringListCount {
			return 100, "A++"
		} else if results.ListedCount > 0 {
			return 100, "A+"
		} else {
			return 95, "A"
		}
	}

	if results == nil || len(results.IPsChecked) == 0 {
		return 100, ""
	}

	if results.ListedCount <= 0 {
		return 100, "A+"
	}

	percentage := 100 - results.RelevantListedCount*100/scoringListCount
	return percentage, ScoreToGrade(percentage)
}

// GetUniqueListedIPs returns a list of unique IPs that are listed on at least one entry
func (r *DNSListChecker) GetUniqueListedIPs(results *DNSListResults) []string {
	var listedIPs []string

	for ip, checks := range results.Checks {
		for _, check := range checks {
			if check.Listed {
				listedIPs = append(listedIPs, ip)
				break
			}
		}
	}

	return listedIPs
}

// GetListsForIP returns all lists that match a specific IP
func (r *DNSListChecker) GetListsForIP(results *DNSListResults, ip string) []string {
	var lists []string

	if checks, exists := results.Checks[ip]; exists {
		for _, check := range checks {
			if check.Listed {
				lists = append(lists, check.Rbl)
			}
		}
	}

	return lists
}
