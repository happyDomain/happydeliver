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
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"

	"git.happydns.org/happyDeliver/pkg/grade"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
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

// ipAddrPatterns match IPv4 and IPv6 candidates in mail headers. Matches are
// confirmed with net.ParseIP before use, so the patterns can be permissive.
//
// The IPv6 pattern (capture group 1 is the candidate):
//   - requires a leading boundary (start-of-string or a non-hex, non-colon
//     character) so it does not carve a spurious address out of the middle of a
//     longer hex token such as "deadbeef:cafe:1::2";
//   - allows the optional "IPv6:" label (any case) used in Received headers,
//     e.g. [IPv6:2001:db8::1];
//   - accepts an optional trailing dotted-quad so IPv4-mapped forms like
//     ::ffff:8.8.8.8 match in full instead of being truncated at the first dot.
var (
	ipv4Pattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	ipv6Pattern = regexp.MustCompile(`(?i)(?:^|[^0-9a-f:])((?:ipv6:)?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}(?:(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})?)`)
)

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

// majorRBLs are the lists most receivers consult: a listing there is
// enough to be refused, which the issue it raises says by its severity.
var majorRBLs = map[string]bool{
	"zen.spamhaus.org":       true,
	"b.barracudacentral.org": true,
	"bl.spamcop.net":         true,
}

// informationalPenalty is what a listing on any informational list costs,
// once, however many of them list the address.
const informationalPenalty = 10

// DefaultDNSWLs is a list of commonly used DNSWL providers
var DefaultDNSWLs = []string{
	"list.dnswl.org",   // DNSWL.org — the main DNS whitelist
	"swl.spamhaus.org", // Spamhaus Safe Whitelist
	"wl.mailspike.net", // Mailspike Whitelist
	"iadb.isipp.com",   // ISIPP Internet Accreditation Database
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
	Checks      map[string][]model.BlacklistCheck // Map of IP -> list of checks for that IP
	IPsChecked  []string
	ListedCount int // Total listings including informational entries
}

// CheckEmail checks all IPs found in the email headers against the configured lists
func (r *DNSListChecker) CheckEmail(email *mailmsg.Message) *DNSListResults {
	results := &DNSListResults{
		Checks: make(map[string][]model.BlacklistCheck),
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
			}
		}

		if !r.CheckAllIPs {
			break
		}
	}

	return results
}

// CheckIP checks a single IP address against all configured lists in parallel
func (r *DNSListChecker) CheckIP(ip string) ([]model.BlacklistCheck, int, error) {
	if !utils.IsPublicIPAddr(ip) {
		return nil, 0, fmt.Errorf("invalid or non-public IP address: %s", ip)
	}

	checks := make([]model.BlacklistCheck, len(r.Lists))
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
func (r *DNSListChecker) extractIPs(email *mailmsg.Message) []string {
	var ips []string
	seenIPs := make(map[string]bool)

	receivedHeaders := email.Header["Received"]

	addIP := func(candidate string) {
		// Strip the "IPv6:" label Received headers use (any case), e.g.
		// [IPv6:2001:db8::1].
		if len(candidate) >= 5 && strings.EqualFold(candidate[:5], "ipv6:") {
			candidate = candidate[5:]
		}
		ip := net.ParseIP(candidate)
		if ip == nil || !utils.IsPublicIPAddr(candidate) {
			return
		}
		// Key on the canonical form so equivalent spellings (e.g. the
		// IPv4-mapped ::ffff:8.8.8.8 and plain 8.8.8.8) dedup to one lookup.
		canonical := ip.String()
		if !seenIPs[canonical] {
			ips = append(ips, canonical)
			seenIPs[canonical] = true
		}
	}

	// ipv6Pattern keeps the candidate in capture group 1 (match[0] also includes
	// the leading boundary character).
	addIPv6Matches := func(s string) {
		for _, m := range ipv6Pattern.FindAllStringSubmatch(s, -1) {
			addIP(m[1])
		}
	}

	for _, received := range receivedHeaders {
		for _, match := range ipv4Pattern.FindAllString(received, -1) {
			addIP(match)
		}
		addIPv6Matches(received)
	}

	if len(ips) == 0 {
		originatingIP := email.Header.Get("X-Originating-IP")
		if originatingIP != "" {
			cleanIP := strings.TrimSuffix(strings.TrimPrefix(originatingIP, "["), "]")
			cleanIP = strings.TrimSpace(cleanIP)
			if match := ipv4Pattern.FindString(cleanIP); match != "" {
				addIP(match)
			} else if m := ipv6Pattern.FindStringSubmatch(cleanIP); m != nil {
				addIP(m[1])
			}
		}
	}

	return ips
}

// checkIP checks a single IP against a single DNS list
func (r *DNSListChecker) checkIP(ip, list string) model.BlacklistCheck {
	check := model.BlacklistCheck{
		Rbl: list,
	}
	if r.informationalSet[list] {
		check.Informational = utils.PtrTo(true)
	}

	reversedIP := r.reverseIP(ip)
	if reversedIP == "" {
		check.Error = utils.PtrTo("Failed to reverse IP address")
		return check
	}

	// Absolute name: a relative one would be retried with the search list
	// of /etc/resolv.conf once the list answers NXDOMAIN, and a wildcard
	// under any of those suffixes would then be read as a listing.
	query := absoluteDNSName(fmt.Sprintf("%s.%s", reversedIP, list))

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
		check.Error = utils.PtrTo(fmt.Sprintf("DNS lookup failed: %v", err))
		return check
	}

	if len(addrs) > 0 {
		check.Response = utils.PtrTo(addrs[0])

		// In RBL mode, 127.255.255.253/254/255 indicate operational errors, not real listings.
		if r.filterErrorCodes && (addrs[0] == "127.255.255.253" || addrs[0] == "127.255.255.254" || addrs[0] == "127.255.255.255") {
			check.Listed = false
			check.Error = utils.PtrTo(fmt.Sprintf("RBL %s returned error code %s (RBL operational issue)", list, addrs[0]))
		} else {
			check.Listed = true
		}
	}

	return check
}

// reverseIP reverses an IPv4 or IPv6 address for DNSBL/DNSWL queries
// Example: 192.0.2.1 -> 1.2.0.192
func (r *DNSListChecker) reverseIP(ipStr string) string {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ""
	}

	return utils.ReverseLabels(ip)
}

// CalculateScore calculates the list contribution to deliverability.
// Informational lists don't count proportionally; instead, if any
// informational list triggers, a flat 10% penalty is applied regardless
// of how many of them fire.
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

	score, _ := r.chargeListings(results)
	if score == 100 {
		return 100, "A+"
	}
	return score, grade.Of(score)
}

// ListingIssues is what the listings of each address checked call for, by
// address, each charged its share of what CalculateScore takes off.
func (r *DNSListChecker) ListingIssues(results *DNSListResults) map[string][]model.Issue {
	_, issues := r.chargeListings(results)
	return issues
}

// chargeListings scores the listings and charges each its share, read off
// the checks themselves. A listing on a scoring list costs its share of the
// 100 points; the first on an informational list costs the flat penalty,
// those after it nothing more.
func (r *DNSListChecker) chargeListings(results *DNSListResults) (int, map[string][]model.Issue) {
	scoringListCount := len(r.Lists) - len(r.informationalSet)
	c := checkScore{score: 100}
	issues := map[string][]model.Issue{}
	if results == nil {
		return c.score, issues
	}

	relevant := 0
	informational := false
	for _, ip := range results.IPsChecked {
		c.issues = nil
		for _, check := range results.Checks[ip] {
			if !check.Listed {
				continue
			}

			if r.informationalSet[check.Rbl] {
				issue := newIssue(model.IssueTypeRblNetworkListed, model.IssueSeverityLow, check.Rbl,
					fmt.Sprintf("%s lists the whole address range or provider of %s, not this address for what it sent. Few receivers use it, but the blacklist score takes a flat penalty for any such listing.", check.Rbl, ip),
					"Nothing to clean up on your side: ask your hosting provider about the listing of its network, or send through a provider with a better-kept network.")
				if informational || scoringListCount <= 0 {
					c.note(issue)
				} else {
					c.deduct(informationalPenalty, issue)
				}
				informational = true
				continue
			}

			severity := model.IssueSeverityHigh
			if majorRBLs[check.Rbl] {
				severity = model.IssueSeverityCritical
			}
			issue := newIssue(model.IssueTypeRblListed, severity, check.Rbl,
				fmt.Sprintf("%s lists %s: receivers that consult it refuse or filter its mail.", check.Rbl, ip),
				"Find out what got the address listed (a compromised account, an open relay, purchased or stale recipient lists), fix it, then request removal from each list. Most lists delist automatically once the cause stops.")
			if scoringListCount <= 0 {
				c.note(issue)
				continue
			}
			// The shares round the way the total does, so they add up to it.
			relevant++
			c.deduct(relevant*100/scoringListCount-(relevant-1)*100/scoringListCount, issue)
		}
		issues[ip] = append([]model.Issue{}, c.issues...)
	}

	return max(c.score, 0), issues
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
