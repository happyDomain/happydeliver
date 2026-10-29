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
	"slices"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

// checkPTRAndForward performs reverse DNS lookup (PTR) and forward confirmation (A/AAAA)
// Returns PTR hostnames and their corresponding forward-resolved IPs
func (d *DNSAnalyzer) checkPTRAndForward(ip string) ([]string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	// Perform reverse DNS lookup (PTR)
	ptrNames, err := d.resolver.LookupAddr(ctx, ip)
	if err != nil || len(ptrNames) == 0 {
		return nil, nil
	}

	var forwardIPs []string
	seenIPs := make(map[string]bool)

	// For each PTR record, perform forward DNS lookup (A/AAAA)
	for _, ptrName := range ptrNames {
		// Look up A records
		ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
		aRecords, err := d.resolver.LookupHost(ctx, ptrName)
		cancel()

		if err == nil {
			for _, forwardIP := range aRecords {
				if !seenIPs[forwardIP] {
					forwardIPs = append(forwardIPs, forwardIP)
					seenIPs[forwardIP] = true
				}
			}
		}
	}

	return ptrNames, forwardIPs
}

// checkHeloPtrMatch reports whether the announced HELO hostname matches one of
// the sender's PTR records (case-insensitive, trailing dot ignored).
func checkHeloPtrMatch(helo string, ptrRecords []string) bool {
	helo = domainname.Normalize(helo)
	if helo == "" {
		return false
	}
	for _, ptr := range ptrRecords {
		if domainname.Normalize(ptr) == helo {
			return true
		}
	}
	return false
}

// Proper reverse DNS (PTR) and forward-confirmed reverse DNS (FCrDNS) is important for deliverability
func (d *DNSAnalyzer) calculatePTRScore(results *model.DNSResults, senderIP string) (int, []model.Issue) {
	c := checkScore{score: 100}

	if results.PtrRecords == nil || len(*results.PtrRecords) == 0 {
		c.cap(0, newIssue(model.IssueTypePtrMissing, model.IssueSeverityHigh, senderIP,
			fmt.Sprintf("%s has no PTR record pointing to a hostname that resolves back to it. Many receivers reject such mail outright.", senderIP),
			"Ask whoever owns the IP address (your hosting provider or ISP) to set its PTR record to your mail server's hostname, and make sure that hostname resolves back to the same IP."))
		return c.score, c.issues
	}
	ptr := (*results.PtrRecords)[0]

	// Half the points for forward-confirmed reverse DNS (FCrDNS): the PTR
	// hostname resolves back to IPs that include the original sender IP
	fcrDnsValid := false
	if results.PtrForwardRecords != nil && senderIP != "" {
		fcrDnsValid = slices.Contains(*results.PtrForwardRecords, senderIP)
	}
	if !fcrDnsValid {
		c.deduct(50, newIssue(model.IssueTypeFcrdnsMismatch, model.IssueSeverityMedium, ptr,
			fmt.Sprintf("%s does not resolve back to %s.", ptr, senderIP),
			fmt.Sprintf("Add an A or AAAA record for %s pointing to %s, or change the PTR record to a hostname that does.", ptr, senderIP)))
	}

	// Several PTR records leave receivers to pick any of them
	if len(*results.PtrRecords) > 1 {
		c.deduct(15, newIssue(model.IssueTypePtrMultiple, model.IssueSeverityLow, senderIP,
			fmt.Sprintf("%s maps to %d hostnames; receivers may pick any of them.", senderIP, len(*results.PtrRecords)),
			"Keep exactly one PTR record, naming your mail server."))
	}

	// Penalty when the announced HELO name doesn't match the PTR hostname
	if results.HeloPtrMatch != nil && !*results.HeloPtrMatch {
		helo := ""
		if results.HeloHostname != nil {
			helo = *results.HeloHostname
		}
		c.deduct(15, newIssue(model.IssueTypeHeloPtrMismatch, model.IssueSeverityLow, helo,
			fmt.Sprintf("The server announced itself as %s, but %s resolves to %s.", helo, senderIP, strings.Join(*results.PtrRecords, ", ")),
			"Configure your mail server to announce the hostname its PTR record names."))
	}

	return c.score, c.issues
}
