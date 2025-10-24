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

	"git.happydns.org/happyDeliver/internal/api"
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

// Proper reverse DNS (PTR) and forward-confirmed reverse DNS (FCrDNS) is important for deliverability
func (d *DNSAnalyzer) calculatePTRScore(results *api.DNSResults, senderIP string) (score int) {
	if results.PtrRecords != nil && len(*results.PtrRecords) > 0 {
		// 50 points for having PTR records
		score += 50

		if len(*results.PtrRecords) > 1 {
			// Penalty has it's bad to have multiple PTR records
			score -= 15
		}

		// Additional 50 points for forward-confirmed reverse DNS (FCrDNS)
		// This means the PTR hostname resolves back to IPs that include the original sender IP
		if results.PtrForwardRecords != nil && len(*results.PtrForwardRecords) > 0 && senderIP != "" {
			// Verify that the sender IP is in the list of forward-resolved IPs
			fcrDnsValid := false
			for _, forwardIP := range *results.PtrForwardRecords {
				if forwardIP == senderIP {
					fcrDnsValid = true
					break
				}
			}
			if fcrDnsValid {
				score += 50
			}
		}
	}

	return
}
