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
	"errors"
	"fmt"
	"net"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// checkMXRecords looks up MX records for a domain. A domain that publishes
// none (NXDOMAIN, or NODATA, which Go reports as not found too) gets an empty
// list; a lookup that failed for another reason gets nil and the failure, for
// the report to tell under lookups rather than charge to the sender.
func (d *DNSAnalyzer) checkMXRecords(domain string) (*[]model.MXRecord, string) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	results := []model.MXRecord{}

	mxRecords, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return &results, ""
		}
		return nil, fmt.Sprintf("Failed to lookup MX records of %s: %s", domain, formatDNSError(err))
	}

	for _, mx := range mxRecords {
		results = append(results, model.MXRecord{
			Host:     mx.Host,
			Priority: mx.Pref,
			Valid:    true,
		})
	}

	return &results, ""
}

// calculateMXScore scores where replies and bounces to the sender domains go,
// half for each. The issues of the From domain and of a Return-Path on
// another domain come apart, as the report shows them on each; a Return-Path
// on the From domain is that domain's to answer for, both halves of it.
func (d *DNSAnalyzer) calculateMXScore(results *model.DNSResults) (int, []model.Issue, []model.Issue) {
	c := checkScore{score: 100}

	var reachFrom, reachRP *model.ReturnOKDomain
	if results.ReturnOk != nil {
		reachFrom, reachRP = results.ReturnOk.From, results.ReturnOk.ReturnPath
	}

	// The Return-Path domain only has records of its own when it is another
	// domain; otherwise it stands or falls with the From domain.
	rpChecked := results.RpMxRecords != nil && len(*results.RpMxRecords) > 0
	rpElsewhere := results.RpDomain != nil && *results.RpDomain != "" && *results.RpDomain != results.FromDomain

	fromPoints, lost := 50, "replies"
	if !rpChecked && !rpElsewhere {
		fromPoints = 100
		if results.RpDomain != nil && *results.RpDomain != "" {
			lost = "replies and bounces"
		}
	}
	mxIssues(&c, results.FromDomain, results.FromMxRecords, reachFrom, fromPoints, lost)
	fromIssues := c.issues

	c.issues = nil
	if rpChecked || rpElsewhere {
		mxIssues(&c, utils.Deref(results.RpDomain), results.RpMxRecords, reachRP, 50, "bounces")
	}

	return c.score, fromIssues, c.issues
}

// mxIssues charges points to what keeps a domain from receiving mail, if
// anything does; lost names what goes there.
func mxIssues(c *checkScore, domain string, records *[]model.MXRecord, reach *model.ReturnOKDomain, points int, lost string) {
	var valid bool
	var invalid []string
	if records != nil {
		for _, mx := range *records {
			if mx.Valid {
				valid = true
				continue
			}
			bad := mx.Host
			if mx.Error != nil {
				bad += ": " + *mx.Error
			}
			invalid = append(invalid, bad)
		}
	}
	if valid {
		points = 0
	}
	// The lookup failed: what the domain publishes is unknown, and the failure
	// is told under lookups. Only a domain found with no way to receive mail
	// at all is still charged, on the lookups of its own check.
	if records == nil && (reach == nil || reach.Status != returnOKStatusFail) {
		return
	}
	publish := fmt.Sprintf("Publish an MX record for %s pointing to a server that accepts mail.", domain)

	switch {
	case reach != nil && reach.Status == returnOKStatusFail:
		c.deduct(points, newIssue(model.IssueTypeDomainUnreachable, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s has neither MX nor A/AAAA record: %s to it are lost, and receivers treat such senders as suspicious.", domain, lost),
			publish))
	case len(invalid) == 0 && !valid:
		message := fmt.Sprintf("%s publishes no MX record, so %s to it have nowhere to go.", domain, lost)
		if reach != nil && reach.Status == returnOKStatusWarn {
			message = fmt.Sprintf("%s publishes no MX record and relies on its A/AAAA record as an implicit MX for %s.", domain, lost)
			// Mail still finds its way there, as receivers accept an implicit
			// MX: only the missing record is charged, a quarter of the points.
			points /= 4
		}
		c.deduct(points, newIssue(model.IssueTypeMxMissing, model.IssueSeverityLow, domain, message, publish))
	case !valid:
		c.deduct(points, newIssue(model.IssueTypeMxInvalid, model.IssueSeverityHigh, domain,
			fmt.Sprintf("No MX record of %s leads to a server: %s.", domain, strings.Join(invalid, "; ")),
			"Make every MX record point to a hostname that resolves to a server accepting mail."))
	case len(invalid) > 0:
		c.note(newIssue(model.IssueTypeMxInvalid, model.IssueSeverityMedium, domain,
			fmt.Sprintf("Some MX records of %s are invalid: %s.", domain, strings.Join(invalid, "; ")),
			"Make every MX record point to a hostname that resolves to a server accepting mail."))
	}
}
