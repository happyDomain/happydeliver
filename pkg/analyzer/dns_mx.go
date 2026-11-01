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
	"git.happydns.org/happyDeliver/pkg/netguard"
)

// nullMXHost is the target of a null MX, by which a domain declares that it
// accepts no mail at all (RFC 7505).
const nullMXHost = "."

// isNullMX reports whether records are an RFC 7505 null MX: a single record
// whose target is the root. Written beside real MX records, it is no null MX,
// just an invalid record.
func isNullMX(records []*net.MX) bool {
	return len(records) == 1 && records[0] != nil && records[0].Host == nullMXHost
}

// checkMXRecords looks up MX records for a domain, and where each of them
// leads: an RFC 7505 null MX is reported as such and leads nowhere; any other
// target must be a hostname, ideally not an alias, resolving to addresses a
// sender can reach. A domain that publishes none (NXDOMAIN, or NODATA, which
// Go reports as not found too) gets an empty list; a lookup that failed for
// another reason gets nil and the failure, for the report to tell under
// lookups rather than charge to the sender.
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

	if isNullMX(mxRecords) {
		// The domain says it accepts no mail: there is no target to look up.
		results = append(results, model.MXRecord{
			Host:     nullMXHost,
			Priority: mxRecords[0].Pref,
			Valid:    false,
			Error:    utils.PtrTo("Null MX: the domain accepts no mail"),
			NullMx:   utils.PtrTo(true),
		})
		return &results, ""
	}

	for _, mx := range mxRecords {
		results = append(results, d.checkMXTarget(ctx, mx))
	}

	return &results, ""
}

// checkMXTarget looks at where one MX record leads.
func (d *DNSAnalyzer) checkMXTarget(ctx context.Context, mx *net.MX) model.MXRecord {
	rec := model.MXRecord{
		Host:     mx.Host,
		Priority: mx.Pref,
		Valid:    true,
	}
	host := strings.TrimSuffix(mx.Host, ".")

	// RFC 5321 section 5.1: the target is a domain name, never an address
	if net.ParseIP(host) != nil {
		rec.Valid = false
		rec.Error = utils.PtrTo(fmt.Sprintf("%s is an IP address, but an MX record must point to a hostname (RFC 5321 section 5.1)", host))
		return rec
	}
	if mx.Host == nullMXHost {
		rec.Valid = false
		rec.Error = utils.PtrTo("Null MX beside other MX records: RFC 7505 only allows it alone")
		return rec
	}
	if host == "" {
		rec.Valid = false
		rec.Error = utils.PtrTo("Empty MX target")
		return rec
	}

	if cr, ok := d.resolver.(cnameResolver); ok {
		if canonical, err := cr.LookupCNAME(ctx, host); err == nil {
			canonical = strings.TrimSuffix(canonical, ".")
			if canonical != "" && !strings.EqualFold(canonical, host) {
				rec.CnameTarget = &canonical
			}
		}
	}

	addrs, err := d.resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		rec.Valid = false
		reason := "it has no A or AAAA record"
		if err != nil {
			reason = formatDNSError(err)
		}
		rec.Error = utils.PtrTo(fmt.Sprintf("%s does not resolve to any address: %s", host, reason))
		return rec
	}
	rec.Addresses = &addrs

	var private []string
	for _, a := range addrs {
		if !d.isPublicAddr(a) {
			private = append(private, a)
		}
	}
	switch {
	case len(private) == len(addrs):
		rec.Valid = false
		rec.Error = utils.PtrTo(fmt.Sprintf("%s only resolves to addresses not routable on the Internet (%s)", host, strings.Join(private, ", ")))
	case len(private) > 0:
		// Still usable through its other addresses, but senders trying
		// these first waste their time.
		rec.Error = utils.PtrTo(fmt.Sprintf("%s also resolves to addresses not routable on the Internet (%s)", host, strings.Join(private, ", ")))
	}

	return rec
}

// isPublicAddr tells whether a sender on the Internet could reach addr.
func (d *DNSAnalyzer) isPublicAddr(addr string) bool {
	if d.publicAddr != nil {
		return d.publicAddr(net.ParseIP(addr))
	}
	return netguard.IsPublicString(addr)
}

// isNullMXRecords reports whether records are what checkMXRecords makes of
// an RFC 7505 null MX.
func isNullMXRecords(records *[]model.MXRecord) bool {
	return records != nil && len(*records) == 1 && (*records)[0].Host == nullMXHost
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
	var invalid, partial, aliases []string
	hasIPv6, resolved := false, false
	if records != nil {
		for _, mx := range *records {
			if mx.Addresses != nil {
				resolved = true
				for _, a := range *mx.Addresses {
					if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
						hasIPv6 = true
					}
				}
			}
			if mx.CnameTarget != nil {
				aliases = append(aliases, fmt.Sprintf("%s → %s", strings.TrimSuffix(mx.Host, "."), *mx.CnameTarget))
			}
			if mx.Valid {
				valid = true
				if mx.Error != nil {
					partial = append(partial, *mx.Error)
				}
				continue
			}
			bad := mx.Host
			if mx.Error != nil {
				bad = *mx.Error
				if mx.Host != "" && !strings.Contains(*mx.Error, strings.TrimSuffix(mx.Host, ".")) {
					bad = mx.Host + ": " + *mx.Error
				}
			}
			invalid = append(invalid, bad)
		}
	}
	full := points
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
	case isNullMXRecords(records):
		c.deduct(points, newIssue(model.IssueTypeMxNull, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s publishes a null MX, declaring that it accepts no mail: %s to it are lost, and receivers may refuse mail sent from it.", domain, lost),
			fmt.Sprintf("Replace the null MX of %s with an MX record pointing to a server that accepts mail, or send from another domain.", domain)))
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

	if len(partial) > 0 {
		c.note(newIssue(model.IssueTypeMxInvalid, model.IssueSeverityMedium, domain,
			fmt.Sprintf("Some MX targets of %s cannot be reached from the Internet: %s.", domain, strings.Join(partial, "; ")),
			"Remove the private, loopback or reserved addresses from the A/AAAA records of your MX hosts."))
	}

	if len(aliases) > 0 {
		// Forbidden, but most senders follow the alias anyway: a warning
		// costing a tenth of the check, not a failure.
		c.deduct(full/10, newIssue(model.IssueTypeMxCname, model.IssueSeverityMedium, domain,
			fmt.Sprintf("MX records of %s point to aliases (%s), which RFC 5321 section 5.1 and RFC 2181 section 10.3 forbid: some senders refuse to follow them.", domain, strings.Join(aliases, ", ")),
			"Point each MX record directly to the canonical hostname of the server, the one with the A/AAAA records."))
	}

	if valid && resolved && !hasIPv6 {
		c.note(newIssue(model.IssueTypeMxNoIpv6, model.IssueSeverityInfo, domain,
			fmt.Sprintf("No MX target of %s has an IPv6 address, so senders reachable only over IPv6 cannot deliver to it.", domain),
			"Publish AAAA records for your MX hosts if your servers have IPv6 connectivity."))
	}
}
