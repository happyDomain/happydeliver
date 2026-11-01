// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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
	"net/url"
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

// dmarcSizeLimit is the optional "!size" suffix a report URI may carry
// (RFC 7489 section 6.2): digits, then a unit.
var dmarcSizeLimit = regexp.MustCompile(`![0-9]+[kKmMgGtT]?$`)

// parseDMARCReportURI tells the domain a mailto: report URI sends reports
// to. Other schemes, which validDMARCReportURI may accept, lead to no domain
// whose consent can be checked.
func parseDMARCReportURI(uri string) (domain string, err error) {
	raw := dmarcSizeLimit.ReplaceAllString(uri, "")
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok || !strings.EqualFold(scheme, "mailto") {
		return "", fmt.Errorf("only mailto: URIs are accepted for DMARC reports")
	}
	addr, err := url.PathUnescape(rest)
	if err != nil {
		return "", fmt.Errorf("malformed percent-encoding")
	}
	if i := strings.IndexByte(addr, '?'); i >= 0 {
		addr = addr[:i]
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", fmt.Errorf("%q is not an email address", addr)
	}
	if strings.ContainsAny(addr[:at], " <>,;\"") {
		return "", fmt.Errorf("%q is not an email address", addr)
	}
	domain = domainname.Normalize(addr[at+1:])
	if !isValidHostnameSyntax(domain) || !strings.Contains(domain, ".") {
		return "", fmt.Errorf("%q is not a valid domain", addr[at+1:])
	}
	return domain, nil
}

// checkDMARCReportDestinations reads the rua= and ruf= tags of a parsed
// record, and asks every destination outside the organizational domain of
// the policy whether it agreed to receive its reports (RFC 7489 section 7.1):
// receivers send nothing to a destination that did not.
func (d *DNSAnalyzer) checkDMARCReportDestinations(rec *model.DMARCRecord, tags map[string]string) {
	policyDomain := domainname.Normalize(utils.Deref(rec.Domain))
	policyOrg := domainname.Organizational(policyDomain)

	var destinations []model.DMARCReportDestination
	authorized := map[string]bool{}
	for _, tag := range []string{"rua", "ruf"} {
		value, ok := tags[tag]
		if !ok {
			continue
		}
		uris := dmarcReportURIs(value)
		if tag == "rua" {
			rec.Rua = &uris
		} else {
			rec.Ruf = &uris
		}
		for _, uri := range uris {
			dest := model.DMARCReportDestination{
				Uri:   uri,
				Tag:   model.DMARCReportDestinationTag(tag),
				Valid: true,
			}
			if !validDMARCReportURI(uri) {
				dest.Valid = false
				dest.Error = utils.PtrTo("not a valid reporting URI")
				destinations = append(destinations, dest)
				continue
			}
			domain, err := parseDMARCReportURI(uri)
			if err != nil {
				destinations = append(destinations, dest)
				continue
			}
			dest.Domain = &domain
			external := policyOrg != "" && domainname.Organizational(domain) != policyOrg
			dest.External = &external
			if external {
				ok, seen := authorized[domain]
				if !seen {
					ok = d.dmarcReportAuthorized(policyDomain, domain)
					authorized[domain] = ok
				}
				dest.Authorized = &ok
			}
			destinations = append(destinations, dest)
		}
	}
	if len(destinations) > 0 {
		rec.ReportAuthorizations = &destinations
	}
}

// dmarcReportAuthorized tells whether destination publishes the record by
// which it accepts the DMARC reports of policyDomain:
// <policyDomain>._report._dmarc.<destination>, starting with v=DMARC1. A
// destination accepting the reports of every domain publishes it under a
// wildcard, which the lookup answers all the same.
func (d *DNSAnalyzer) dmarcReportAuthorized(policyDomain, destination string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txts, err := d.resolver.LookupTXT(ctx, policyDomain+"._report._dmarc."+destination)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.TrimSpace(txt), "v=DMARC1") {
			return true
		}
	}
	return false
}

// dmarcReportIssues is what the reporting set up by a valid policy calls for.
func dmarcReportIssues(c *checkScore, dmarc *model.DMARCRecord, domain string) {
	// Records built before rua= was read carry no list: only a record read
	// here says whether the tag is missing.
	if dmarc.Record != nil && len(utils.Deref(dmarc.Rua)) == 0 {
		c.note(newIssue(model.IssueTypeDmarcNoRua, model.IssueSeverityLow, domain,
			"The DMARC record asks for no aggregate report (no rua= tag): you cannot see who sends mail in your name, nor whether your legitimate mail passes, which is what moving to quarantine or reject safely takes.",
			fmt.Sprintf("Add rua=mailto:<address> to the record at _dmarc.%s, pointing to a mailbox or a DMARC report analysis service.", domain)))
	}

	seen := map[string]bool{}
	for _, dest := range utils.Deref(dmarc.ReportAuthorizations) {
		if !dest.Valid || !utils.Deref(dest.External) || utils.Deref(dest.Authorized) {
			continue
		}
		target := utils.Deref(dest.Domain)
		if seen[target] {
			continue
		}
		seen[target] = true
		c.deduct(5, newIssue(model.IssueTypeDmarcReportUnauthorized, model.IssueSeverityMedium, domain,
			fmt.Sprintf("%s receives reports for %s but has not agreed to: without a TXT record at %s._report._dmarc.%s, receivers send it nothing (RFC 7489 section 7.1).", target, domain, domain, target),
			fmt.Sprintf(`Ask the operator of %s to publish %s._report._dmarc.%s IN TXT "v=DMARC1", or send the reports to an address in your own domain.`, target, domain, target)))
	}
}
