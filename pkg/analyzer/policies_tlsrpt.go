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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// checkTLSRPT reads the SMTP TLS Reporting record of domain (RFC 8460).
func (m *MailPolicyChecker) checkTLSRPT(ctx context.Context, domain string) *model.TLSRPTResult {
	result := &model.TLSRPTResult{Status: model.TLSRPTResultStatusAbsent}

	txts, err := m.lookupTXT(ctx, "_smtp._tls."+domain)
	if err != nil && !isVoidAnswer(err, 0) {
		result.Status = model.TLSRPTResultStatusInvalid
		result.Error = utils.PtrTo(fmt.Sprintf("Failed to lookup the TXT record: %s", formatDNSError(err)))
		return result
	}
	var records []string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=TLSRPTv1") {
			records = append(records, txt)
		}
	}
	if len(records) == 0 {
		return result
	}

	result.Record = &records[0]
	if len(records) > 1 {
		result.Status = model.TLSRPTResultStatusInvalid
		result.Error = utils.PtrTo(fmt.Sprintf("%d TXT records start with v=TLSRPTv1; senders ignore them unless there is exactly one", len(records)))
		return result
	}
	rua, err := parseTLSRPTRecord(records[0])
	if len(rua) > 0 {
		result.Rua = &rua
	}
	if err != nil {
		result.Status = model.TLSRPTResultStatusInvalid
		result.Error = utils.PtrTo(err.Error())
		return result
	}
	result.Status = model.TLSRPTResultStatusValid
	return result
}

// parseTLSRPTRecord reads the rua= of a TLS-RPT record, telling the first
// reason senders would ignore it.
func parseTLSRPTRecord(record string) ([]string, error) {
	var rua []string
	found := false
	for i, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not a key=value field", part)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if i == 0 {
			if key != "v" || value != "TLSRPTv1" {
				return nil, fmt.Errorf("the record must start with v=TLSRPTv1")
			}
			continue
		}
		if key != "rua" {
			continue
		}
		found = true
		for _, uri := range strings.Split(value, ",") {
			if uri = strings.TrimSpace(uri); uri != "" {
				rua = append(rua, uri)
			}
		}
	}
	if !found || len(rua) == 0 {
		return rua, fmt.Errorf("the record has no rua= telling where to send reports")
	}
	for _, uri := range rua {
		if err := validTLSRPTURI(uri); err != nil {
			return rua, fmt.Errorf("%s: %s", uri, err)
		}
	}
	return rua, nil
}

// validTLSRPTURI checks a report destination: a mailto: address or an
// https: URL (RFC 8460 section 3).
func validTLSRPTURI(uri string) error {
	scheme, _, _ := strings.Cut(uri, ":")
	switch strings.ToLower(scheme) {
	case "mailto":
		_, err := parseDMARCReportURI(uri)
		if err != nil {
			return fmt.Errorf("not a valid mailto: address")
		}
		return nil
	case "https":
		u, err := url.Parse(uri)
		if err != nil || u.Host == "" {
			return fmt.Errorf("not a valid https: URL")
		}
		return nil
	default:
		return fmt.Errorf("only mailto: and https: destinations are allowed")
	}
}

// tlsRPTPenaltyInvalid is what a broken TLS-RPT record costs: the reports
// that would warn of delivery failures go nowhere.
const tlsRPTPenaltyInvalid = 5

// tlsRPTIssues is what the TLS-RPT record of domain calls for, knowing the
// MTA-STS policy: reports matter most to who enforces TLS.
func tlsRPTIssues(policies *model.MailPolicies, domain string, charge policyCharge) {
	result := policies.TlsRpt
	if result == nil {
		return
	}
	location := "_smtp._tls." + domain
	switch result.Status {
	case model.TLSRPTResultStatusAbsent:
		enforcing := policies.MtaSts != nil && policies.MtaSts.Status != model.MTASTSResultStatusAbsent
		severity, message := model.IssueSeverityLow,
			fmt.Sprintf("%s publishes no TLS-RPT record, so senders cannot tell you when they fail to deliver to it over TLS. Optional: it does not affect the score.", domain)
		if enforcing {
			severity = model.IssueSeverityMedium
			message = fmt.Sprintf("%s requires TLS from senders (MTA-STS) but publishes no TLS-RPT record: when a certificate or policy problem makes them refuse to deliver, nobody tells you.", domain)
		}
		charge(0, newIssue(model.IssueTypeTlsRptMissing, severity, location, message,
			fmt.Sprintf(`Publish _smtp._tls.%s IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@%s".`, domain, domain)))
	case model.TLSRPTResultStatusInvalid:
		charge(tlsRPTPenaltyInvalid, newIssue(model.IssueTypeTlsRptInvalid, model.IssueSeverityHigh, location,
			fmt.Sprintf("Senders ignore the TLS-RPT record of %s: %s.", domain, utils.Deref(result.Error)),
			`Publish a single TXT record of the form "v=TLSRPTv1; rua=mailto:<address>", with mailto: or https: destinations separated by commas.`))
	}
}
