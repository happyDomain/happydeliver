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
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

const (
	// mtaSTSMaxPolicySize caps the policy file read (RFC 8461 section 3.3
	// suggests senders do not fetch more than 64 KiB).
	mtaSTSMaxPolicySize = 64 * 1024
	// mtaSTSMaxAge is the largest max_age allowed (RFC 8461 section 3.2).
	mtaSTSMaxAge = 31557600
	// mtaSTSMinRecommendedAge is the shortest max_age worth having: below
	// a week, a policy lapses between two visits of most senders.
	mtaSTSMinRecommendedAge = 604800
)

// mtaSTSID is the shape of the id= of the TXT record: 1 to 32 alphanumerics.
var mtaSTSID = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// parseMTASTSRecord reads the fields of an MTA-STS TXT record.
func parseMTASTSRecord(record string) (id string, err error) {
	fields := map[string]string{}
	for i, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return "", fmt.Errorf("%q is not a key=value field", part)
		}
		if i == 0 && (key != "v" || value != "STSv1") {
			return "", fmt.Errorf("the record must start with v=STSv1")
		}
		fields[key] = value
	}
	id, ok := fields["id"]
	if !ok {
		return "", fmt.Errorf("the id= field is missing")
	}
	if !mtaSTSID.MatchString(id) {
		return id, fmt.Errorf("id=%s is not 1 to 32 letters and digits", id)
	}
	return id, nil
}

// checkMTASTS reads the MTA-STS TXT record of domain, then the policy it
// announces.
func (m *MailPolicyChecker) checkMTASTS(ctx context.Context, domain string) *model.MTASTSResult {
	result := &model.MTASTSResult{Status: model.MTASTSResultStatusAbsent}

	txts, err := m.lookupTXT(ctx, "_mta-sts."+domain)
	if err != nil && !isVoidAnswer(err, 0) {
		result.Status = model.MTASTSResultStatusInvalid
		result.RecordError = utils.PtrTo(fmt.Sprintf("Failed to lookup the TXT record: %s", formatDNSError(err)))
		return result
	}
	var records []string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=STSv1") {
			records = append(records, txt)
		}
	}
	if len(records) == 0 {
		return result
	}

	result.Status = model.MTASTSResultStatusValid
	result.Record = &records[0]
	switch id, err := parseMTASTSRecord(records[0]); {
	case len(records) > 1:
		result.Status = model.MTASTSResultStatusInvalid
		result.RecordError = utils.PtrTo(fmt.Sprintf("%d TXT records start with v=STSv1; senders ignore the policy unless there is exactly one", len(records)))
	case err != nil:
		result.Status = model.MTASTSResultStatusInvalid
		result.RecordError = utils.PtrTo(err.Error())
	default:
		result.Id = &id
	}

	// The policy is fetched whatever the record says: a sender that cached
	// it goes on applying it, so it matters even with a broken record.
	policyURL := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	result.PolicyUrl = &policyURL
	body, err := m.fetchMTASTSPolicy(ctx, policyURL)
	if err != nil {
		result.Status = model.MTASTSResultStatusInvalid
		result.PolicyError = utils.PtrTo(err.Error())
		return result
	}
	result.Policy = &body
	if err := parseMTASTSPolicy(body, result); err != nil {
		result.Status = model.MTASTSResultStatusInvalid
		result.PolicyError = utils.PtrTo(err.Error())
	}
	return result
}

// fetchMTASTSPolicy downloads the policy the way RFC 8461 section 3.3 tells
// senders to: over HTTPS with a valid certificate, without following
// redirects, expecting 200 and text/plain.
func (m *MailPolicyChecker) fetchMTASTSPolicy(ctx context.Context, policyURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		var urlErr interface{ Unwrap() error }
		if errors.As(err, &urlErr) && urlErr.Unwrap() != nil {
			err = urlErr.Unwrap()
		}
		return "", fmt.Errorf("the policy cannot be fetched: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", fmt.Errorf("the policy host answers %d, redirecting to %s, but senders must not follow redirects (RFC 8461 section 3.3)", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the policy host answers %d instead of 200", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/plain" {
		return "", fmt.Errorf("the policy is served as %q, but it must be text/plain", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, mtaSTSMaxPolicySize+1))
	if err != nil {
		return "", fmt.Errorf("the policy cannot be read: %s", err)
	}
	if len(body) > mtaSTSMaxPolicySize {
		return "", fmt.Errorf("the policy is larger than %d bytes", mtaSTSMaxPolicySize)
	}
	return string(body), nil
}

// parseMTASTSPolicy reads the fields of a policy file into result, and tells
// the first reason senders would reject it.
func parseMTASTSPolicy(body string, result *model.MTASTSResult) error {
	var version, mode, maxAge string
	var mx []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("line %q is not a key: value field", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "version":
			version = value
		case "mode":
			mode = value
		case "max_age":
			maxAge = value
		case "mx":
			mx = append(mx, value)
		}
	}
	if len(mx) > 0 {
		result.Mx = &mx
	}
	switch mode {
	case "enforce", "testing", "none":
		result.Mode = utils.PtrTo(model.MTASTSResultMode(mode))
	}
	if age, err := strconv.Atoi(maxAge); err == nil {
		result.MaxAge = &age
	}

	switch {
	case version != "STSv1":
		return fmt.Errorf("the policy must declare version: STSv1")
	case result.Mode == nil:
		return fmt.Errorf("the policy declares no valid mode (enforce, testing or none)")
	case result.MaxAge == nil || *result.MaxAge < 0 || *result.MaxAge > mtaSTSMaxAge:
		return fmt.Errorf("max_age must be a number of seconds between 0 and %d", mtaSTSMaxAge)
	case mode != "none" && len(mx) == 0:
		return fmt.Errorf("the policy lists no mx, so no server can receive mail under it")
	}
	for _, pattern := range mx {
		if !validMXPattern(pattern) {
			return fmt.Errorf("mx: %s is not a hostname nor a *.domain wildcard", pattern)
		}
	}
	return nil
}

// validMXPattern tells whether an mx field of a policy is a hostname, or a
// wildcard on its leftmost label only.
func validMXPattern(pattern string) bool {
	pattern = strings.TrimSuffix(pattern, ".")
	pattern = strings.TrimPrefix(pattern, "*.")
	return isValidHostnameSyntax(pattern) && strings.Contains(pattern, ".")
}

// mxPatternMatches tells whether host is covered by an mx field of a policy:
// equal to it, or, for "*.example.net", one label under example.net
// (RFC 8461 section 4.1).
func mxPatternMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		label, rest, found := strings.Cut(host, ".")
		return found && label != "" && rest == suffix
	}
	return pattern == host
}

// mtaSTSCovers fills the coverage of the MX hosts by the policy, and tells
// the hosts it leaves out.
func mtaSTSCovers(result *model.MTASTSResult, hosts []string) (uncovered []string) {
	if result.Mx == nil || len(hosts) == 0 {
		return nil
	}
	var coverage []model.MTASTSMXCoverage
	for _, host := range hosts {
		entry := model.MTASTSMXCoverage{Host: host}
		for _, pattern := range *result.Mx {
			if mxPatternMatches(pattern, host) {
				entry.Covered = true
				entry.Pattern = utils.PtrTo(pattern)
				break
			}
		}
		if !entry.Covered {
			uncovered = append(uncovered, host)
		}
		coverage = append(coverage, entry)
	}
	result.MxCoverage = &coverage
	return uncovered
}

// Penalties of a broken MTA-STS deployment, in points of the domain test
// score. A policy in enforce mode that leaves an MX out makes senders refuse
// to deliver there, mail they would otherwise have delivered: that is the
// one that really loses mail.
const (
	mtaSTSPenaltyMismatch    = 20
	mtaSTSPenaltyUnreachable = 10
	mtaSTSPenaltyInvalid     = 5
)

// mtaSTSIssues is what the MTA-STS deployment of domain calls for.
func mtaSTSIssues(result *model.MTASTSResult, domain string, hosts []string, charge policyCharge) {
	if result == nil {
		return
	}
	location := "_mta-sts." + domain
	if result.Status == model.MTASTSResultStatusAbsent {
		charge(0, newIssue(model.IssueTypeMtaStsMissing, model.IssueSeverityLow, location,
			fmt.Sprintf("%s publishes no MTA-STS policy, so senders deliver to it over TLS only if nobody strips STARTTLS on the way. Optional: it does not affect the score.", domain),
			fmt.Sprintf(`Serve a policy at https://mta-sts.%s/.well-known/mta-sts.txt ("version: STSv1", "mode: testing", "mx: <your MX hosts>", "max_age: 604800"), then publish _mta-sts.%s IN TXT "v=STSv1; id=<a version id>". Move to mode: enforce once TLS-RPT reports show no failure.`, domain, domain)))
		return
	}

	if result.RecordError != nil {
		charge(mtaSTSPenaltyInvalid, newIssue(model.IssueTypeMtaStsInvalid, model.IssueSeverityHigh, location,
			fmt.Sprintf("The MTA-STS record of %s is not valid: %s.", domain, *result.RecordError),
			`Publish a single TXT record of the form "v=STSv1; id=20240101T000000", changing the id whenever the policy changes.`))
	}

	if result.PolicyError != nil {
		if result.Policy == nil {
			charge(mtaSTSPenaltyUnreachable, newIssue(model.IssueTypeMtaStsPolicyUnreachable, model.IssueSeverityHigh, utils.Deref(result.PolicyUrl),
				fmt.Sprintf("%s announces an MTA-STS policy, but %s.", domain, *result.PolicyError),
				fmt.Sprintf("Serve the policy at %s over HTTPS, with a certificate valid for mta-sts.%s, as text/plain, answering 200 without redirect.", utils.Deref(result.PolicyUrl), domain)))
		} else {
			charge(mtaSTSPenaltyInvalid, newIssue(model.IssueTypeMtaStsPolicyInvalid, model.IssueSeverityHigh, utils.Deref(result.PolicyUrl),
				fmt.Sprintf("Senders reject the MTA-STS policy of %s: %s.", domain, *result.PolicyError),
				"Write the policy as lines of \"key: value\": version: STSv1, mode, max_age and one mx line per MX host or wildcard."))
		}
		return
	}

	if result.MaxAge != nil && *result.MaxAge < mtaSTSMinRecommendedAge && utils.Deref(result.Mode) != model.MTASTSResultModeNone {
		charge(0, newIssue(model.IssueTypeMtaStsMaxAgeShort, model.IssueSeverityMedium, utils.Deref(result.PolicyUrl),
			fmt.Sprintf("The MTA-STS policy of %s is cached for %d seconds only: senders that visit less often than that are not protected.", domain, *result.MaxAge),
			"Set max_age to at least 604800 (a week); RFC 8461 suggests weeks or more once the policy is stable."))
	}

	switch utils.Deref(result.Mode) {
	case model.MTASTSResultModeTesting:
		charge(0, newIssue(model.IssueTypeMtaStsModeTesting, model.IssueSeverityInfo, utils.Deref(result.PolicyUrl),
			"The MTA-STS policy is in testing mode: senders report TLS failures but deliver anyway.",
			"Switch to mode: enforce once the TLS-RPT reports show no failure."))
	case model.MTASTSResultModeNone:
		charge(0, newIssue(model.IssueTypeMtaStsModeTesting, model.IssueSeverityInfo, utils.Deref(result.PolicyUrl),
			"The MTA-STS policy is in mode none: it withdraws a former policy and protects nothing.",
			"Publish mode: testing, then enforce, if you mean to protect delivery to your domain."))
	}

	if uncovered := mtaSTSCovers(result, hosts); len(uncovered) > 0 {
		list := strings.Join(uncovered, ", ")
		advice := fmt.Sprintf("Add an mx line covering %s to the policy, and change the id of the TXT record so that senders fetch it again.", list)
		switch utils.Deref(result.Mode) {
		case model.MTASTSResultModeEnforce:
			result.Status = model.MTASTSResultStatusInvalid
			charge(mtaSTSPenaltyMismatch, newIssue(model.IssueTypeMtaStsMxMismatch, model.IssueSeverityHigh, utils.Deref(result.PolicyUrl),
				fmt.Sprintf("The MTA-STS policy of %s is enforced but does not cover %s: senders applying it refuse to deliver there, so mail routed to these servers is lost or delayed.", domain, list),
				advice))
		case model.MTASTSResultModeTesting:
			charge(0, newIssue(model.IssueTypeMtaStsMxMismatch, model.IssueSeverityMedium, utils.Deref(result.PolicyUrl),
				fmt.Sprintf("The MTA-STS policy of %s does not cover %s: in enforce mode, senders would refuse to deliver there.", domain, list),
				advice))
		}
	}
}

// CheckMTASTS reads the MTA-STS record and policy of domain, for the probes
// of its mail servers, which check every MX against it.
func (m *MailPolicyChecker) CheckMTASTS(ctx context.Context, domain string) *model.MTASTSResult {
	return m.checkMTASTS(ctx, domain)
}

// MTASTSCoversHost tells whether a sound MTA-STS policy covers the MX host.
func MTASTSCoversHost(result *model.MTASTSResult, host string) bool {
	if result == nil || result.Mx == nil {
		return false
	}
	for _, pattern := range *result.Mx {
		if mxPatternMatches(pattern, host) {
			return true
		}
	}
	return false
}
