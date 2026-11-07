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
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

var dmarcPolicyStrength = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

// errMultipleDMARCRecords says a domain publishes several DMARC records: policy
// discovery stops there and none of them applies (RFC 7489 section 6.6.3).
var errMultipleDMARCRecords = errors.New("multiple DMARC records")

// dmarcMultipleRecordsError is what a record reports for that error.
const dmarcMultipleRecordsError = "Multiple DMARC records found, so receivers apply none of them"

// lookupDMARCAt queries _dmarc.<domain> and returns the raw DMARC1 TXT record.
// notFound=true means no record exists (NXDOMAIN or empty); false means a real DNS error occurred.
// With errMultipleDMARCRecords, the first of them is returned along.
func (d *DNSAnalyzer) lookupDMARCAt(domain string) (record string, notFound bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, lookupErr := d.resolver.LookupTXT(ctx, fmt.Sprintf("_dmarc.%s", domain))
	if lookupErr != nil {
		if dnsErr, ok := lookupErr.(*net.DNSError); ok && dnsErr.IsNotFound {
			return "", true, nil
		}
		return "", false, lookupErr
	}

	var records []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			records = append(records, txt)
		}
	}
	switch len(records) {
	case 0:
		return "", true, nil
	case 1:
		return records[0], false, nil
	default:
		return records[0], false, errMultipleDMARCRecords
	}
}

// parseDMARCTags splits a DMARC record into a tag→value map. Unlike DKIM's, its
// tag names and keywords ignore case; the reporting URIs keep theirs.
func parseDMARCTags(record string) map[string]string {
	tags := make(map[string]string)
	for name, value := range parseDKIMTags(record) {
		name = strings.ToLower(name)
		if name != "rua" && name != "ruf" {
			value = strings.ToLower(value)
		}
		tags[name] = value
	}
	return tags
}

// duplicateDMARCTag returns the first tag a record holds twice, or "". Such a
// tag list is invalid as a whole (RFC 6376 section 3.2, which DMARC takes it
// from).
func duplicateDMARCTag(record string) string {
	seen := make(map[string]bool)
	for _, part := range strings.Split(record, ";") {
		name, _, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if seen[name] {
			return name
		}
		seen[name] = true
	}
	return ""
}

// dmarcReportURI is the shape of a reporting URI: a scheme, what follows it, and
// the size limit RFC 7489 section 6.2 allowed after a "!".
var dmarcReportURI = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*:[^\s!]+)(![0-9]+[kKmMgGtT]?)?$`)

// validDMARCReportURI reports whether uri can receive reports: a syntactically
// valid URI, holding an address when it is a mailto: one.
func validDMARCReportURI(uri string) bool {
	match := dmarcReportURI.FindStringSubmatch(uri)
	if match == nil {
		return false
	}

	parsed, err := url.Parse(match[1])
	if err != nil {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "mailto") {
		local, domain, found := strings.Cut(parsed.Opaque, "@")
		return found && local != "" && domain != ""
	}
	return true
}

// dmarcReportURIs splits the comma-separated value of a rua= or ruf= tag.
func dmarcReportURIs(value string) []string {
	var uris []string
	for _, uri := range strings.Split(value, ",") {
		if uri = strings.TrimSpace(uri); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

// invalidDMARCReportURIs returns the entries of rua= and ruf= that cannot
// receive reports.
func invalidDMARCReportURIs(tags map[string]string) (invalid []string) {
	for _, tag := range []string{"rua", "ruf"} {
		for _, uri := range dmarcReportURIs(tags[tag]) {
			if !validDMARCReportURI(uri) {
				invalid = append(invalid, uri)
			}
		}
	}
	return invalid
}

// parseDMARCRecord parses a raw DMARC TXT record into a DMARCRecord model.
func (d *DNSAnalyzer) parseDMARCRecord(foundDomain, rawRecord string) *model.DMARCRecord {
	tags := parseDMARCTags(rawRecord)

	// Policy
	policy := "unknown"
	switch tags["p"] {
	case "none", "quarantine", "reject":
		policy = tags["p"]
	}

	// SPF alignment (default: relaxed)
	spfAlignment := utils.PtrTo(model.DMARCRecordSpfAlignmentRelaxed)
	if tags["aspf"] == "s" {
		spfAlignment = utils.PtrTo(model.DMARCRecordSpfAlignmentStrict)
	}

	// DKIM alignment (default: relaxed)
	dkimAlignment := utils.PtrTo(model.DMARCRecordDkimAlignmentRelaxed)
	if tags["adkim"] == "s" {
		dkimAlignment = utils.PtrTo(model.DMARCRecordDkimAlignmentStrict)
	}

	// Subdomain policy
	var subdomainPolicy *model.DMARCRecordSubdomainPolicy
	switch tags["sp"] {
	case "none", "quarantine", "reject":
		subdomainPolicy = utils.PtrTo(model.DMARCRecordSubdomainPolicy(tags["sp"]))
	}

	// Non-existent subdomain policy (DMARCbis np=)
	var nonexistentSubdomainPolicy *model.DMARCRecordNonexistentSubdomainPolicy
	switch tags["np"] {
	case "none", "quarantine", "reject":
		nonexistentSubdomainPolicy = utils.PtrTo(model.DMARCRecordNonexistentSubdomainPolicy(tags["np"]))
	}

	// Percentage (pct=, deprecated in DMARCbis)
	var percentage *int
	if pctStr, ok := tags["pct"]; ok {
		if pct, err := strconv.Atoi(pctStr); err == nil && pct >= 0 && pct <= 100 {
			percentage = &pct
		}
	}

	// Test mode (DMARCbis t=)
	var testMode *bool
	if t, ok := tags["t"]; ok {
		v := t == "y"
		testMode = &v
	}

	// PSD (DMARCbis psd=)
	var psd *model.DMARCRecordPsd
	switch tags["psd"] {
	case "y", "n", "u":
		psd = utils.PtrTo(model.DMARCRecordPsd(tags["psd"]))
	}

	rec := &model.DMARCRecord{
		Domain:                     &foundDomain,
		Record:                     &rawRecord,
		Policy:                     utils.PtrTo(model.DMARCRecordPolicy(policy)),
		SubdomainPolicy:            subdomainPolicy,
		NonexistentSubdomainPolicy: nonexistentSubdomainPolicy,
		Percentage:                 percentage,
		TestMode:                   testMode,
		Psd:                        psd,
		SpfAlignment:               spfAlignment,
		DkimAlignment:              dkimAlignment,
	}
	if percentage != nil {
		rec.DeprecatedPct = utils.PtrTo(true)
	}
	if _, ok := tags["rf"]; ok {
		rec.DeprecatedRf = utils.PtrTo(true)
	}
	if _, ok := tags["ri"]; ok {
		rec.DeprecatedRi = utils.PtrTo(true)
	}

	if invalid := invalidDMARCReportURIs(tags); len(invalid) > 0 {
		rec.InvalidReportUris = &invalid
	}

	if tag := duplicateDMARCTag(rawRecord); tag != "" {
		rec.Valid = false
		rec.Error = utils.PtrTo(fmt.Sprintf("The %s= tag appears more than once, so receivers ignore the record", tag))
		return rec
	}

	if !d.validateDMARC(rawRecord) {
		rec.Valid = false
		rec.Error = utils.PtrTo("DMARC record appears malformed")
		if problem := dmarcPolicyProblem(tags); problem != "" {
			rec.Error = utils.PtrTo(fmt.Sprintf("%s and rua= holds no valid address, so receivers ignore the record", problem))
		}
		return rec
	}

	rec.Valid = true
	if _, hasPolicy := tags["p"]; !hasPolicy {
		rec.Policy = utils.PtrTo(model.DMARCRecordPolicy("none"))
	}
	if problem := dmarcPolicyProblem(tags); problem != "" {
		rec.Policy = utils.PtrTo(model.DMARCRecordPolicy("none"))
		rec.Error = utils.PtrTo(fmt.Sprintf("%s, so receivers treat the record as p=none", problem))
	}
	return rec
}

// walkDNSForDMARC implements the DMARCbis DNS Tree Walk algorithm (Section 4.10).
// It queries _dmarc.<domain> and walks up the label hierarchy until a valid DMARC
// record is found or all labels are exhausted. Maximum 8 DNS queries per message.
// For domains with ≥8 labels, after the initial miss the walk jumps to the 7-label
// suffix before resuming normally (to stay within the 8-query budget).
// Single-label (TLD) records are only accepted when they carry psd=y.
func (d *DNSAnalyzer) walkDNSForDMARC(domain string) (record, foundDomain string, err error) {
	labels := strings.Split(domainname.Normalize(domain), ".")
	n := len(labels)

	for i, queries := 0, 0; i < n && queries < 8; i, queries = i+1, queries+1 {
		current := strings.Join(labels[i:], ".")

		raw, notFound, lookupErr := d.lookupDMARCAt(current)
		if errors.Is(lookupErr, errMultipleDMARCRecords) {
			return raw, current, lookupErr
		}
		if lookupErr != nil {
			return "", "", lookupErr
		}
		if !notFound {
			// Single-label (TLD) records are only used when the record explicitly opts in.
			if !strings.Contains(current, ".") {
				if d.extractDMARCPSDValue(raw) != "y" {
					break
				}
			}
			return raw, current, nil
		}

		// DMARCbis §4.10: after missing on a ≥8-label domain, shortcut to the
		// 7-label suffix for the next query rather than stepping one label at a time.
		if i == 0 && n >= 8 {
			i = n - 8 // the outer i++ will land at n-7 (7 labels from the right)
		}
	}

	return "", "", nil
}

// checkDMARCRecord looks up and validates the DMARC record for a domain using
// the DMARCbis DNS Tree Walk algorithm (Section 4.10), which supersedes the
// RFC 7489 PSL-based organizational domain lookup and the RFC 9091 PSD DMARC
// experimental fallback.
func (d *DNSAnalyzer) checkDMARCRecord(domain string) *model.DMARCRecord {
	raw, foundDomain, err := d.walkDNSForDMARC(domain)
	if errors.Is(err, errMultipleDMARCRecords) {
		return &model.DMARCRecord{
			Domain: &foundDomain,
			Record: &raw,
			Valid:  false,
			Error:  utils.PtrTo(dmarcMultipleRecordsError),
		}
	}
	if err != nil {
		return &model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo(fmt.Sprintf("Failed to lookup DMARC record: %s", formatDNSError(err))),
		}
	}
	if foundDomain == "" {
		return &model.DMARCRecord{
			Valid: false,
			Error: utils.PtrTo("No DMARC record found"),
		}
	}
	return d.parseDMARCRecord(foundDomain, raw)
}

// extractDMARCPSDValue returns the raw psd= value ("y", "n", "u") or "" if absent.
// Used during DNS Tree Walk before full record parsing.
func (d *DNSAnalyzer) extractDMARCPSDValue(record string) string {
	v := parseDMARCTags(record)["psd"]
	switch v {
	case "y", "n", "u":
		return v
	}
	return ""
}

// dmarcPolicyProblem says what is wrong with the policies of a record, or "" if
// they are fine. A record without p= has no problem of its own: see validateDMARC.
func dmarcPolicyProblem(tags map[string]string) string {
	for _, tag := range []string{"p", "sp"} {
		if value, found := tags[tag]; found {
			if _, known := dmarcPolicyStrength[value]; !known {
				return fmt.Sprintf("%s=%s is not a DMARC policy", tag, value)
			}
		}
	}
	return ""
}

// hasValidDMARCReportURI reports whether rua= holds a URI that can receive reports.
func hasValidDMARCReportURI(tags map[string]string) bool {
	return slices.ContainsFunc(dmarcReportURIs(tags["rua"]), validDMARCReportURI)
}

// validateDMARC performs basic DMARC record validation.
// A record with no p= tag, or with an invalid p= or sp= tag, only stands on a
// valid rua=, which makes it a p=none record (RFC 7489 section 6.6.3; DMARCbis
// makes p= RECOMMENDED, not required).
func (d *DNSAnalyzer) validateDMARC(record string) bool {
	if !strings.HasPrefix(record, "v=DMARC1") {
		return false
	}

	tags := parseDMARCTags(record)
	if _, hasPolicy := tags["p"]; !hasPolicy || dmarcPolicyProblem(tags) != "" {
		return hasValidDMARCReportURI(tags)
	}

	return true
}

// calculateDMARCScore scores the DMARC policy of the From domain. A sound
// policy earns bonuses taking it above 100, which the issues are not charged
// for: each costs what it takes from the check's 100 points.
func (d *DNSAnalyzer) calculateDMARCScore(results *model.DNSResults) (int, []model.Issue) {
	dmarc := results.DmarcRecord
	domain := results.FromDomain
	if dmarc != nil && dmarc.Domain != nil && *dmarc.Domain != "" {
		domain = *dmarc.Domain
	}

	if dmarc == nil || !dmarc.Valid {
		c := checkScore{score: 100}
		if dmarc == nil || dmarc.Record == nil {
			c.cap(0, newIssue(model.IssueTypeDmarcMissing, model.IssueSeverityHigh, domain,
				fmt.Sprintf("%s publishes no DMARC policy. Gmail and Yahoo require one from bulk senders.", domain),
				fmt.Sprintf(`Publish a TXT record at _dmarc.%s, starting with "v=DMARC1; p=none; rua=mailto:<address>" to collect reports, then move to p=quarantine and p=reject once all your mail passes.`, domain)))
		} else {
			// Partial credit if a DMARC record exists but has issues
			message := "Receivers cannot parse the DMARC record and ignore it."
			if dmarc.Error != nil {
				message = *dmarc.Error
			}
			advice := "Fix the syntax of the record: it must start with v=DMARC1, and give each tag once."
			if message == dmarcMultipleRecordsError {
				advice = fmt.Sprintf("Keep a single DMARC record at _dmarc.%s.", domain)
			}
			c.cap(20, newIssue(model.IssueTypeDmarcInvalid, model.IssueSeverityHigh, domain, message, advice))
		}
		return c.score, c.issues
	}

	// The best policy is worth 105, then strict alignment modes add 5 each.
	c := checkScore{score: 105}
	if dmarc.SpfAlignment != nil && *dmarc.SpfAlignment == model.DMARCRecordSpfAlignmentStrict {
		c.score += 5
	}
	if dmarc.DkimAlignment != nil && *dmarc.DkimAlignment == model.DMARCRecordDkimAlignmentStrict {
		c.score += 5
	}

	// What the policy costs, as published: reject earns 25, none loses 25.
	policy := "none"
	if dmarc.Policy != nil {
		policy = string(*dmarc.Policy)
	}
	switch policy {
	case "quarantine":
		c.deduct(25, newIssue(model.IssueTypeDmarcPolicyQuarantine, model.IssueSeverityLow, domain,
			"p=quarantine sends failing mail to spam; p=reject is the strongest protection.",
			"Move to p=reject once you are confident all your legitimate mail passes."))
	case "none":
		c.deduct(50, newIssue(model.IssueTypeDmarcPolicyNone, model.IssueSeverityLow, domain,
			"Mail failing DMARC is delivered as usual, so your domain is not protected from spoofing.",
			"Once the aggregate reports show all your legitimate mail passing, move to p=quarantine, then p=reject."))
	}

	// DMARCbis t=y downgrades the policy one level, which costs what that
	// level is worth on top. p=none has no level below: t=y changes nothing
	// there, and removing it would bring nothing back.
	effectivePolicy := policy
	if dmarc.TestMode != nil && *dmarc.TestMode {
		points := 0
		switch policy {
		case "reject":
			effectivePolicy, points = "quarantine", 25
		case "quarantine":
			effectivePolicy, points = "none", 25
		}
		if points > 0 {
			c.deduct(points, newIssue(model.IssueTypeDmarcTestMode, model.IssueSeverityMedium, domain,
				"Receivers apply your policy one level softer than published.",
				"Remove t=y once you are confident all your legitimate mail passes."))
		}
	}

	// Subdomain policy (sp tag): one weaker than the policy in effect costs 30
	effectiveSubPolicy := effectivePolicy
	if dmarc.SubdomainPolicy != nil {
		effectiveSubPolicy = string(*dmarc.SubdomainPolicy)
		if dmarcPolicyStrength[effectiveSubPolicy] < dmarcPolicyStrength[effectivePolicy] {
			c.deduct(30, newIssue(model.IssueTypeDmarcSpWeaker, model.IssueSeverityLow, domain,
				fmt.Sprintf("sp=%s is weaker than the %s policy applied to the domain.", effectiveSubPolicy, effectivePolicy),
				fmt.Sprintf("Set sp=%s, or remove sp= so subdomains inherit the main policy.", policy)))
		}
	}

	// Non-existent subdomain policy (np tag, DMARCbis): same, against the subdomain policy
	if dmarc.NonexistentSubdomainPolicy != nil {
		np := string(*dmarc.NonexistentSubdomainPolicy)
		if dmarcPolicyStrength[np] < dmarcPolicyStrength[effectiveSubPolicy] {
			c.deduct(30, newIssue(model.IssueTypeDmarcNpWeaker, model.IssueSeverityLow, domain,
				fmt.Sprintf("np=%s is weaker than the %s policy applied to existing subdomains, though spoofing a subdomain that does not exist is the easier attack.", np, effectiveSubPolicy),
				fmt.Sprintf("Set np=%s, or remove np= so they inherit it.", effectiveSubPolicy)))
		}
	}

	// pct= scaling (deprecated in DMARCbis, kept for backward compatibility).
	// pct=0 is an anti-pattern: score it as zero enforcement.
	if dmarc.Percentage != nil && *dmarc.Percentage < 100 {
		pct := *dmarc.Percentage
		c.cap(c.score*pct/100, newIssue(model.IssueTypeDmarcPct, model.IssueSeverityMedium, domain,
			fmt.Sprintf("The policy applies to %d%% of failing mail; the rest is treated as if the policy were one level softer. The pct= tag is also removed in DMARCbis.", pct),
			"Remove pct= to apply the policy to all mail; use t=y instead if you need a test phase."))
	} else if dmarc.DeprecatedPct != nil && *dmarc.DeprecatedPct {
		c.note(newIssue(model.IssueTypeDmarcPctDeprecated, model.IssueSeverityInfo, domain,
			"pct=100 is the default and DMARCbis removes the tag.",
			"Remove pct= from the record."))
	}

	// A policy that does not exist, which rua= saved from being ignored: what
	// p=none costs is already charged, and it does not say why.
	if dmarc.Error != nil {
		c.note(newIssue(model.IssueTypeDmarcInvalid, model.IssueSeverityMedium, domain,
			fmt.Sprintf("%s.", *dmarc.Error),
			"Set p= and sp= to none, quarantine or reject."))
	}

	if dmarc.InvalidReportUris != nil && len(*dmarc.InvalidReportUris) > 0 {
		c.note(newIssue(model.IssueTypeDmarcReportUriInvalid, model.IssueSeverityLow, domain,
			fmt.Sprintf("Receivers cannot send reports to %s: it is not a valid reporting URI.", strings.Join(*dmarc.InvalidReportUris, ", ")),
			"Write each address as a URI, such as rua=mailto:dmarc@example.com, and separate them with commas."))
	}

	var deprecated []string
	if dmarc.DeprecatedRf != nil && *dmarc.DeprecatedRf {
		deprecated = append(deprecated, "rf=")
	}
	if dmarc.DeprecatedRi != nil && *dmarc.DeprecatedRi {
		deprecated = append(deprecated, "ri=")
	}
	if len(deprecated) > 0 {
		tags := strings.Join(deprecated, " and ")
		c.note(newIssue(model.IssueTypeDmarcDeprecatedTags, model.IssueSeverityInfo, domain,
			fmt.Sprintf("The record uses %s, which DMARCbis removes and receivers ignore.", tags),
			fmt.Sprintf("Remove %s from the record.", tags)))
	}

	return c.score, c.issues
}
