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
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/utils"
)

// ScannerMicrosoft365 is Microsoft 365 (Exchange Online Protection), filtering
// what its tenants send and receive.
const ScannerMicrosoft365 SpamScanner = "microsoft365"

func init() {
	registerUpstreamSpamVerdictFilter(upstreamSpamVerdictFilter{
		profile: spamScannerProfile{
			scanner: ScannerMicrosoft365,
			// Exchange Online Protection stamps its verdict on every message it
			// filters, those its tenants send included. The "-Untrusted" copies
			// it also writes are left out: Microsoft itself marks them as not to
			// be relied on.
			ownHeaders: []string{
				"X-Forefront-Antispam-Report",
				"X-Microsoft-Antispam",
			},
		},
		name:    "Microsoft 365",
		analyze: analyzeMicrosoft365Verdict,
	})
}

// microsoft365Details is what Microsoft 365 stamped on the message, as the web
// interface shows it.
//
// The fields and their values are those Microsoft documents in "Anti-spam
// message headers":
// https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
type microsoft365Details struct {
	// IsSpam tells whether Microsoft 365 classified the message as spam,
	// phishing, spoofing, impersonation or malware, by its CAT or its SFV.
	// Bulk mail is not spam: the BCL, the CAT and SRV:BULK tell it instead.
	// The verdict carries it.
	IsSpam bool `json:"-"`

	// Direction is whether Microsoft 365 filtered the message on its way out
	// of a tenant (DIR:OUT), into one (DIR:INB) or within one (DIR:INT).
	Direction *string `json:"direction,omitempty"`

	// Scl is the spam confidence level, -1 or 0 to 9. Microsoft states it no
	// longer decides the verdict nor the action in its cloud, CAT does: it is
	// reported, never graded.
	Scl *int `json:"scl,omitempty"`

	// Bcl is the bulk complaint level, from X-Microsoft-Antispam: the higher,
	// the more recipients complain about this sender's bulk mail.
	Bcl *int `json:"bcl,omitempty"`

	// Bulk tells whether spam filtering identified the message as bulk mail
	// against the BCL threshold of the policy it applied (SRV:BULK).
	Bulk bool `json:"bulk,omitempty"`

	// FilterVerdict is the spam filtering verdict (SFV): NSPM not spam, SPM
	// spam, SKN skipped...
	FilterVerdict *string `json:"filter_verdict,omitempty"`

	// Category is the threat policy applied (CAT): NONE, SPM, HSPM, PHSH,
	// BULK, MALW...
	Category *string `json:"category,omitempty"`

	// Report is the raw X-Forefront-Antispam-Report header.
	Report *string `json:"report,omitempty"`
}

// The directions Microsoft 365 filters a message in.
const (
	m365Outbound = "outbound"
	m365Inbound  = "inbound"
	m365Internal = "internal"
)

// Microsoft 365's bulk complaint level (BCL) thresholds: from 7 the default
// anti-spam policy files a message as bulk, from 6 the Standard preset policy,
// from 5 the Strict one.
const (
	m365DefaultBulkBCL = 7
	m365StrictBulkBCL  = 5
)

// m365BlockedCategories are the threat policies (CAT) keeping the message from
// its recipients whatever the policy: malware, caught by the anti-malware
// filter or Safe Attachments, attachments of a blocked type, and high
// confidence phishing.
var m365BlockedCategories = map[string]bool{
	"MALW":   true,
	"AMP":    true,
	"SAP":    true,
	"FTBP":   true,
	"HPHSH":  true,
	"HPHISH": true,
}

// m365SevereCategories are the threat policies (CAT) Microsoft 365 is surest
// of after those: phishing and high confidence spam. The default anti-spam
// policy files them in the junk folder, the Standard and Strict preset
// policies quarantine them.
var m365SevereCategories = map[string]bool{
	"PHSH":  true,
	"INTOS": true,
	"HSPM":  true,
}

// m365SpamCategories are the other threat policies (CAT) counting the message
// as spam: spam, outbound spam, spoofing and impersonation.
var m365SpamCategories = map[string]bool{
	"SPM":   true,
	"OSPM":  true,
	"SPOOF": true,
	"UIMP":  true,
	"DIMP":  true,
	"GIMP":  true,
	"BIMP":  true,
}

// m365ImpersonationCategories are those of m365SpamCategories the default
// anti-phishing policy takes no action on.
var m365ImpersonationCategories = map[string]bool{
	"UIMP": true,
	"DIMP": true,
	"GIMP": true,
	"BIMP": true,
}

// m365SpamVerdicts are the filtering verdicts (SFV) by which Microsoft 365
// treated the message as spam: found so by the filter, or by a mail flow rule
// or a block list before it.
var m365SpamVerdicts = map[string]bool{
	"SPM": true,
	"SKS": true,
	"SKB": true,
	"BLK": true,
}

// m365ReleasedVerdict is the filtering verdict (SFV) of a message released from
// the quarantine it had first been put in.
const m365ReleasedVerdict = "SKQ"

// m365SkippedVerdicts are the filtering verdicts (SFV) of a message spam
// filtering skipped: a mail flow rule, an allow list or a safe sender let it
// through.
var m365SkippedVerdicts = map[string]bool{
	"SKN": true,
	"SKA": true,
	"SKI": true,
	"SFE": true,
}

// analyzeMicrosoft365Verdict reads Microsoft 365's verdict for the registry.
func analyzeMicrosoft365Verdict(headers ScannerHeaders) *UpstreamSpamVerdict {
	details := AnalyzeMicrosoft365(headers)
	if details == nil {
		return nil
	}

	score, grade := CalculateMicrosoft365Score(details)

	return &UpstreamSpamVerdict{
		IsSpam:  details.IsSpam,
		Verdict: m365Outcome(details),
		Score:   score,
		Grade:   grade,
		Details: details,
	}
}

// m365Outcome says what becomes of the message by Microsoft 365's verdict,
// under its default policies; the web interface tells where the Standard and
// Strict preset policies go further.
func m365Outcome(details *microsoft365Details) string {
	category := utils.Deref(details.Category)
	verdict := utils.Deref(details.FilterVerdict)

	switch {
	case category == "FTBP":
		return "Rejected"
	case m365BlockedCategories[category]:
		return "Quarantined"
	case details.IsSpam && utils.Deref(details.Direction) == m365Outbound:
		return "High-risk delivery pool"
	case verdict == m365ReleasedVerdict:
		return "Released from quarantine"
	case m365ImpersonationCategories[category]:
		return "Impersonation"
	case details.IsSpam:
		return "Junk folder"
	case details.isBulk():
		return "Bulk, junk folder"
	case details.Bcl != nil && *details.Bcl >= m365StrictBulkBCL:
		return "Bulk under preset policies"
	case m365SkippedVerdicts[verdict]:
		return "Not filtered"
	default:
		return "Inbox"
	}
}

// isBulk tells whether the policy Microsoft 365 applied filed the message as
// bulk, or the default one would have.
func (d *microsoft365Details) isBulk() bool {
	return d.Bulk || utils.Deref(d.Category) == "BULK" ||
		(d.Bcl != nil && *d.Bcl >= m365DefaultBulkBCL)
}

// AnalyzeMicrosoft365 reads the verdict Microsoft 365 stamped on the message
// from the headers SpamScannerHeaders attributed to it. It returns nil when
// they carry none.
func AnalyzeMicrosoft365(headers ScannerHeaders) *microsoft365Details {
	report := headers["X-Forefront-Antispam-Report"]
	fields := parseMicrosoftAntispamFields(report)
	antispam := parseMicrosoftAntispamFields(headers["X-Microsoft-Antispam"])

	result := &microsoft365Details{}
	found := false

	if scl, ok := parseMicrosoftLevel(fields["SCL"], -1); ok {
		result.Scl = &scl
		found = true
	}
	if bcl, ok := parseMicrosoftLevel(antispam["BCL"], 0); ok {
		result.Bcl = &bcl
		found = true
	}
	if sfv := strings.ToUpper(fields["SFV"]); sfv != "" {
		result.FilterVerdict = &sfv
		found = true
	}
	if cat := strings.ToUpper(fields["CAT"]); cat != "" {
		result.Category = &cat
		found = true
	}
	if strings.EqualFold(fields["SRV"], "BULK") {
		result.Bulk = true
		found = true
	}

	if !found {
		return nil
	}

	switch strings.ToUpper(fields["DIR"]) {
	case "OUT":
		result.Direction = utils.PtrTo(m365Outbound)
	case "INB":
		result.Direction = utils.PtrTo(m365Inbound)
	case "INT":
		result.Direction = utils.PtrTo(m365Internal)
	}

	if report != "" {
		result.Report = &report
	}

	category := utils.Deref(result.Category)
	verdict := utils.Deref(result.FilterVerdict)
	result.IsSpam = m365BlockedCategories[category] ||
		m365SevereCategories[category] ||
		m365SpamCategories[category] ||
		m365SpamVerdicts[verdict] ||
		verdict == m365ReleasedVerdict

	return result
}

// CalculateMicrosoft365Score returns the spam grade Microsoft 365's verdict
// holds the message to, or an empty grade when it does not count against it.
//
// The category (CAT) decides, as Microsoft says it does, the filtering verdict
// (SFV) and the bulk levels coming next; the spam confidence level (SCL) is
// left out, Microsoft stating it no longer decides anything in its cloud.
//
// Whoever handed the message over controls these headers, so only a verdict
// against the message is taken: anyone can stamp a clean one, nobody stamps
// their own mail as spam.
func CalculateMicrosoft365Score(result *microsoft365Details) (int, string) {
	if result == nil {
		return 100, ""
	}

	category := utils.Deref(result.Category)

	switch {
	case m365BlockedCategories[category] || m365SevereCategories[category]:
		return spamBandF.top()
	case result.IsSpam || result.isBulk():
		return spamBandE.top()
	case result.Bcl != nil && *result.Bcl >= m365StrictBulkBCL:
		return spamBandD.top()
	default:
		return 100, ""
	}
}

// parseMicrosoftAntispamFields splits one of Microsoft's antispam headers,
// "CIP:192.0.2.1;CTRY:;LANG:en;SCL:1;SFV:NSPM;...", into its fields keyed by
// upper-case name. The first occurrence of a field wins.
func parseMicrosoftAntispamFields(header string) map[string]string {
	fields := map[string]string{}

	for part := range strings.SplitSeq(header, ";") {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}

		key = strings.ToUpper(strings.TrimSpace(key))
		if _, seen := fields[key]; !seen && key != "" {
			fields[key] = strings.TrimSpace(value)
		}
	}

	return fields
}

// parseMicrosoftLevel parses a confidence level, which Microsoft keeps between
// lowest and 9.
func parseMicrosoftLevel(value string, lowest int) (int, bool) {
	level, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || level < lowest || level > 9 {
		return 0, false
	}

	return level, true
}
