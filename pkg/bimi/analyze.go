// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

package bimi

import (
	"context"
	"fmt"
	"strings"
)

// Analyze looks up the BIMI record for domain/selector, parses it and, when
// it is syntactically valid, runs the asset evidence checks. The returned
// Record fully describes validity. A non-nil error is returned only when the
// DNS lookup fails or no record exists (ErrNoRecord).
func (v *Validator) Analyze(ctx context.Context, domain, selector string) (*Record, error) {
	return v.AnalyzeForLocalPart(ctx, domain, selector, "")
}

// AnalyzeForLocalPart analyses the BIMI record like Analyze, resolving it with
// LookupForLocalPart so that the Local-part Selector of the sending address is
// honoured. Callers analysing a message should prefer it: it is the record the
// receiver of that message would act on.
func (v *Validator) AnalyzeForLocalPart(ctx context.Context, domain, selector, localPart string) (*Record, error) {
	rec, err := v.LookupForLocalPart(ctx, domain, selector, localPart)
	if err != nil {
		return nil, err
	}
	if rec.Valid {
		v.ValidateAssets(ctx, rec)
	}
	return rec, nil
}

// ValidateAssets performs the evidence checks (logo download, XML
// well-formedness, SVG Tiny P/S profile, VMC analysis) for a syntactically
// valid record, filling rec.Checks and rec.VMC. When a mandatory check fails
// it sets rec.Valid to false and rec.Error. A BIMI record only leads to a
// displayed logo if its assets are compliant.
func (v *Validator) ValidateAssets(ctx context.Context, rec *Record) {
	checks := []Check{checkRecordTags(rec)}

	// The logo and the certificate sit at two unrelated URLs, and only the
	// final comparison of one against the other needs both: download them
	// at the same time, so a pair of slow hosts costs one fetch timeout
	// rather than the sum of two.
	var vmcFetch <-chan fetchedFile
	if rec.VMCURL != "" {
		vmcFetch = v.fetchAsync(ctx, rec.VMCURL, MaxFileSize)
	}

	var logoContent []byte

	if rec.LogoURL == "" {
		// An empty l= is only meaningful as a Declination to Publish,
		// which requires a= to be empty too. With a VMC published but no
		// Indicator location, Indicator Discovery has failed: no logo can
		// ever be displayed.
		if rec.VMCURL != "" {
			checks = append(checks,
				newCheck("logo_fetch", "Logo file retrieval", StatusFail,
					"The l= tag is empty while a VMC is published in a=: with no logo URL, no Indicator can be displayed"))
		} else {
			checks = append(checks,
				newCheck("logo_fetch", "Logo file retrieval", StatusSkipped,
					"No logo URL published (declination record)"))
		}
	} else {
		content, contentType, problems := v.fetchFile(ctx, rec.LogoURL, MaxLogoSize)
		if len(problems) > 0 {
			checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusFail, problems...))
		} else if svg, compressed, err := DecodeLogo(content); err != nil {
			checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusFail,
				fmt.Sprintf("Unable to decode the logo file: %s", err)))
		} else {
			// Every later check reads the decoded document: an SVGZ is a
			// gzip stream, which is neither XML nor comparable to the
			// logo the certificate carries, itself already inflated.
			logoContent = svg
			checks = append(checks, checkLogoFetch(contentType, compressed, len(svg)))
		}

		if logoContent == nil {
			checks = append(checks,
				newCheck("logo_xml", "Logo XML well-formedness", StatusSkipped,
					"Skipped: the logo could not be retrieved"),
				newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusSkipped,
					"Skipped: the logo could not be retrieved"))
		} else {
			checks = append(checks, CheckLogoXML(logoContent), CheckLogoSVGTinyPS(logoContent))
		}
	}

	if rec.VMCURL == "" {
		checks = append(checks,
			newCheck("vmc", "Verified Mark Certificate", StatusSkipped,
				"No VMC published (a= tag absent or empty): VMC is optional but required by some mail providers (e.g. Gmail, Apple Mail)"))
	} else {
		vmcCheck, vmcInfo := v.analyzeVMCFetch(<-vmcFetch, v.vmcBinding(rec), logoContent)
		checks = append(checks, vmcCheck)
		rec.VMC = vmcInfo
	}

	rec.Checks = checks
	// The verdict is read back from the checks rather than tracked
	// alongside them: a check added here cannot then be forgotten in the
	// bookkeeping and let a failing record be reported as valid.
	if failed := failedChecks(checks); len(failed) > 0 {
		rec.Valid = false
		rec.Error = fmt.Sprintf("BIMI assets failed validation: %s", strings.Join(failed, ", "))
	}
}

// failedChecks lists the descriptions of the checks that failed, in the order
// they were run.
func failedChecks(checks []Check) []string {
	var failed []string
	for _, c := range checks {
		if c.Status == StatusFail {
			failed = append(failed, c.Description)
		}
	}
	return failed
}

// checkRecordTags reports on the tags that carry a preference rather than an
// asset, which the record's own syntax check cannot reject on its own.
//
// An avp= value outside the registered set is a warning, not a failure: the
// specification has a receiver ignore it, falling back to the default
// preference, and only allows a mailbox provider to treat it as a failing
// record. Publishing it still says the Domain Owner believes it is expressing
// a preference it is not, and on the providers that do act on it the record
// stops working altogether.
func checkRecordTags(rec *Record) Check {
	check := Check{Name: "record_tags", Description: "BIMI record tags", Status: StatusPass}

	if rec.AvatarPreference != "" && !isKnownAvatarPreference(rec.AvatarPreference) {
		check.Status = StatusWarning
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityWarning,
			Text: fmt.Sprintf("The avp= tag publishes the unknown avatar preference %q, expected %q or %q: receivers must ignore it and fall back to %q, and some may treat the whole record as failing",
				rec.AvatarPreference, AvatarPreferencePersonal, AvatarPreferenceBrand, AvatarPreferenceBrand),
		})
	} else if rec.AvatarPreference == AvatarPreferencePersonal {
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityInfo,
			Text:     "The avp=personal tag asks providers that display personal avatars to prefer the sender's avatar over the brand Indicator",
		})
	}

	if rec.LocalPartSelector {
		scope := "every local-part"
		if len(rec.LocalPartPrefixes) > 0 {
			scope = fmt.Sprintf("the local-parts starting with %s", quotedList(rec.LocalPartPrefixes))
		}
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityInfo,
			Text:     fmt.Sprintf("The lps= tag sends %s to a selector named after the address, so those senders can be served another Indicator than this one", scope),
		})
	}

	if rec.FromLocalPartSelector() {
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityInfo,
			Text:     fmt.Sprintf("This record was found under the %q selector, derived from the sender's local-part by the lps= tag of the %q record", rec.Selector, rec.RequestedSelector),
		})
	}

	return check
}

// checkLogoFetch reports on the file the l= URL actually served, once it has
// been retrieved and decoded.
//
// Publishing an SVGZ is not a defect: BIMI accepts SVG and SVGZ alike for the
// l= tag, so the compression is reported informationally, next to the size the
// profile measures its own limit against. The media type stays the one thing
// that can be wrong on its own here, compressed or not: RFC 6170 section 5.2
// mandates image/svg+xml for SVG and SVGZ images alike, so an SVGZ announced
// as application/gzip is still misdeclared.
func checkLogoFetch(contentType string, compressed bool, size int) Check {
	check := Check{Name: "logo_fetch", Description: "Logo file retrieval", Status: StatusPass}

	if compressed {
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityInfo,
			Text:     fmt.Sprintf("Logo served as SVGZ (gzip-compressed, RFC 6170 section 5.2), decompressing to %d bytes: BIMI accepts SVG and SVGZ alike for the l= tag", size),
		})
	}

	if contentType != "image/svg+xml" {
		check.Status = StatusWarning
		check.Messages = append(check.Messages, CheckMessage{
			Severity: SeverityWarning,
			Text:     fmt.Sprintf("Logo served with Content-Type %q, expected \"image/svg+xml\"", contentType),
		})
	}

	return check
}

// vmcBinding names the Assertion Record a Verified Mark Certificate published
// by rec must be bound to. Both the queried domain and its organizational
// domain are acceptable, whichever of them the record was actually found at:
// a certificate is issued to an organization, and a subdomain that publishes
// its own record is still covered by the organizational domain's certificate.
func (v *Validator) vmcBinding(rec *Record) VMCBinding {
	return VMCBinding{
		Selector:             rec.Selector,
		Domain:               rec.Domain,
		OrganizationalDomain: v.organizationalDomain(rec.Domain),
	}
}
