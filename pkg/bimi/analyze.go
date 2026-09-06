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
	allPassed := true

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
			allPassed = false
		} else {
			checks = append(checks,
				newCheck("logo_fetch", "Logo file retrieval", StatusSkipped,
					"No logo URL published (declination record)"))
		}
	} else {
		content, contentType, problems := v.fetchFile(ctx, rec.LogoURL, MaxLogoSize)
		if len(problems) > 0 {
			checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusFail, problems...))
			allPassed = false
		} else {
			logoContent = content
			if contentType != "image/svg+xml" {
				checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusWarning,
					fmt.Sprintf("Logo served with Content-Type %q, expected \"image/svg+xml\"", contentType)))
			} else {
				checks = append(checks, newCheck("logo_fetch", "Logo file retrieval", StatusPass))
			}
		}

		if logoContent == nil {
			checks = append(checks,
				newCheck("logo_xml", "Logo XML well-formedness", StatusSkipped,
					"Skipped: the logo could not be retrieved"),
				newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusSkipped,
					"Skipped: the logo could not be retrieved"))
		} else {
			xmlCheck := CheckLogoXML(logoContent)
			checks = append(checks, xmlCheck)
			if xmlCheck.Status == StatusFail {
				allPassed = false
			}

			svgCheck := CheckLogoSVGTinyPS(logoContent)
			checks = append(checks, svgCheck)
			if svgCheck.Status == StatusFail {
				allPassed = false
			}
		}
	}

	if rec.VMCURL == "" {
		checks = append(checks,
			newCheck("vmc", "Verified Mark Certificate", StatusSkipped,
				"No VMC published (a= tag absent or empty): VMC is optional but required by some mail providers (e.g. Gmail, Apple Mail)"))
	} else {
		vmcCheck, vmcInfo := v.analyzeVMCURL(ctx, rec.VMCURL, v.vmcBinding(rec), logoContent)
		checks = append(checks, vmcCheck)
		rec.VMC = vmcInfo
		if vmcCheck.Status == StatusFail {
			allPassed = false
		}
	}

	rec.Checks = checks
	if !allPassed {
		rec.Valid = false
		rec.Error = "BIMI assets failed validation, see detailed checks below"
	}
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
