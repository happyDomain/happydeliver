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
	rec, err := v.Lookup(ctx, domain, selector)
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
	var checks []Check
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
