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
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/api"
)

// GenerateAuthenticationChecks generates check results for authentication
func (a *AuthenticationAnalyzer) GenerateAuthenticationChecks(results *api.AuthenticationResults) []api.Check {
	var checks []api.Check

	// SPF check
	if results.Spf != nil {
		check := a.generateSPFCheck(results.Spf)
		checks = append(checks, check)
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "SPF Record",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No SPF authentication result found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Ensure your MTA is configured to check SPF records"),
		})
	}

	// DKIM check
	if results.Dkim != nil && len(*results.Dkim) > 0 {
		for i, dkim := range *results.Dkim {
			check := a.generateDKIMCheck(&dkim, i)
			checks = append(checks, check)
		}
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "DKIM Signature",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No DKIM signature found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Configure DKIM signing for your domain to improve deliverability"),
		})
	}

	// DMARC check
	if results.Dmarc != nil {
		check := a.generateDMARCCheck(results.Dmarc)
		checks = append(checks, check)
	} else {
		checks = append(checks, api.Check{
			Category: api.Authentication,
			Name:     "DMARC Policy",
			Status:   api.CheckStatusWarn,
			Score:    0.0,
			Message:  "No DMARC authentication result found",
			Severity: api.PtrTo(api.CheckSeverityMedium),
			Advice:   api.PtrTo("Implement DMARC policy for your domain"),
		})
	}

	// BIMI check (optional, informational only)
	if results.Bimi != nil {
		check := a.generateBIMICheck(results.Bimi)
		checks = append(checks, check)
	}

	// ARC check (optional, for forwarded emails)
	if results.Arc != nil {
		check := a.generateARCCheck(results.Arc)
		checks = append(checks, check)
	}

	return checks
}

func (a *AuthenticationAnalyzer) generateSPFCheck(spf *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "SPF Record",
	}

	switch spf.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "SPF validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your SPF record is properly configured")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "SPF validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityCritical)
		check.Advice = api.PtrTo("Fix your SPF record to authorize this sending server")
	case api.AuthResultResultSoftfail:
		check.Status = api.CheckStatusWarn
		check.Score = 0.5
		check.Message = "SPF validation softfail"
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Review your SPF record configuration")
	case api.AuthResultResultNeutral:
		check.Status = api.CheckStatusWarn
		check.Score = 0.5
		check.Message = "SPF validation neutral"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("Consider tightening your SPF policy")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("SPF validation result: %s", spf.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Review your SPF record configuration")
	}

	if spf.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *spf.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateDKIMCheck(dkim *api.AuthResult, index int) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     fmt.Sprintf("DKIM Signature #%d", index+1),
	}

	switch dkim.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "DKIM signature is valid"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your DKIM signature is properly configured")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "DKIM signature validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Check your DKIM keys and signing configuration")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("DKIM validation result: %s", dkim.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Ensure DKIM signing is enabled and configured correctly")
	}

	var detailsParts []string
	if dkim.Domain != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Domain: %s", *dkim.Domain))
	}
	if dkim.Selector != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Selector: %s", *dkim.Selector))
	}
	if len(detailsParts) > 0 {
		details := strings.Join(detailsParts, ", ")
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateDMARCCheck(dmarc *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "DMARC Policy",
	}

	switch dmarc.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 1.0
		check.Message = "DMARC validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your DMARC policy is properly aligned")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusFail
		check.Score = 0.0
		check.Message = "DMARC validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityHigh)
		check.Advice = api.PtrTo("Ensure SPF or DKIM alignment with your From domain")
	default:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = fmt.Sprintf("DMARC validation result: %s", dmarc.Result)
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("Configure DMARC policy for your domain")
	}

	if dmarc.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *dmarc.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateBIMICheck(bimi *api.AuthResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "BIMI (Brand Indicators)",
	}

	switch bimi.Result {
	case api.AuthResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 0.0 // BIMI doesn't contribute to score (branding feature)
		check.Message = "BIMI validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("Your brand logo is properly configured via BIMI")
	case api.AuthResultResultFail:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = "BIMI validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("BIMI is optional but can improve brand recognition. Ensure DMARC is enforced (p=quarantine or p=reject) and configure a valid BIMI record")
	default:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = fmt.Sprintf("BIMI validation result: %s", bimi.Result)
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("BIMI is optional. Consider implementing it to display your brand logo in supported email clients")
	}

	if bimi.Domain != nil {
		details := fmt.Sprintf("Domain: %s", *bimi.Domain)
		check.Details = &details
	}

	return check
}

func (a *AuthenticationAnalyzer) generateARCCheck(arc *api.ARCResult) api.Check {
	check := api.Check{
		Category: api.Authentication,
		Name:     "ARC (Authenticated Received Chain)",
	}

	switch arc.Result {
	case api.ARCResultResultPass:
		check.Status = api.CheckStatusPass
		check.Score = 0.0 // ARC doesn't contribute to score (informational for forwarding)
		check.Message = "ARC chain validation passed"
		check.Severity = api.PtrTo(api.CheckSeverityInfo)
		check.Advice = api.PtrTo("ARC preserves authentication results through email forwarding. Your email passed through intermediaries while maintaining authentication")
	case api.ARCResultResultFail:
		check.Status = api.CheckStatusWarn
		check.Score = 0.0
		check.Message = "ARC chain validation failed"
		check.Severity = api.PtrTo(api.CheckSeverityMedium)
		check.Advice = api.PtrTo("The ARC chain is broken or invalid. This may indicate issues with email forwarding intermediaries")
	default:
		check.Status = api.CheckStatusInfo
		check.Score = 0.0
		check.Message = "No ARC chain present"
		check.Severity = api.PtrTo(api.CheckSeverityLow)
		check.Advice = api.PtrTo("ARC is not present. This is normal for emails sent directly without forwarding through mailing lists or other intermediaries")
	}

	// Build details
	var detailsParts []string
	if arc.ChainLength != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Chain length: %d", *arc.ChainLength))
	}
	if arc.ChainValid != nil {
		detailsParts = append(detailsParts, fmt.Sprintf("Chain valid: %v", *arc.ChainValid))
	}
	if arc.Details != nil {
		detailsParts = append(detailsParts, *arc.Details)
	}

	if len(detailsParts) > 0 {
		details := strings.Join(detailsParts, ", ")
		check.Details = &details
	}

	return check
}
