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
	"net/textproto"
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

var (
	spfResultRe   = regexp.MustCompile(`spf=(\w+)`)
	spfMailFromRe = regexp.MustCompile(`smtp\.mailfrom=("[^"]*"|[^\s;]+)`)
	spfHeloRe     = regexp.MustCompile(`smtp\.helo=("[^"]*"|[^\s;()]+)`)

	// Keys of the legacy Received-SPF header (RFC 7208 section 7.2). Each of them
	// is anchored on a key boundary, as a key is only ever introduced by the start
	// of the header, a semicolon or whitespace: without it `helo=` would also
	// match the tail of a non-standard `x-helo=`, and `sender=` that of
	// `x-sender=`, and the first match in the header is the one that wins.
	spfLegacyReceiverRe = regexp.MustCompile(`(?:^|[;\s])receiver=("[^"]*"|[^\s;]+)`)
	spfLegacyIdentityRe = regexp.MustCompile(`(?:^|[;\s])identity=\s*"?([a-zA-Z0-9-]+)`)
	spfLegacyMailFromRe = regexp.MustCompile(`(?:^|[;\s])(?:envelope-from|sender)=("[^"]*"|[^\s;]+)`)
	spfLegacyHeloRe     = regexp.MustCompile(`(?:^|[;\s])helo=("[^"]*"|[^\s;]+)`)
)

// Priorities of the identities an envelope sender result may carry, used to pick
// the most relevant "spf=" method when several of them are reported.
const (
	spfIdentityUnknown  = 0 // no ptype reported, assume the envelope sender
	spfIdentityMailFrom = 1 // explicitly about the envelope sender (MAIL FROM)
)

// spfPartIdentity tells which identity an "spf=" method applies to, or nil when
// the method reports no ptype at all.
//
// Some MTAs report both the HELO and the MAIL FROM checks in the
// same header (RFC 8601 §2.7.2). They describe different things and are kept
// apart: only the MAIL FROM one authenticates the envelope sender.
func spfPartIdentity(part string) *model.AuthResultIdentity {
	switch {
	case spfMailFromRe.MatchString(part):
		return utils.PtrTo(model.AuthResultIdentityMailfrom)
	case spfHeloRe.MatchString(part):
		return utils.PtrTo(model.AuthResultIdentityHelo)
	default:
		return nil
	}
}

// spfIdentityPriority ranks an already parsed envelope sender result: a method
// explicitly about smtp.mailfrom describes the Return-Path for certain, so it
// supersedes one that reported no ptype.
func spfIdentityPriority(result *model.AuthResult) int {
	if result != nil && result.Identity != nil && *result.Identity == model.AuthResultIdentityMailfrom {
		return spfIdentityMailFrom
	}

	return spfIdentityUnknown
}

// spfPValue unwraps the value a receiver reported for a property, whether in an
// Authentication-Results header or in a legacy Received-SPF one.
//
// RFC 8601 section 2.2 allows a pvalue to be a quoted-string, and receivers wrap
// hostnames and addresses alike in angle brackets, so neither delimiter belongs
// to the value itself.
func spfPValue(value string) string {
	return strings.Trim(value, `"<>`)
}

// spfMailFromDomain extracts the domain out of an envelope sender as a receiver
// reported it, or nil when it carries none.
//
// The value comes in several shapes: a plain or quoted address, a bare domain
// (some receivers report only that), an address wrapped in angle brackets, or
// the null sender "<>" of a bounce, which names no domain at all.
func spfMailFromDomain(value string) *string {
	mailfrom := spfPValue(value)

	domain := mailfrom
	if idx := strings.LastIndex(mailfrom, "@"); idx != -1 {
		domain = mailfrom[idx+1:]
	}

	if domain == "" {
		return nil
	}

	return &domain
}

// spfHeloName extracts the hostname out of a HELO identity as a receiver
// reported it, or nil when the value holds nothing but its delimiters.
func spfHeloName(value string) *string {
	helo := spfPValue(value)
	if helo == "" {
		return nil
	}

	return &helo
}

// parseSPFResult parses SPF result from Authentication-Results
// Example: spf=pass smtp.mailfrom=sender@example.com
func (a *AuthenticationAnalyzer) parseSPFResult(part string) *model.AuthResult {
	result := &model.AuthResult{Identity: spfPartIdentity(part)}

	// Extract result (pass, fail, etc.)
	if matches := spfResultRe.FindStringSubmatch(part); len(matches) > 1 {
		resultStr := strings.ToLower(matches[1])
		result.Result = model.AuthResultResult(resultStr)
	}

	// Extract the authenticated domain: the envelope sender for a MAIL FROM
	// check, the announced hostname for a HELO one
	if matches := spfMailFromRe.FindStringSubmatch(part); len(matches) > 1 {
		result.Domain = spfMailFromDomain(matches[1])
	} else if matches := spfHeloRe.FindStringSubmatch(part); len(matches) > 1 {
		result.Domain = spfHeloName(matches[1])
	}

	result.Details = utils.PtrTo(strings.TrimPrefix(part, "spf="))

	return result
}

// parseLegacySPFHeader parses a single Received-SPF header (RFC 7208 section
// 7.2), the legacy way a receiver reports an SPF check.
//
// Returns nil when the header was not written by the authority we trust, or when
// it reports an identity that is neither of the two SPF ones: Sender-ID's PRA
// (RFC 4407) authenticates an address taken from the message headers, so its
// verdict says nothing about the envelope sender nor about the HELO name.
func (a *AuthenticationAnalyzer) parseLegacySPFHeader(receivedSPF, authservID string) *model.AuthResult {
	// Verify the header was written by the authority we trust
	if authservID != "" {
		if matches := spfLegacyReceiverRe.FindStringSubmatch(receivedSPF); len(matches) > 1 {
			if !strings.EqualFold(spfPValue(matches[1]), authservID) {
				return nil
			}
		}
	}

	result := &model.AuthResult{Details: &receivedSPF}

	// Extract result (first word)
	if parts := strings.Fields(receivedSPF); len(parts) > 0 {
		resultStr := strings.ToLower(parts[0])
		result.Result = model.AuthResultResult(resultStr)
	}

	// Only the identity= key tells which identity was checked: envelope-from and
	// helo are both reported whatever it is, so their mere presence proves
	// nothing. A header without it predates the key or omits it, and is then
	// taken to be about the envelope sender, as it is what SPF checks by default.
	if matches := spfLegacyIdentityRe.FindStringSubmatch(receivedSPF); len(matches) > 1 {
		switch strings.ToLower(matches[1]) {
		case "helo":
			result.Identity = utils.PtrTo(model.AuthResultIdentityHelo)
		case "mailfrom":
			result.Identity = utils.PtrTo(model.AuthResultIdentityMailfrom)
		default:
			return nil
		}
	}

	// Extract the domain from the key naming the identity that was checked
	if result.Identity != nil && *result.Identity == model.AuthResultIdentityHelo {
		if matches := spfLegacyHeloRe.FindStringSubmatch(receivedSPF); len(matches) > 1 {
			result.Domain = spfHeloName(matches[1])
		}
	} else if matches := spfLegacyMailFromRe.FindStringSubmatch(receivedSPF); len(matches) > 1 {
		// The header names the envelope sender it checked, so the identity is known
		result.Identity = utils.PtrTo(model.AuthResultIdentityMailfrom)

		result.Domain = spfMailFromDomain(matches[1])
	}

	return result
}

// parseLegacySPF parses the Received-SPF headers and routes each of them to the
// identity it was checked against, mirroring what is done for the spf= methods
// of an Authentication-Results header.
//
// A receiver may report one header per identity checked, so both are collected
// in a single pass. For each identity the first header wins, as headers come
// most recent first and the closest hop is the one we trust.
func (a *AuthenticationAnalyzer) parseLegacySPF(email *EmailMessage, authservID string) (mailfrom, helo *model.AuthResult) {
	for _, receivedSPF := range email.Header[textproto.CanonicalMIMEHeaderKey("Received-SPF")] {
		if receivedSPF == "" {
			continue
		}

		result := a.parseLegacySPFHeader(receivedSPF, authservID)
		if result == nil {
			continue
		}

		if result.Identity != nil && *result.Identity == model.AuthResultIdentityHelo {
			if helo == nil {
				helo = result
			}
		} else if mailfrom == nil {
			mailfrom = result
		}
	}

	return mailfrom, helo
}

func (a *AuthenticationAnalyzer) calculateSPFScore(results *model.AuthenticationResults) (score int) {
	if results.Spf != nil {
		switch results.Spf.Result {
		case model.AuthResultResultPass:
			return 100
		case model.AuthResultResultNeutral, model.AuthResultResultNone:
			return 50
		case model.AuthResultResultSoftfail:
			return 17
		default: // fail, temperror, permerror
			return 0
		}
	}

	// A receiver that only checked the HELO identity did evaluate SPF, it just
	// says nothing about the envelope sender: score it like an absent policy
	// rather than like a failed one.
	if results.SpfHelo != nil {
		return 50
	}

	return 0
}

// calculateSPFHeloScore rates the SPF check made against the HELO/EHLO identity.
//
// It is penalty-only (0 leaves the score untouched, -100 applies the full
// malus): passing that check authenticates the relay, not the sender, so it
// earns nothing. Only an outright failure counts, as it denotes a relay whose
// announced name contradicts the SPF policy it claims. A missing record is the
// common case for a relay hostname and must stay neutral.
func (a *AuthenticationAnalyzer) calculateSPFHeloScore(results *model.AuthenticationResults) (score int) {
	if results.SpfHelo != nil {
		switch results.SpfHelo.Result {
		case model.AuthResultResultFail:
			return -100
		case model.AuthResultResultSoftfail:
			return -50
		default: // pass, none, neutral, temperror, permerror
			return 0
		}
	}

	return 0
}
