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
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// parseXTLSResult parses the x-tls result from Authentication-Results.
// Example: x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_256_GCM_SHA384 smtp.bits=256
func (a *AuthenticationAnalyzer) parseXTLSResult(part string) *model.AuthResult {
	result := &model.AuthResult{}

	// Extract result (pass, fail, none, ...)
	re := regexp.MustCompile(`x-tls=(\w+)`)
	if matches := re.FindStringSubmatch(part); len(matches) > 1 {
		result.Result = model.AuthResultResult(strings.ToLower(matches[1]))
	}

	result.Details = utils.PtrTo(formatTLSDetails(
		submatch(part, `smtp\.version=([^\s;()]+)`),
		submatch(part, `smtp\.cipher=([^\s;()]+)`),
		submatch(part, `smtp\.bits=(\d+)`),
	))

	return result
}

// calculateXTLSScore returns a penalty for a negative transport-TLS result.
// pass (or absent) does not alter the score; any other result is penalized.
func (a *AuthenticationAnalyzer) calculateXTLSScore(results *model.AuthenticationResults) (score int) {
	if results.XTls != nil {
		switch results.XTls.Result {
		case model.AuthResultResultPass:
			// pass: don't alter the score
		default:
			return -100
		}
	}

	return 0
}

// ReconcileXTLS fills in the x-tls result from the inbound connection's parsed TLS
// information when no x-tls Authentication-Results header was present. The inbound
// connection is the most recent hop (index 0) of the received chain.
func (a *AuthenticationAnalyzer) ReconcileXTLS(results *model.AuthenticationResults, chain *[]model.ReceivedHop) {
	if results == nil || results.XTls != nil {
		return
	}
	if chain == nil || len(*chain) == 0 {
		return
	}

	inbound := (*chain)[0]
	switch {
	case inbound.Tls != nil:
		// Full TLS parenthetical present (smtpd_tls_received_header = yes).
		var version, cipher, bits string
		if inbound.Tls.Version != nil {
			version = *inbound.Tls.Version
		}
		if inbound.Tls.Cipher != nil {
			cipher = *inbound.Tls.Cipher
		}
		if inbound.Tls.Bits != nil {
			bits = fmt.Sprintf("%d", *inbound.Tls.Bits)
		}
		results.XTls = &model.AuthResult{
			Result:  model.AuthResultResultPass,
			Details: utils.PtrTo(formatTLSDetails(version, cipher, bits)),
		}

	case protocolIndicatesTLS(inbound.With):
		// No TLS parenthetical (smtpd_tls_received_header may be disabled), but the
		// transport keyword (ESMTPS, ESMTPSA, ...) tells us the session was encrypted.
		// We just don't have the cipher details.
		results.XTls = &model.AuthResult{
			Result:  model.AuthResultResultPass,
			Details: utils.PtrTo(fmt.Sprintf("Encrypted connection (%s); cipher details unavailable", *inbound.With)),
		}

	case inbound.With != nil:
		// A plaintext transport keyword (SMTP, ESMTP, ESMTPA, ...) is positive
		// evidence the inbound connection was not encrypted.
		results.XTls = &model.AuthResult{
			Result:  model.AuthResultResultNone,
			Details: utils.PtrTo(fmt.Sprintf("Inbound connection was not encrypted (%s)", *inbound.With)),
		}

	default:
		// Neither TLS details nor a transport keyword: we cannot tell whether the
		// connection was encrypted. Leave x-tls unset rather than wrongly penalize.
	}
}

// protocolIndicatesTLS reports whether an SMTP "with" transport keyword denotes a
// TLS-encrypted session. Per RFC 3848 the keyword gains a trailing "S" when STARTTLS
// (or implicit TLS) was negotiated: ESMTPS, ESMTPSA, SMTPS, LMTPS, LMTPSA, UTF8SMTPS...
// The plaintext variants end in "P" (SMTP, ESMTP, LMTP) or "A" (ESMTPA, LMTPA).
func protocolIndicatesTLS(with *string) bool {
	if with == nil {
		return false
	}
	p := strings.ToUpper(strings.TrimSpace(*with))
	return strings.HasSuffix(p, "S") || strings.HasSuffix(p, "SA")
}

// submatch returns the first capture group of pattern in s, or "".
func submatch(s, pattern string) string {
	if matches := regexp.MustCompile(pattern).FindStringSubmatch(s); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// formatTLSDetails builds a human-readable summary of the TLS parameters.
func formatTLSDetails(version, cipher, bits string) string {
	var parts []string
	if version != "" {
		parts = append(parts, version)
	}
	if cipher != "" {
		parts = append(parts, "cipher "+cipher)
	}
	if bits != "" {
		parts = append(parts, bits+" bits")
	}
	return strings.Join(parts, ", ")
}
