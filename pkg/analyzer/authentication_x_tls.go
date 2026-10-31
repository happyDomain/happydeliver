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
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"

	"git.happydns.org/happyDeliver/pkg/authresults"
)

// parseXTLSResult parses the x-tls result from Authentication-Results.
// Example: x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_256_GCM_SHA384 smtp.bits=256
//
// The parameters of the connection stay in the details, as the receiver wrote them, like
// the properties of any other method.
func (a *AuthenticationAnalyzer) parseXTLSResult(method authresults.Method) *model.AuthResult {
	return &model.AuthResult{
		Result:  model.AuthResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}
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

// ReconcileXTLS fills in the x-tls result from the inbound hop of the received chain
// when no x-tls Authentication-Results header was present.
//
// Only the verdict is filled in: the parameters of the connection it rests on are those
// the hop already gives, in its TLS details and its transport keyword.
func (a *AuthenticationAnalyzer) ReconcileXTLS(results *model.AuthenticationResults, inbound *model.ReceivedHop) {
	if results == nil || results.XTls != nil || inbound == nil {
		return
	}

	switch {
	case inbound.Tls != nil, protocolIndicatesTLS(inbound.With):
		// Either the full TLS parenthetical (smtpd_tls_received_header = yes), or a
		// transport keyword (ESMTPS, ESMTPSA, ...) telling the session was encrypted.
		results.XTls = &model.AuthResult{Result: model.AuthResultResultPass}

	case inbound.With != nil:
		// A plaintext transport keyword (SMTP, ESMTP, ESMTPA, ...) is positive
		// evidence the inbound connection was not encrypted.
		results.XTls = &model.AuthResult{Result: model.AuthResultResultNone}

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
