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
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// maxDKIMVerifications bounds the number of signatures verified in a single
// message. Each one costs a DNS lookup and a public key operation, both of which
// an uploaded EML would otherwise be free to multiply at will.
const maxDKIMVerifications = 10

// DKIMVerifier checks the DKIM signatures a message carries against the keys
// published in the DNS.
//
// Unlike the Authentication-Results parsing, which reports what some other
// server claimed, this is a first-hand verdict: it is computed here, from the
// message octets and the public keys, and cannot be forged by whoever supplied
// the message.
type DKIMVerifier struct {
	resolver DNSResolver
	timeout  time.Duration
}

// NewDKIMVerifier creates a verifier resolving public keys through resolver.
// A nil resolver disables verification: VerifyDKIM then reports nothing rather
// than reaching for the system resolver behind the caller's back.
func NewDKIMVerifier(resolver DNSResolver, timeout time.Duration) *DKIMVerifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DKIMVerifier{resolver: resolver, timeout: timeout}
}

// VerifyDKIM verifies every DKIM-Signature of the raw message, in the order the
// headers appear, and returns one result per signature.
//
// raw must be the message exactly as received: DKIM signs octets, so a message
// re-serialised from parsed headers would not verify. It returns nothing at all
// — rather than a "fail" — when there is no signature to judge, or when the
// message cannot be read far enough to find one.
func (v *DKIMVerifier) VerifyDKIM(raw []byte) []model.AuthResult {
	if v == nil || v.resolver == nil || len(raw) == 0 {
		return nil
	}

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        v.lookupTXT,
		MaxVerifications: maxDKIMVerifications,
	})
	// ErrTooManySignatures comes back alongside the verifications that were
	// performed, which are exactly the ones we asked for; any other error means
	// nothing could be verified.
	if err != nil && err != dkim.ErrTooManySignatures {
		return nil
	}
	if len(verifications) == 0 {
		return nil
	}

	// go-msgauth reports the signing domain but not the selector, and the
	// selector is what tells two signatures of the same domain apart. Both lists
	// follow the header order, so they line up index by index.
	selectors := dkimSignatureSelectors(raw)

	results := make([]model.AuthResult, 0, len(verifications))
	for i, verification := range verifications {
		result := model.AuthResult{Result: dkimResultOf(verification.Err)}

		if verification.Domain != "" {
			result.Domain = utils.PtrTo(verification.Domain)
		}
		if i < len(selectors) && selectors[i] != "" {
			result.Selector = utils.PtrTo(selectors[i])
		}
		if verification.Err != nil {
			result.Details = utils.PtrTo(verification.Err.Error())
		}

		results = append(results, result)
	}

	return results
}

// lookupTXT adapts the analyzer's resolver to the signature go-msgauth expects.
func (v *DKIMVerifier) lookupTXT(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	return v.resolver.LookupTXT(ctx, domain)
}

// dkimResultOf maps a verification error onto an authentication result, keeping
// RFC 8601's distinction between a signature that is wrong (fail) and one that
// could not be judged (temperror when it may work later, permerror when it never
// will).
func dkimResultOf(err error) model.AuthResultResult {
	switch {
	case err == nil:
		return model.AuthResultResultPass
	case dkim.IsTempFail(err):
		return model.AuthResultResultTemperror
	case dkim.IsPermFail(err):
		return model.AuthResultResultPermerror
	default:
		return model.AuthResultResultFail
	}
}

// dkimSignatureSelectors lists the s= tag of every DKIM-Signature header of the
// raw message, in header order, with an empty string where the tag is missing.
//
// The header block is scanned here rather than through a MIME header parser
// because the result has to stay positional even for a message malformed enough
// that a parser would give up: a missing entry would silently shift every
// selector onto the wrong signature.
func dkimSignatureSelectors(raw []byte) []string {
	var (
		selectors []string
		current   strings.Builder
		inSig     bool
	)

	flush := func() {
		if !inSig {
			return
		}
		selectors = append(selectors, strings.TrimSpace(parseDKIMTags(current.String())["s"]))
		current.Reset()
		inSig = false
	}

	for _, line := range splitHeaderLines(raw) {
		// An empty line ends the header block; nothing below it is a header.
		if line == "" {
			break
		}

		// A line starting with whitespace continues the previous header.
		if line[0] == ' ' || line[0] == '\t' {
			if inSig {
				current.WriteString(" ")
				current.WriteString(strings.TrimSpace(line))
			}
			continue
		}

		flush()

		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
			continue
		}

		inSig = true
		current.WriteString(strings.TrimSpace(value))
	}
	flush()

	return selectors
}

// splitHeaderLines splits the message into lines, stripping the CR of CRLF, up
// to and including the first empty line.
func splitHeaderLines(raw []byte) []string {
	head, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))

	lines := strings.Split(string(head), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}

	return lines
}
