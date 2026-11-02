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

package mailmsg

import (
	"strconv"
	"strings"
	"unicode"
)

// DKIM2Key is one of the signatures a DKIM2-Signature header carries in its
// s= tag: the selector naming the key and the algorithm it was made with.
type DKIM2Key struct {
	Selector  string
	Algorithm string // e.g. rsa-sha256, ed25519-sha256, mldsa44
	// Group is the alternative the signature belongs to: signatures of the
	// same group must all pass, and one passing group is enough (s=a,b|c
	// puts a and b in group 0 and c in group 1).
	Group int
}

// DKIM2Signature holds what a DKIM2-Signature header claims
// (draft-ietf-dkim-dkim2-spec): its place in the chain, the domain it signs
// for, and the keys of its signatures.
type DKIM2Signature struct {
	// Instance is the i= tag, 1 for the originator; 0 when unreadable.
	Instance int
	// Domain is the d= tag, the Signing Domain.
	Domain string
	// NextDomain is the nd= tag, the domain of the next signature when the
	// message is forwarded from another domain than the one it arrived to.
	NextDomain string
	// Timestamp is the t= tag, in seconds since the epoch; 0 when unreadable.
	Timestamp int64
	// Flags are those of the f= tag (exploded, feedback, feedhere...).
	Flags []string
	// Keys are the signatures of the s= tag, in the order written.
	Keys []DKIM2Key
}

// DKIM2Signatures reads what each DKIM2-Signature header of the message
// claims. Like DKIMSignatures, it reports what is written, and says nothing
// about whether any of it verifies. A header naming no domain or no selector
// is left out: no key could be looked up for it.
func (e *Message) DKIM2Signatures() []DKIM2Signature {
	var results []DKIM2Signature
	for _, header := range e.Header["Dkim2-Signature"] {
		if sig, ok := ParseDKIM2Signature(header); ok {
			results = append(results, sig)
		}
	}
	return results
}

// ParseDKIM2Signature reads the value of a DKIM2-Signature header, and says
// whether it names a domain and at least one selector.
func ParseDKIM2Signature(value string) (DKIM2Signature, bool) {
	var sig DKIM2Signature

	for _, part := range strings.Split(value, ";") {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		// Tag names are case-sensitive, and DKIM2 writes them in lower case.
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)

		switch name {
		case "i":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				sig.Instance = n
			}
		case "d":
			sig.Domain = strings.TrimSuffix(val, ".")
		case "nd":
			sig.NextDomain = strings.TrimSuffix(val, ".")
		case "t":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				sig.Timestamp = n
			}
		case "f":
			for _, flag := range strings.Split(val, ",") {
				if flag = strings.TrimSpace(flag); flag != "" {
					sig.Flags = append(sig.Flags, flag)
				}
			}
		case "s":
			sig.Keys = parseDKIM2Keys(val)
		}
	}

	return sig, sig.Domain != "" && len(sig.Keys) > 0
}

// parseDKIM2Keys reads the s= tag: groups of signatures separated by "|",
// signatures within a group separated by ",", each "selector:algorithm:value".
// Folding whitespace may appear anywhere, the base64 value included.
func parseDKIM2Keys(value string) []DKIM2Key {
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)

	var keys []DKIM2Key
	for group, alternative := range strings.Split(value, "|") {
		for _, set := range strings.Split(alternative, ",") {
			selector, rest, ok := strings.Cut(set, ":")
			if !ok || selector == "" {
				continue
			}
			algorithm, _, _ := strings.Cut(rest, ":")
			keys = append(keys, DKIM2Key{
				Selector:  strings.TrimSuffix(selector, "."),
				Algorithm: algorithm,
				Group:     group,
			})
		}
	}
	return keys
}
