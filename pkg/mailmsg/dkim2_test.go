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
	"net/mail"
	"reflect"
	"testing"
)

func TestDKIM2Signatures(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		expected []DKIM2Signature
	}{
		{
			name:     "No header",
			expected: nil,
		},
		{
			// As Fastmail signs: one RSA and one Ed25519 signature, either
			// of which is enough.
			name: "Fastmail style, folded, two alternatives",
			headers: []string{
				"i=1; m=1; t=1793570894; d=example.com;\r\n mf=PHNlbmRlckBleGFtcGxlLmNvbT4=;\r\n rt=PHJjcHRAZXhhbXBsZS5uZXQ+;\r\n s=dkim-abc-rsa:rsa-sha256:C2FvbWU=|\r\n dkim-abc-ed25519:ed25519-sha256:6xYz==;",
			},
			expected: []DKIM2Signature{{
				Instance:  1,
				Domain:    "example.com",
				Timestamp: 1793570894,
				Keys: []DKIM2Key{
					{Selector: "dkim-abc-rsa", Algorithm: "rsa-sha256", Group: 0},
					{Selector: "dkim-abc-ed25519", Algorithm: "ed25519-sha256", Group: 1},
				},
			}},
		},
		{
			name: "Hybrid group and forwarder chain",
			headers: []string{
				"i=1; m=1; t=1; d=sender.example; nd=list.example; s=a:rsa-sha256:AAA=,b:mldsa44:BB BB==",
				"i=2; m=2; t=2; d=list.example; f=exploded, feedhere; mf=PD4=; rt=PGFAYj4=; s=c:ed25519-sha256:CCC=",
			},
			expected: []DKIM2Signature{
				{
					Instance: 1, Domain: "sender.example", NextDomain: "list.example", Timestamp: 1,
					Keys: []DKIM2Key{
						{Selector: "a", Algorithm: "rsa-sha256", Group: 0},
						{Selector: "b", Algorithm: "mldsa44", Group: 0},
					},
				},
				{
					Instance: 2, Domain: "list.example", Timestamp: 2, Flags: []string{"exploded", "feedhere"},
					Keys: []DKIM2Key{{Selector: "c", Algorithm: "ed25519-sha256", Group: 0}},
				},
			},
		},
		{
			name:     "No selector",
			headers:  []string{"i=1; m=1; t=1; d=example.com; mf=PD4=; rt=PD4="},
			expected: nil,
		},
		{
			name:     "No domain",
			headers:  []string{"i=1; m=1; t=1; s=sel:rsa-sha256:AAA="},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{Header: mail.Header{}}
			if tt.headers != nil {
				msg.Header["Dkim2-Signature"] = tt.headers
			}
			got := msg.DKIM2Signatures()
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("DKIM2Signatures() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

// A DKIM2-Signature is not a DKIM-Signature: each is read on its own, so a
// message carrying both is read as one signature of each kind.
func TestDKIM2SignaturesKeptApartFromDKIM(t *testing.T) {
	raw := "From: a@example.com\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=one; bh=x; b=y\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1; d=example.com; mf=PD4=; rt=PD4=; s=two:ed25519-sha256:AAA=\r\n" +
		"Message-Instance: m=1; h=sha256:AAA=:BBB=\r\n" +
		"\r\n" +
		"body\r\n"

	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if dkim := msg.DKIMSignatures(); len(dkim) != 1 || dkim[0].Selector != "one" {
		t.Errorf("DKIMSignatures() = %+v, want the one DKIM1 signature", dkim)
	}
	if dkim2 := msg.DKIM2Signatures(); len(dkim2) != 1 || dkim2[0].Keys[0].Selector != "two" {
		t.Errorf("DKIM2Signatures() = %+v, want the one DKIM2 signature", dkim2)
	}
}

// Algorithm names are case-sensitive: one in another case is not the algorithm.
func TestParseDKIM2SignatureKeepsAlgorithmCase(t *testing.T) {
	sig, ok := ParseDKIM2Signature("i=1; d=example.com; s=sel:RSA-SHA256:AAAA")
	if !ok || len(sig.Keys) != 1 || sig.Keys[0].Algorithm != "RSA-SHA256" {
		t.Errorf("ParseDKIM2Signature = %+v, %v", sig, ok)
	}
}
