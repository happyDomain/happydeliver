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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"strings"
	"testing"
)

// The next three tests exercise checkDKIMRecord's classification of a
// non-conforming TXT record found at the DKIM selector location. The
// decisive factor is the "v=" tag: an explicit "v=" that isn't "DKIM1"
// (e.g. a DMARC record) is reported as a foreign record, not a malformed
// DKIM one (TestCheckDKIMRecordRejectsForeignRecord); "v=DKIM1" present but
// no "p=" key is reported as a DKIM record missing its public key
// (TestCheckDKIMRecordMissingPublicKey); and no "v=" tag at all, with no
// "p=" either, is treated the same as a foreign record — an unrelated TXT
// value that happens to live at that name (TestCheckDKIMRecordUnrelatedTXT).
func TestCheckDKIMRecordRejectsForeignRecord(t *testing.T) {
	// A misbehaving resolver serving a DMARC record where the DKIM key should be
	// must not be reported as a malformed DKIM record.
	const phantom = "v=DMARC1;p=quarantine;pct=0;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;fo=1"

	analyzer := newMockAnalyzer(map[string][]string{
		"mail._domainkey.example.com": {phantom},
	}, nil)

	rec := analyzer.checkDKIMRecord(mailmsg.DKIMSignature{Domain: "example.com", Selector: "mail", Algorithm: "rsa-sha256"})
	if rec.Valid {
		t.Fatalf("expected DKIM record to be invalid, got valid")
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "No DKIM record found") {
		t.Errorf("Error = %v, want to contain %q", rec.Error, "No DKIM record found")
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "a DMARC record") {
		t.Errorf("Error = %v, want to mention the misplaced DMARC record", rec.Error)
	}
	// The extracted key metadata must not be populated from the foreign record.
	if rec.KeyType != nil || rec.KeySize != nil {
		t.Errorf("KeyType/KeySize should be nil for a non-DKIM record, got %v/%v", rec.KeyType, rec.KeySize)
	}
}

func TestCheckDKIMRecordMissingPublicKey(t *testing.T) {
	analyzer := newMockAnalyzer(map[string][]string{
		"mail._domainkey.example.com": {"v=DKIM1; k=rsa"},
	}, nil)

	rec := analyzer.checkDKIMRecord(mailmsg.DKIMSignature{Domain: "example.com", Selector: "mail"})
	if rec.Valid {
		t.Fatalf("expected DKIM record to be invalid, got valid")
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "public key") {
		t.Errorf("Error = %v, want to mention the missing public key", rec.Error)
	}
}

func TestCheckDKIMRecordUnrelatedTXT(t *testing.T) {
	// An unrelated TXT value (no DKIM version tag, no public key) served at the
	// DKIM location is not a malformed DKIM record; it is simply not a DKIM
	// record, and must not be reported as "missing the public key".
	analyzer := newMockAnalyzer(map[string][]string{
		"mail._domainkey.example.com": {"pardot123456=abcdef"},
	}, nil)

	rec := analyzer.checkDKIMRecord(mailmsg.DKIMSignature{Domain: "example.com", Selector: "mail"})
	if rec.Valid {
		t.Fatalf("expected DKIM record to be invalid, got valid")
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "No DKIM record found") {
		t.Errorf("Error = %v, want to contain %q", rec.Error, "No DKIM record found")
	}
	if rec.Error != nil && strings.Contains(*rec.Error, "public key") {
		t.Errorf("Error = %v, should not claim a missing public key for a non-DKIM record", rec.Error)
	}
}

func TestParseDKIMTags(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		wantTags map[string]string
	}{
		{
			name:     "standard RSA record",
			record:   "v=DKIM1; k=rsa; p=MIIBI; h=sha256",
			wantTags: map[string]string{"v": "DKIM1", "k": "rsa", "p": "MIIBI", "h": "sha256"},
		},
		{
			name:     "ed25519 record",
			record:   "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS",
			wantTags: map[string]string{"v": "DKIM1", "k": "ed25519", "p": "11qYAYKxCrfVS"},
		},
		{
			name:     "missing k= defaults",
			record:   "v=DKIM1; p=MIIBI",
			wantTags: map[string]string{"v": "DKIM1", "p": "MIIBI"},
		},
		{
			name:     "empty record",
			record:   "",
			wantTags: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDKIMTags(tt.record)
			for key, want := range tt.wantTags {
				if got[key] != want {
					t.Errorf("tag %q = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

// TestParseKeySize exercises parseKeySize, which derives a bit size from the
// "k=" and "p=" DKIM tags. For "ed25519" it always returns 256 regardless of
// "p="; for "rsa" (or an empty "k=", which defaults to RSA per RFC 6376) it
// base64-decodes "p=" (with or without padding) as a DER-encoded PKIX public
// key and returns its size in bits, e.g. a 2048-bit RSA key's DER yields
// 2048. It returns nil for an unrecognized key type, or for "rsa"/"" whose
// "p=" isn't valid base64 or doesn't decode to a parseable public key.
func TestParseKeySize(t *testing.T) {
	// Generate a real RSA key for testing
	rsaKey1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)

	der1024, _ := x509.MarshalPKIXPublicKey(&rsaKey1024.PublicKey)
	der2048, _ := x509.MarshalPKIXPublicKey(&rsaKey2048.PublicKey)

	p1024 := base64.StdEncoding.EncodeToString(der1024)
	p2048 := base64.StdEncoding.EncodeToString(der2048)

	tests := []struct {
		name    string
		keyType string
		p       string
		want    *int
	}{
		{
			name:    "RSA 1024",
			keyType: "rsa",
			p:       p1024,
			want:    intPtr(1024),
		},
		{
			name:    "RSA 2048",
			keyType: "rsa",
			p:       p2048,
			want:    intPtr(2048),
		},
		{
			name:    "Ed25519 always 256",
			keyType: "ed25519",
			p:       "11qYAYKxCrfVS",
			want:    intPtr(256),
		},
		{
			name:    "Unknown key type",
			keyType: "unknown",
			p:       "somedata",
			want:    nil,
		},
		{
			name:    "Invalid RSA base64",
			keyType: "rsa",
			p:       "!!!not-base64!!!",
			want:    nil,
		},
		{
			name:    "Empty k= defaults to RSA",
			keyType: "",
			p:       p2048,
			want:    intPtr(2048),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKeySize(tt.keyType, tt.p)
			if tt.want == nil {
				if got != nil {
					t.Errorf("parseKeySize(%q, ...) = %d, want nil", tt.keyType, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseKeySize(%q, ...) = nil, want %d", tt.keyType, *tt.want)
			}
			if *got != *tt.want {
				t.Errorf("parseKeySize(%q, ...) = %d, want %d", tt.keyType, *got, *tt.want)
			}
		})
	}
}

func intPtr(v int) *int { return &v }
