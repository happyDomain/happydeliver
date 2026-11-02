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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"reflect"
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// testKeys holds base64 public keys in each of the forms the tests publish.
type testKeys struct {
	rsaSPKI, rsaPKCS1, rsa1024, ed25519Raw, ed25519SPKI, mldsa44 string
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallSPKI, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSPKI, _ := x509.MarshalPKIXPublicKey(edPub)

	return testKeys{
		rsaSPKI:     b64(spki),
		rsaPKCS1:    b64(x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)),
		rsa1024:     b64(smallSPKI),
		ed25519Raw:  b64(edPub),
		ed25519SPKI: b64(edSPKI),
		mldsa44:     b64(make([]byte, mldsa44KeyLen)),
	}
}

func TestCheckDKIM2Record(t *testing.T) {
	keys := newTestKeys(t)
	const name = "sel._domainkey.example.com"

	tests := []struct {
		name           string
		algorithm      string
		txt            []string
		err            error
		wantValid      bool
		wantErr        string
		wantKeyType    string
		wantSize       int
		wantDeprecated []string
	}{
		{
			name:        "RSA, SubjectPublicKeyInfo",
			algorithm:   "rsa-sha256",
			txt:         []string{"v=DKIM1; k=rsa; p=" + keys.rsaSPKI},
			wantValid:   true,
			wantKeyType: "rsa",
			wantSize:    2048,
		},
		{
			name:        "RSA, bare RSAPublicKey, no k=",
			algorithm:   "rsa-sha256",
			txt:         []string{"v=DKIM1; p=" + keys.rsaPKCS1},
			wantValid:   true,
			wantKeyType: "rsa",
			wantSize:    2048,
		},
		{
			name:           "Ed25519, raw key, shared with DKIM1 (deprecated tags)",
			algorithm:      "ed25519-sha256",
			txt:            []string{"v=DKIM1; k=ed25519; h=sha256; t=s; p=" + keys.ed25519Raw},
			wantValid:      true,
			wantKeyType:    "ed25519",
			wantSize:       256,
			wantDeprecated: []string{"h", "t"},
		},
		{
			name:        "ML-DSA-44",
			algorithm:   "mldsa44",
			txt:         []string{"v=DKIM1; k=mldsa44; p=" + keys.mldsa44},
			wantValid:   true,
			wantKeyType: "mldsa44",
		},
		{
			name:      "Ed25519 published as DER",
			algorithm: "ed25519-sha256",
			txt:       []string{"v=DKIM1; k=ed25519; p=" + keys.ed25519SPKI},
			wantErr:   "PERMERROR: DKIM2-Signature i=1 public key sel is malformed",
		},
		{
			name:      "Key without its base64 padding",
			algorithm: "ed25519-sha256",
			txt:       []string{"v=DKIM1; k=ed25519; p=" + strings.TrimRight(keys.ed25519Raw, "=")},
			wantErr:   "PERMERROR: DKIM2-Signature i=1 public key sel has a syntax error",
		},
		{
			name:      "Base64 padded with non-zero bits",
			algorithm: "ed25519-sha256",
			txt:       []string{"v=DKIM1; k=ed25519; p=" + strings.TrimRight(keys.ed25519Raw, "=")[:42] + "B="},
			wantErr:   "PERMERROR: DKIM2-Signature i=1 public key sel has a syntax error",
		},
		{
			name:      "Algorithm mismatch",
			algorithm: "ed25519-sha256",
			txt:       []string{"v=DKIM1; k=rsa; p=" + keys.rsaSPKI},
			wantErr:   "algorithm mismatch",
		},
		{
			name:      "Revoked",
			algorithm: "rsa-sha256",
			txt:       []string{"v=DKIM1; k=rsa; p="},
			wantErr:   "has been revoked",
		},
		{
			name:        "RSA key under the minimum",
			algorithm:   "rsa-sha256",
			txt:         []string{"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALaDWvsIj/qbQhiW5d3uy7lAS1qLpaZ9rkLDAxQv43iqNFNu8SW1slIjKHYfcUSPZHgeyNYd4OI9BlEmk0SaVw0CAwEAAQ=="},
			wantErr:     "PERMERROR: DKIM2-Signature i=1 public key sel too short",
			wantKeyType: "rsa",
			wantSize:    512,
		},
		{
			name:      "Algorithm no draft defines",
			algorithm: "rsa-sha512",
			txt:       []string{"v=DKIM1; k=rsa; p=" + keys.rsaSPKI},
			wantErr:   "PERMERROR: DKIM2-Signature i=1 selector sel algorithm unknown",
		},
		{
			name:      "Unknown algorithm",
			algorithm: "rsa-sha1",
			txt:       []string{"v=DKIM1; p=" + keys.rsaSPKI},
			wantErr:   "PERMERROR: DKIM2-Signature i=1 selector sel algorithm unknown",
		},
		{
			name:      "Duplicate tag",
			algorithm: "rsa-sha256",
			txt:       []string{"v=DKIM1; p=" + keys.rsaSPKI + "; p=" + keys.rsaSPKI},
			wantErr:   "has a syntax error",
		},
		{
			name:      "Multiple records",
			algorithm: "rsa-sha256",
			txt:       []string{"v=DKIM1; p=" + keys.rsaSPKI, "p=" + keys.rsaPKCS1},
			wantErr:   "has multiple records",
		},
		{
			name:      "Only a foreign record",
			algorithm: "rsa-sha256",
			txt:       []string{"v=DMARC1; p=none"},
			wantErr:   "does not exist (a DMARC record is published there instead)",
		},
		{
			name:      "No record",
			algorithm: "rsa-sha256",
			wantErr:   "PERMERROR: DKIM2-Signature i=1 public key sel does not exist",
		},
		{
			name:      "DNS failure",
			algorithm: "rsa-sha256",
			err:       &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true},
			wantErr:   "TEMPERROR: DKIM2-Signature i=1 public key sel could not be fetched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt := map[string][]string{}
			if tt.txt != nil {
				txt[name] = tt.txt
			}
			errs := map[string]error{}
			if tt.err != nil {
				errs[name] = tt.err
			}
			analyzer := newMockAnalyzer(txt, errs)

			rec := analyzer.checkDKIM2Record(
				mailmsg.DKIM2Signature{Instance: 1, Domain: "example.com"},
				mailmsg.DKIM2Key{Selector: "sel", Algorithm: tt.algorithm},
			)

			if rec.Valid != tt.wantValid {
				t.Fatalf("Valid = %v (error %q), want %v", rec.Valid, utils.Deref(rec.Error), tt.wantValid)
			}
			if tt.wantErr != "" && !strings.Contains(utils.Deref(rec.Error), tt.wantErr) {
				t.Errorf("Error = %q, want it to contain %q", utils.Deref(rec.Error), tt.wantErr)
			}
			if tt.wantKeyType != "" && utils.Deref(rec.KeyType) != tt.wantKeyType {
				t.Errorf("KeyType = %q, want %q", utils.Deref(rec.KeyType), tt.wantKeyType)
			}
			if utils.Deref(rec.KeySize) != tt.wantSize {
				t.Errorf("KeySize = %d, want %d", utils.Deref(rec.KeySize), tt.wantSize)
			}
			if !reflect.DeepEqual(utils.Deref(rec.DeprecatedTags), tt.wantDeprecated) {
				t.Errorf("DeprecatedTags = %v, want %v", utils.Deref(rec.DeprecatedTags), tt.wantDeprecated)
			}
		})
	}
}

func TestCheckDKIM2PolicyRecord(t *testing.T) {
	tests := []struct {
		name       string
		txt        []string
		wantValid  bool
		wantStrict *bool
		wantRecord bool
	}{
		{name: "No record", wantValid: true},
		{name: "DomainKeys policy only, ignored", txt: []string{"o=~; r=postmaster@example.com"}, wantValid: true},
		{name: "Strict", txt: []string{"v=DKIM1; f=strict"}, wantValid: true, wantStrict: utils.PtrTo(true), wantRecord: true},
		{name: "No flag", txt: []string{"v=DKIM1"}, wantValid: true, wantStrict: utils.PtrTo(false), wantRecord: true},
		{name: "Several", txt: []string{"v=DKIM1", "v=DKIM1; f=strict"}, wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt := map[string][]string{}
			if tt.txt != nil {
				txt["_domainkey.example.com"] = tt.txt
			}
			rec := newMockAnalyzer(txt, nil).checkDKIM2PolicyRecord("example.com")

			if rec.Valid != tt.wantValid {
				t.Fatalf("Valid = %v (error %q), want %v", rec.Valid, utils.Deref(rec.Error), tt.wantValid)
			}
			if !reflect.DeepEqual(rec.Strict, tt.wantStrict) {
				t.Errorf("Strict = %v, want %v", rec.Strict, tt.wantStrict)
			}
			if (rec.Record != nil) != tt.wantRecord {
				t.Errorf("Record = %v, want one: %v", rec.Record, tt.wantRecord)
			}
		})
	}
}

func TestDKIM2KeyIssues(t *testing.T) {
	valid := func(i, alt int, selector string) model.DKIM2Record {
		return model.DKIM2Record{Instance: i, Alternative: utils.PtrTo(alt), Selector: selector, Domain: "example.com", KeyType: utils.PtrTo("rsa"), KeySize: utils.PtrTo(2048), Valid: true}
	}
	invalid := func(i, alt int, selector string) model.DKIM2Record {
		return model.DKIM2Record{Instance: i, Alternative: utils.PtrTo(alt), Selector: selector, Domain: "example.com", Valid: false, Error: utils.PtrTo("PERMERROR: DKIM2-Signature public key " + selector + " does not exist")}
	}
	weakAt := func(i int) model.DKIM2Record {
		rec := valid(i, 1, "weak")
		rec.KeySize = utils.PtrTo(1024)
		return rec
	}
	weak := weakAt(1)

	tests := []struct {
		name       string
		records    []model.DKIM2Record
		wantPoints int
		wantTypes  []model.IssueType
	}{
		{
			name:    "All good",
			records: []model.DKIM2Record{valid(1, 0, "a"), valid(1, 1, "b")},
		},
		{
			name:    "One alternative of two unusable: the signature still verifies",
			records: []model.DKIM2Record{invalid(1, 0, "a"), valid(1, 1, "b")},
		},
		{
			name:       "Both signatures of a hybrid group are required",
			records:    []model.DKIM2Record{invalid(1, 0, "a"), valid(1, 0, "b")},
			wantPoints: dkim2PenaltyInvalid,
			wantTypes:  []model.IssueType{model.IssueTypeDkim2Invalid},
		},
		{
			name:       "Penalties never exceed the maximum",
			records:    []model.DKIM2Record{invalid(1, 0, "a"), invalid(2, 0, "b"), weakAt(3)},
			wantPoints: dkim2PenaltyMax,
			wantTypes:  []model.IssueType{model.IssueTypeDkim2Invalid, model.IssueTypeDkim2Invalid, model.IssueTypeDkim2KeyWeak},
		},
		{
			name:       "Weak RSA key",
			records:    []model.DKIM2Record{valid(1, 0, "a"), weak},
			wantPoints: dkim2PenaltyKeyWeak,
			wantTypes:  []model.IssueType{model.IssueTypeDkim2KeyWeak},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, points := dkim2KeyIssues(&model.DNSResults{Dkim2Records: &tt.records})
			if points != tt.wantPoints {
				t.Errorf("points = %d, want %d", points, tt.wantPoints)
			}
			var types []model.IssueType
			total := 0
			for _, issue := range issues {
				types = append(types, issue.Type)
				total += utils.Deref(issue.Penalty)
			}
			if !reflect.DeepEqual(types, tt.wantTypes) {
				t.Errorf("issue types = %v, want %v", types, tt.wantTypes)
			}
			if total != points {
				t.Errorf("issues charge %d points, the score loses %d", total, points)
			}
		})
	}
}

// A message signed with DKIM2 only loses half the DKIM check, not all of it;
// one signed with nothing loses it all, as before.
func TestCalculateDKIMScoreDKIM2Only(t *testing.T) {
	d := newMockAnalyzer(nil, nil)

	score, issues := d.calculateDKIMScore(&model.DNSResults{
		FromDomain:   "example.com",
		Dkim2Records: &[]model.DKIM2Record{{Instance: 1, Selector: "s", Domain: "example.com", Valid: true}},
	})
	if score != 50 || len(issues) != 1 || issues[0].Type != model.IssueTypeDkimMissing || issues[0].Severity != model.IssueSeverityMedium {
		t.Errorf("DKIM2 only: score %d, issues %+v; want 50 and one medium dkim_missing", score, issues)
	}

	score, issues = d.calculateDKIMScore(&model.DNSResults{FromDomain: "example.com"})
	if score != 0 || len(issues) != 1 || issues[0].Severity != model.IssueSeverityHigh {
		t.Errorf("unsigned: score %d, issues %+v; want 0 and one high dkim_missing", score, issues)
	}
}

// Both kinds of signature are looked up, each on its own: the same key may
// serve both.
func TestAnalyzeDNSWithDKIMAndDKIM2(t *testing.T) {
	keys := newTestKeys(t)
	raw := "From: sender@example.com\r\n" +
		"To: test@happydeliver.local\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=shared; bh=x; b=y\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1; d=example.com; mf=PD4=; rt=PD4=;\r\n s=shared:rsa-sha256:AAA=|ed:ed25519-sha256:BBB=\r\n" +
		"\r\nbody\r\n"
	email, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	analyzer := newMockAnalyzer(map[string][]string{
		"shared._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + keys.rsaSPKI},
		"ed._domainkey.example.com":     {"v=DKIM1; k=ed25519; p=" + keys.ed25519Raw},
		"_domainkey.example.com":        {"v=DKIM1; f=strict"},
	}, nil)

	headers := &model.HeaderAnalysis{DomainAlignment: &model.DomainAlignment{FromDomain: utils.PtrTo("example.com")}}
	results := analyzer.AnalyzeDNS(email, headers, nil)

	if results.DkimRecords == nil || len(*results.DkimRecords) != 1 || !(*results.DkimRecords)[0].Valid {
		t.Fatalf("DKIM records = %+v, want the one valid key", results.DkimRecords)
	}
	if results.Dkim2Records == nil || len(*results.Dkim2Records) != 2 {
		t.Fatalf("DKIM2 records = %+v, want two keys", results.Dkim2Records)
	}
	for _, rec := range *results.Dkim2Records {
		if !rec.Valid {
			t.Errorf("DKIM2 key %s invalid: %s", rec.Selector, utils.Deref(rec.Error))
		}
	}
	if results.Dkim2PolicyRecords == nil || len(*results.Dkim2PolicyRecords) != 1 || !utils.Deref((*results.Dkim2PolicyRecords)[0].Strict) {
		t.Errorf("DKIM2 policy = %+v, want strict", results.Dkim2PolicyRecords)
	}
}

// A selector a signature names twice is reported rather than looked up twice.
func TestCheckDKIM2RecordsDuplicateSelector(t *testing.T) {
	keys := newTestKeys(t)
	analyzer := newMockAnalyzer(map[string][]string{
		"sel._domainkey.example.com": {"v=DKIM1; p=" + keys.rsaSPKI},
	}, nil)

	records := analyzer.checkDKIM2Records([]mailmsg.DKIM2Signature{{
		Instance: 1,
		Domain:   "example.com",
		Keys: []mailmsg.DKIM2Key{
			{Selector: "sel", Algorithm: "rsa-sha256", Group: 0},
			{Selector: "sel", Algorithm: "rsa-sha256", Group: 1},
		},
	}})

	if len(records) != 2 || !records[0].Valid || records[1].Valid {
		t.Fatalf("records = %+v, want the first valid and the repeated one not", records)
	}
	if !strings.Contains(utils.Deref(records[1].Error), "PERMERROR: DKIM2-Signature i=1 has a duplicate selector") {
		t.Errorf("Error = %q", utils.Deref(records[1].Error))
	}
}
