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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"git.happydns.org/happyDeliver/internal/model"
)

// --- Test fixtures -----------------------------------------------------------
//
// Every signature used here is produced at test time by go-msgauth's signer,
// against a key pair generated on the spot and published through a fake
// resolver. Nothing is hardcoded: the tests exercise the real end-to-end
// cryptographic chain (canonicalization → body hash → header hash → public key
// retrieval → signature verification), so a regression anywhere along it fails
// them.

// testMessage is the message every fixture is derived from. CRLF line endings
// are mandatory: DKIM signs the octets on the wire, not Go string literals.
const testMessage = "From: Sender <sender@example.com>\r\n" +
	"To: Recipient <recipient@example.net>\r\n" +
	"Subject: Test message\r\n" +
	"Date: Fri, 29 Aug 2026 09:33:07 +0200\r\n" +
	"Message-ID: <test-message@example.com>\r\n" +
	"\r\n" +
	"Hello, this is the body.\r\n"

// dkimKey is a signing key together with the DNS TXT record publishing it.
type dkimKey struct {
	signer crypto.Signer
	record string
}

// txtName returns the DNS name a signature with this selector and domain is
// looked up under.
func txtName(selector, domain string) string {
	return selector + "._domainkey." + domain
}

var (
	sharedRSAKeyOnce  sync.Once
	sharedRSAKeyValue dkimKey
	otherRSAKeyOnce   sync.Once
	otherRSAKeyValue  dkimKey
)

// sharedRSAKey returns the RSA key most tests sign with. Key generation is slow
// enough to be worth doing once for the whole package.
func sharedRSAKey(t *testing.T) dkimKey {
	t.Helper()
	sharedRSAKeyOnce.Do(func() { sharedRSAKeyValue = newRSAKey(t) })
	return sharedRSAKeyValue
}

// otherRSAKey returns a second, unrelated RSA key, used to publish the wrong
// public key for a signature.
func otherRSAKey(t *testing.T) dkimKey {
	t.Helper()
	otherRSAKeyOnce.Do(func() { otherRSAKeyValue = newRSAKey(t) })
	return otherRSAKeyValue
}

func newRSAKey(t *testing.T) dkimKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	return dkimKey{
		signer: key,
		record: "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der),
	}
}

func newEd25519Key(t *testing.T) dkimKey {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	// RFC 8463 section 3: the p= tag carries the raw 32-byte public key, not a
	// PKIX structure.
	return dkimKey{
		signer: priv,
		record: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub),
	}
}

// sign returns message signed by key for domain/selector, with the given
// canonicalization (empty means simple/simple, go-msgauth's default).
func sign(t *testing.T, message string, key dkimKey, domain, selector string, headerCan, bodyCan dkim.Canonicalization) string {
	t.Helper()

	var out bytes.Buffer
	err := dkim.Sign(&out, strings.NewReader(message), &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key.signer,
		HeaderCanonicalization: headerCan,
		BodyCanonicalization:   bodyCan,
	})
	if err != nil {
		t.Fatalf("dkim.Sign() error = %v", err)
	}

	return out.String()
}

// signRelaxed signs with relaxed/relaxed, by far the most common choice in the
// wild.
func signRelaxed(t *testing.T, message string, key dkimKey, domain, selector string) string {
	t.Helper()
	return sign(t, message, key, domain, selector, dkim.CanonicalizationRelaxed, dkim.CanonicalizationRelaxed)
}

// newTestDKIMVerifier builds a verifier resolving DKIM keys through a fake DNS.
func newTestDKIMVerifier(txt map[string][]string, errs map[string]error) *DKIMVerifier {
	if errs == nil {
		errs = map[string]error{}
	}
	return NewDKIMVerifier(&mockDNSResolver{txt: txt, err: errs}, 5*time.Second)
}

// wantResult is the expected shape of one model.AuthResult.
type wantResult struct {
	result   model.AuthResultResult
	domain   string
	selector string
	// detailsSubstr, when set, must appear in Details (case-insensitive).
	detailsSubstr string
}

func checkResults(t *testing.T, got []model.AuthResult, want []wantResult) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("VerifyDKIM() returned %d result(s), want %d: %+v", len(got), len(want), got)
	}

	for i, w := range want {
		g := got[i]

		if g.Result != w.result {
			t.Errorf("result[%d].Result = %q, want %q (details: %s)", i, g.Result, w.result, detailsOf(g))
		}
		if w.domain != "" && (g.Domain == nil || *g.Domain != w.domain) {
			t.Errorf("result[%d].Domain = %v, want %q", i, g.Domain, w.domain)
		}
		if w.selector != "" && (g.Selector == nil || *g.Selector != w.selector) {
			t.Errorf("result[%d].Selector = %v, want %q", i, g.Selector, w.selector)
		}
		if w.detailsSubstr != "" {
			if !strings.Contains(strings.ToLower(detailsOf(g)), strings.ToLower(w.detailsSubstr)) {
				t.Errorf("result[%d].Details = %q, want it to contain %q", i, detailsOf(g), w.detailsSubstr)
			}
		}
	}
}

func detailsOf(r model.AuthResult) string {
	if r.Details == nil {
		return ""
	}
	return *r.Details
}

// --- The cryptographic chain -------------------------------------------------

// TestVerifyDKIM walks the whole verification chain, one deviation at a time.
// Each case starts from a genuinely signed message and breaks exactly one link,
// so a "fail" can only come from the link the case is about.
func TestVerifyDKIM(t *testing.T) {
	tests := []struct {
		name string
		// build returns the raw message and the DNS zone to serve it against.
		build func(t *testing.T) (raw string, txt map[string][]string, errs map[string]error)
		want  []wantResult
	}{
		{
			name: "valid RSA signature, relaxed/relaxed",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				return signRelaxed(t, testMessage, key, "example.com", "test1"),
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "test1"}},
		},
		{
			// simple canonicalization hashes the header octets verbatim. It only
			// verifies if the message is fed to the verifier exactly as received,
			// which is what makes this case the guard against any lossy
			// re-serialisation of the headers before verification.
			name: "valid RSA signature, simple/simple",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				return sign(t, testMessage, key, "example.com", "test1", dkim.CanonicalizationSimple, dkim.CanonicalizationSimple),
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "test1"}},
		},
		{
			name: "valid Ed25519 signature",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := newEd25519Key(t)
				return signRelaxed(t, testMessage, key, "example.com", "ed1"),
					map[string][]string{txtName("ed1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "ed1"}},
		},
		{
			name: "body modified after signing",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				raw := signRelaxed(t, testMessage, key, "example.com", "test1")
				raw = strings.Replace(raw, "Hello, this is the body.", "Hello, this is the b0dy.", 1)
				return raw,
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultFail, domain: "example.com", detailsSubstr: "body hash"}},
		},
		{
			name: "signed header modified after signing",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				raw := signRelaxed(t, testMessage, key, "example.com", "test1")
				raw = strings.Replace(raw, "Subject: Test message", "Subject: Tampered subject", 1)
				return raw,
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultFail, domain: "example.com", detailsSubstr: "signature"}},
		},
		{
			name: "DNS publishes an unrelated public key",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				impostor := otherRSAKey(t)
				return signRelaxed(t, testMessage, key, "example.com", "test1"),
					map[string][]string{txtName("test1", "example.com"): {impostor.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultFail, domain: "example.com", detailsSubstr: "signature"}},
		},
		{
			name: "no key published for the selector",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				return signRelaxed(t, testMessage, key, "example.com", "test1"),
					map[string][]string{},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPermerror, domain: "example.com", detailsSubstr: "no key"}},
		},
		{
			name: "key revoked (empty p=)",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				return signRelaxed(t, testMessage, key, "example.com", "test1"),
					map[string][]string{txtName("test1", "example.com"): {"v=DKIM1; k=rsa; p="}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPermerror, domain: "example.com", detailsSubstr: "revoked"}},
		},
		{
			name: "temporary DNS failure",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				return signRelaxed(t, testMessage, key, "example.com", "test1"),
					map[string][]string{},
					map[string]error{
						txtName("test1", "example.com"): &net.DNSError{Err: "server misbehaving", IsTemporary: true},
					}
			},
			want: []wantResult{{result: model.AuthResultResultTemperror, domain: "example.com"}},
		},
		{
			// RFC 8301: rsa-sha1 must not be accepted, however well-formed the
			// rest of the signature is.
			name: "rsa-sha1 is refused",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				raw := signRelaxed(t, testMessage, key, "example.com", "test1")
				raw = strings.Replace(raw, "a=rsa-sha256", "a=rsa-sha1", 1)
				return raw,
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPermerror, domain: "example.com", detailsSubstr: "weak"}},
		},
		{
			// An l= tag leaves the tail of the body unsigned, so anything can be
			// appended to a "valid" message.
			name: "body length tag is refused",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				raw := signRelaxed(t, testMessage, key, "example.com", "test1")
				raw = strings.Replace(raw, "DKIM-Signature: ", "DKIM-Signature: l=10; ", 1)
				return raw,
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultFail, domain: "example.com", detailsSubstr: "body length"}},
		},
		{
			name: "signature does not cover the From header",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				key := sharedRSAKey(t)
				raw := signRelaxed(t, testMessage, key, "example.com", "test1")
				raw = strings.Replace(raw, "h=From:To:Subject:Date:Message-ID", "h=To:Subject:Date:Message-ID", 1)
				return raw,
					map[string][]string{txtName("test1", "example.com"): {key.record}},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPermerror, domain: "example.com", detailsSubstr: "from"}},
		},
		{
			name: "malformed signature tags",
			build: func(t *testing.T) (string, map[string][]string, map[string]error) {
				return "DKIM-Signature: this is not a tag list\r\n" + testMessage,
					map[string][]string{},
					nil
			},
			want: []wantResult{{result: model.AuthResultResultPermerror}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, txt, errs := tt.build(t)
			got := newTestDKIMVerifier(txt, errs).VerifyDKIM([]byte(raw))
			checkResults(t, got, tt.want)
		})
	}
}

// TestVerifyDKIMMultipleSignatures checks that each signature is reported
// separately, in header order, and that one broken signature does not affect
// the verdict of the others — the exact situation of an ESP signing on behalf of
// a customer domain.
func TestVerifyDKIMMultipleSignatures(t *testing.T) {
	good := sharedRSAKey(t)
	broken := otherRSAKey(t)

	// The inner signature is applied first, so it ends up below the outer one.
	raw := signRelaxed(t, testMessage, broken, "esp.example.net", "inner")
	raw = signRelaxed(t, raw, good, "example.com", "outer")

	verifier := newTestDKIMVerifier(map[string][]string{
		txtName("outer", "example.com"): {good.record},
		// The ESP selector publishes a key its signature was not made with.
		txtName("inner", "esp.example.net"): {good.record},
	}, nil)

	got := verifier.VerifyDKIM([]byte(raw))

	// The ESP signature is verified against a key it was not signed with, and
	// must fail on its own without dragging the valid one down.
	checkResults(t, got, []wantResult{
		{result: model.AuthResultResultPass, domain: "example.com", selector: "outer"},
		{result: model.AuthResultResultFail, domain: "esp.example.net", selector: "inner"},
	})
}

// TestVerifyDKIMBothSignaturesValid is the shape of the message that motivated
// this work: two independent valid signatures, one from the author domain and
// one from its sending platform.
func TestVerifyDKIMBothSignaturesValid(t *testing.T) {
	author := sharedRSAKey(t)
	platform := newEd25519Key(t)

	raw := signRelaxed(t, testMessage, platform, "mta.example.net", "platform")
	raw = signRelaxed(t, raw, author, "example.com", "author")

	verifier := newTestDKIMVerifier(map[string][]string{
		txtName("author", "example.com"):       {author.record},
		txtName("platform", "mta.example.net"): {platform.record},
	}, nil)

	checkResults(t, verifier.VerifyDKIM([]byte(raw)), []wantResult{
		{result: model.AuthResultResultPass, domain: "example.com", selector: "author"},
		{result: model.AuthResultResultPass, domain: "mta.example.net", selector: "platform"},
	})
}

// TestVerifyDKIMSignatureCap bounds the work an uploaded EML can ask for: a
// message stuffed with signatures must not turn into an unbounded number of DNS
// lookups and public key operations.
func TestVerifyDKIMSignatureCap(t *testing.T) {
	key := sharedRSAKey(t)

	raw := testMessage
	for range maxDKIMVerifications + 3 {
		raw = signRelaxed(t, raw, key, "example.com", "test1")
	}

	got := newTestDKIMVerifier(map[string][]string{
		txtName("test1", "example.com"): {key.record},
	}, nil).VerifyDKIM([]byte(raw))

	if len(got) != maxDKIMVerifications {
		t.Fatalf("VerifyDKIM() returned %d result(s), want the cap of %d", len(got), maxDKIMVerifications)
	}
	for i, r := range got {
		if r.Result != model.AuthResultResultPass {
			t.Errorf("result[%d].Result = %q, want pass (details: %s)", i, r.Result, detailsOf(r))
		}
	}
}

// TestVerifyDKIMNothingToVerify covers the inputs that must yield no result at
// all rather than a verdict: a verdict on an absent signature would be a claim
// we cannot make.
func TestVerifyDKIMNothingToVerify(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"no DKIM-Signature header", testMessage},
		{"empty input", ""},
		{"headers only, no body separator", "From: sender@example.com\r\nSubject: truncated\r\n"},
		{"not an email at all", "\x00\x01\x02 garbage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newTestDKIMVerifier(nil, nil).VerifyDKIM([]byte(tt.raw))
			if len(got) != 0 {
				t.Errorf("VerifyDKIM() = %+v, want no result", got)
			}
		})
	}
}

// TestVerifyDKIMNilVerifier makes the zero-dependency path safe: an analyzer
// built without a resolver must decline rather than panic.
func TestVerifyDKIMNilVerifier(t *testing.T) {
	var v *DKIMVerifier
	if got := v.VerifyDKIM([]byte(testMessage)); got != nil {
		t.Errorf("VerifyDKIM() on nil verifier = %+v, want nil", got)
	}
}

// --- The raw message must survive parsing ------------------------------------

// TestParseEmailPreservesRaw is the foundation everything above rests on: DKIM
// signs the octets as received, so the parser must hand them back untouched.
// The reconstructed RawHeaders field is not a substitute — it reorders fields,
// unfolds them and normalises their case.
func TestParseEmailPreservesRaw(t *testing.T) {
	key := sharedRSAKey(t)
	raw := sign(t, testMessage, key, "example.com", "test1", dkim.CanonicalizationSimple, dkim.CanonicalizationSimple)

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if !bytes.Equal(email.Raw, []byte(raw)) {
		t.Errorf("ParseEmail() did not preserve the message octets:\n got %q\nwant %q", email.Raw, raw)
	}

	// And the preserved bytes must still verify, which they only can if not a
	// single octet moved.
	got := newTestDKIMVerifier(map[string][]string{
		txtName("test1", "example.com"): {key.record},
	}, nil).VerifyDKIM(email.Raw)

	checkResults(t, got, []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "test1"}})
}

// TestParseEmailPreservesRawWithFoldedHeaders guards the same property on the
// header shapes a rebuilt string cannot reproduce: continuation lines, tabs and
// non-canonical field-name case.
func TestParseEmailPreservesRawWithFoldedHeaders(t *testing.T) {
	raw := "from: Sender <sender@example.com>\r\n" +
		"To: Recipient <recipient@example.net>,\r\n" +
		"\tOther <other@example.net>\r\n" +
		"SUBJECT: A subject\r\n" +
		"  folded onto a second line\r\n" +
		"\r\n" +
		"body\r\n"

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	if !bytes.Equal(email.Raw, []byte(raw)) {
		t.Errorf("ParseEmail() did not preserve the message octets:\n got %q\nwant %q", email.Raw, raw)
	}
}

// TestVerifyDKIMOnMIMEMessage checks the multipart path, where the body used to
// be consumed by the MIME reader and lost.
func TestVerifyDKIMOnMIMEMessage(t *testing.T) {
	key := sharedRSAKey(t)

	const boundary = "boundary42"
	mime := "From: Sender <sender@example.com>\r\n" +
		"To: Recipient <recipient@example.net>\r\n" +
		"Subject: Multipart\r\n" +
		"Date: Fri, 29 Aug 2026 09:33:07 +0200\r\n" +
		"Message-ID: <mime@example.com>\r\n" +
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q\r\n", boundary) +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Plain text part.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<p>HTML part.</p>\r\n" +
		"--" + boundary + "--\r\n"

	raw := signRelaxed(t, mime, key, "example.com", "test1")

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	got := newTestDKIMVerifier(map[string][]string{
		txtName("test1", "example.com"): {key.record},
	}, nil).VerifyDKIM(email.Raw)

	checkResults(t, got, []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "test1"}})
}

// --- Where the verdict lands in the analysis ---------------------------------
//
// The rule the tests below pin down: a first-hand verification only ever fills
// a gap. Whenever a trusted Authentication-Results header already carries a
// dkim= verdict, that verdict is the receiver's own measurement — taken on the
// message as it stood there, before any hop we cannot see — and it stands.

// newTestAuthAnalyzer builds an authentication analyzer that verifies DKIM
// through a fake DNS.
func newTestAuthAnalyzer(receiverHostname string, txt map[string][]string) *AuthenticationAnalyzer {
	a := NewAuthenticationAnalyzer(receiverHostname)
	a.dkimVerifier = newTestDKIMVerifier(txt, nil)
	return a
}

func parseTestEmail(t *testing.T, raw string) *EmailMessage {
	t.Helper()

	email, err := ParseEmail(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}
	return email
}

// TestAnalyzeAuthenticationVerifiesWhenNoAuthResults covers the plain case: the
// message states no dkim= we trust, so we compute one ourselves instead of
// leaving the message unjudged.
func TestAnalyzeAuthenticationVerifiesWhenNoAuthResults(t *testing.T) {
	key := sharedRSAKey(t)
	email := parseTestEmail(t, signRelaxed(t, testMessage, key, "example.com", "sel1"))

	analyzer := newTestAuthAnalyzer("", map[string][]string{
		txtName("sel1", "example.com"): {key.record},
	})

	results := analyzer.AnalyzeAuthentication(email, "")
	if results.Dkim == nil {
		t.Fatal("AnalyzeAuthentication() left Dkim nil, want the verified signature")
	}

	checkResults(t, *results.Dkim, []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "sel1"}})
}

// TestAnalyzeAuthenticationVerifiesFailure checks the gap is filled even when
// the answer is bad news: a signature that does not verify must be reported as
// a fail, not dropped for lack of a verdict to agree with.
func TestAnalyzeAuthenticationVerifiesFailure(t *testing.T) {
	key := sharedRSAKey(t)
	email := parseTestEmail(t, signRelaxed(t, testMessage, key, "example.com", "sel1"))

	// Publish somebody else's public key at the signature's location.
	analyzer := newTestAuthAnalyzer("", map[string][]string{
		txtName("sel1", "example.com"): {otherRSAKey(t).record},
	})

	results := analyzer.AnalyzeAuthentication(email, "")
	if results.Dkim == nil {
		t.Fatal("AnalyzeAuthentication() left Dkim nil, want the failed signature")
	}

	checkResults(t, *results.Dkim, []wantResult{{result: model.AuthResultResultFail, domain: "example.com", selector: "sel1"}})
}

// TestAnalyzeAuthenticationKeepsTrustedAuthResults is the important one: a
// trusted Authentication-Results carries dkim=fail while the signature verifies
// here and now. The reported verdict must stay the trusted one — our own
// verification says nothing about what the recipient's server saw.
func TestAnalyzeAuthenticationKeepsTrustedAuthResults(t *testing.T) {
	key := sharedRSAKey(t)
	signed := signRelaxed(t, testMessage, key, "example.com", "sel1")
	email := parseTestEmail(t, "Authentication-Results: mx.example.net; dkim=fail header.d=example.com header.s=sel1\r\n"+signed)

	analyzer := newTestAuthAnalyzer("mx.example.net", map[string][]string{
		txtName("sel1", "example.com"): {key.record},
	})

	results := analyzer.AnalyzeAuthentication(email, "mx.example.net")
	if results.Dkim == nil || len(*results.Dkim) != 1 {
		t.Fatalf("AnalyzeAuthentication() Dkim = %+v, want the single reported result", results.Dkim)
	}

	checkResults(t, *results.Dkim, []wantResult{{result: model.AuthResultResultFail, domain: "example.com"}})
}

// TestAnalyzeAuthenticationVerifiesPastUntrustedAuthResults guards the other
// half of the rule: a header we do not trust is not a verdict at all, so the
// gap it appears to fill is still a gap.
func TestAnalyzeAuthenticationVerifiesPastUntrustedAuthResults(t *testing.T) {
	key := sharedRSAKey(t)
	signed := signRelaxed(t, testMessage, key, "example.com", "sel1")
	email := parseTestEmail(t, "Authentication-Results: mx.example.org; dkim=fail header.d=example.com header.s=sel1\r\n"+signed)

	analyzer := newTestAuthAnalyzer("mx.example.net", map[string][]string{
		txtName("sel1", "example.com"): {key.record},
	})

	results := analyzer.AnalyzeAuthentication(email, "mx.example.net")
	if results.Dkim == nil {
		t.Fatal("AnalyzeAuthentication() left Dkim nil, want the verified signature")
	}

	checkResults(t, *results.Dkim, []wantResult{{result: model.AuthResultResultPass, domain: "example.com", selector: "sel1"}})
}

// TestAnalyzeAuthenticationWithoutVerifier checks the analyzer built without a
// resolver stays what it always was: a reader of other servers' verdicts, which
// reaches no network of its own.
func TestAnalyzeAuthenticationWithoutVerifier(t *testing.T) {
	key := sharedRSAKey(t)
	email := parseTestEmail(t, signRelaxed(t, testMessage, key, "example.com", "sel1"))

	results := NewAuthenticationAnalyzer("").AnalyzeAuthentication(email, "")
	if results.Dkim != nil {
		t.Errorf("AnalyzeAuthentication() Dkim = %+v, want nil without a verifier", *results.Dkim)
	}
}
