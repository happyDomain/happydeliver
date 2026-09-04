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
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func TestParseSPFResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   model.AuthResultResult
		expectedDomain   string
		expectedIdentity string
	}{
		{
			name:             "SPF pass with domain",
			part:             "spf=pass smtp.mailfrom=sender@example.com",
			expectedResult:   model.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedIdentity: "mailfrom",
		},
		{
			name:             "SPF fail",
			part:             "spf=fail smtp.mailfrom=sender@example.com",
			expectedResult:   model.AuthResultResultFail,
			expectedDomain:   "example.com",
			expectedIdentity: "mailfrom",
		},
		{
			name:             "SPF neutral",
			part:             "spf=neutral smtp.mailfrom=sender@example.com",
			expectedResult:   model.AuthResultResultNeutral,
			expectedDomain:   "example.com",
			expectedIdentity: "mailfrom",
		},
		{
			name:             "SPF softfail",
			part:             "spf=softfail smtp.mailfrom=sender@example.com",
			expectedResult:   model.AuthResultResultSoftfail,
			expectedDomain:   "example.com",
			expectedIdentity: "mailfrom",
		},
		{
			// The HELO check authenticates the announced hostname, not a sender
			name:             "SPF on the HELO identity",
			part:             "spf=pass (localhost) smtp.helo=mail.example.net",
			expectedResult:   model.AuthResultResultPass,
			expectedDomain:   "mail.example.net",
			expectedIdentity: "helo",
		},
		{
			// Some receivers wrap the reported address in angle brackets
			name:             "SPF pass with a bracketed envelope sender",
			part:             "spf=pass smtp.mailfrom=<sender@example.com>",
			expectedResult:   model.AuthResultResultPass,
			expectedDomain:   "example.com",
			expectedIdentity: "mailfrom",
		},
		{
			// A bounce has a null envelope sender, which names no domain at all
			name:             "SPF on the null envelope sender",
			part:             "spf=none smtp.mailfrom=<>",
			expectedResult:   model.AuthResultResultNone,
			expectedIdentity: "mailfrom",
		},
		{
			name:           "SPF without ptype",
			part:           "spf=pass",
			expectedResult: model.AuthResultResultPass,
		},
	}

	analyzer := NewAuthenticationAnalyzer("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseSPFResult(tt.part)

			assertSPFResult(t, "spf", result, tt.expectedResult, tt.expectedDomain, tt.expectedIdentity)
		})
	}
}

func TestParseLegacySPF(t *testing.T) {
	tests := []struct {
		name           string
		receivedSPF    string
		expectedResult model.AuthResultResult
		expectedDomain *string
		expectNil      bool
	}{
		{
			name: "SPF pass with envelope-from",
			receivedSPF: `pass
    (mail.example.com: 192.0.2.10 is authorized to use 'user@example.com' in 'mfrom' identity (mechanism 'ip4:192.0.2.10' matched))
    receiver=mx.receiver.com;
    identity=mailfrom;
    envelope-from="user@example.com";
    helo=smtp.example.com;
    client-ip=192.0.2.10`,
			expectedResult: model.AuthResultResultPass,
			expectedDomain: utils.PtrTo("example.com"),
		},
		{
			name: "SPF fail with sender",
			receivedSPF: `fail
    (mail.example.com: domain of sender@test.com does not designate 192.0.2.20 as permitted sender)
    receiver=mx.receiver.com;
    identity=mailfrom;
    sender="sender@test.com";
    helo=smtp.test.com;
    client-ip=192.0.2.20`,
			expectedResult: model.AuthResultResultFail,
			expectedDomain: utils.PtrTo("test.com"),
		},
		{
			name:           "SPF softfail",
			receivedSPF:    "softfail (example.com: transitioning domain of admin@example.org does not designate 192.0.2.30 as permitted sender) envelope-from=\"admin@example.org\"",
			expectedResult: model.AuthResultResultSoftfail,
			expectedDomain: utils.PtrTo("example.org"),
		},
		{
			name:           "SPF neutral",
			receivedSPF:    "neutral (example.com: 192.0.2.40 is neither permitted nor denied by domain of info@domain.net) envelope-from=\"info@domain.net\"",
			expectedResult: model.AuthResultResultNeutral,
			expectedDomain: utils.PtrTo("domain.net"),
		},
		{
			name:           "SPF none",
			receivedSPF:    "none (example.com: domain of noreply@company.io has no SPF record) envelope-from=\"noreply@company.io\"",
			expectedResult: model.AuthResultResultNone,
			expectedDomain: utils.PtrTo("company.io"),
		},
		{
			name:           "SPF temperror",
			receivedSPF:    "temperror (example.com: error in processing SPF record) envelope-from=\"support@shop.example\"",
			expectedResult: model.AuthResultResultTemperror,
			expectedDomain: utils.PtrTo("shop.example"),
		},
		{
			name:           "SPF permerror",
			receivedSPF:    "permerror (example.com: domain of contact@invalid.test has invalid SPF record) envelope-from=\"contact@invalid.test\"",
			expectedResult: model.AuthResultResultPermerror,
			expectedDomain: utils.PtrTo("invalid.test"),
		},
		{
			name:           "SPF pass without domain extraction",
			receivedSPF:    "pass (example.com: 192.0.2.50 is authorized)",
			expectedResult: model.AuthResultResultPass,
			expectedDomain: nil,
		},
		{
			name:        "Empty Received-SPF header",
			receivedSPF: "",
			expectNil:   true,
		},
		{
			name:           "SPF with unquoted envelope-from",
			receivedSPF:    "pass (example.com: sender SPF authorized) envelope-from=postmaster@mail.example.net",
			expectedResult: model.AuthResultResultPass,
			expectedDomain: utils.PtrTo("mail.example.net"),
		},
		{
			name:           "SPF with a bracketed envelope-from",
			receivedSPF:    `pass (example.com: sender SPF authorized) envelope-from="<user@example.com>"`,
			expectedResult: model.AuthResultResultPass,
			expectedDomain: utils.PtrTo("example.com"),
		},
		{
			// A bounce has a null envelope sender, which names no domain at all
			name:           "SPF on the null envelope sender",
			receivedSPF:    `none (example.com: no SPF record) envelope-from="<>"`,
			expectedResult: model.AuthResultResultNone,
			expectedDomain: nil,
		},
	}

	analyzer := NewAuthenticationAnalyzer("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock email message with Received-SPF header
			email := &EmailMessage{
				Header: make(map[string][]string),
			}
			if tt.receivedSPF != "" {
				email.Header["Received-Spf"] = []string{tt.receivedSPF}
			}

			result, helo := analyzer.parseLegacySPF(email, "")

			// None of these headers reports the HELO identity
			if helo != nil {
				t.Errorf("spf_helo = %+v, want none", *helo)
			}

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result, got nil")
			}

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}

			if tt.expectedDomain != nil {
				if result.Domain == nil {
					t.Errorf("Domain = nil, want %v", *tt.expectedDomain)
				} else if *result.Domain != *tt.expectedDomain {
					t.Errorf("Domain = %v, want %v", *result.Domain, *tt.expectedDomain)
				}
			} else {
				if result.Domain != nil {
					t.Errorf("Domain = %v, want nil", *result.Domain)
				}
			}

			if result.Details == nil {
				t.Error("Expected Details to be set, got nil")
			} else if *result.Details != tt.receivedSPF {
				t.Errorf("Details = %v, want %v", *result.Details, tt.receivedSPF)
			}
		})
	}
}

// assertSPFResult checks one of the two SPF slots. An empty wantResult means the
// slot is expected to stay empty; an empty wantIdentity means no ptype was
// reported for it.
func assertSPFResult(t *testing.T, label string, got *model.AuthResult, wantResult model.AuthResultResult, wantDomain, wantIdentity string) {
	t.Helper()

	if wantResult == "" {
		if got != nil {
			t.Errorf("%s = %+v, want none", label, *got)
		}
		return
	}

	if got == nil {
		t.Fatalf("%s = nil, want %v", label, wantResult)
	}
	if got.Result != wantResult {
		t.Errorf("%s result = %v, want %v", label, got.Result, wantResult)
	}

	var gotDomain string
	if got.Domain != nil {
		gotDomain = *got.Domain
	}
	if gotDomain != wantDomain {
		t.Errorf("%s domain = %q, want %q", label, gotDomain, wantDomain)
	}

	var gotIdentity string
	if got.Identity != nil {
		gotIdentity = string(*got.Identity)
	}
	if gotIdentity != wantIdentity {
		t.Errorf("%s identity = %q, want %q", label, gotIdentity, wantIdentity)
	}
}

func TestParseAuthenticationResultsHeader_SPFIdentities(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	tests := []struct {
		name string
		// An empty want*Result means the corresponding slot must stay empty
		header         string
		wantResult     model.AuthResultResult
		wantDomain     string
		wantIdentity   string
		wantHelo       model.AuthResultResult
		wantHeloDomain string
	}{
		{
			// Some MTAs report both identities in the same header
			name:           "HELO before MAIL FROM",
			header:         "mx.example.com; spf=none (localhost) smtp.helo=mail.example.net; spf=pass (localhost) smtp.mailfrom=user@example.org",
			wantResult:     model.AuthResultResultPass,
			wantDomain:     "example.org",
			wantIdentity:   "mailfrom",
			wantHelo:       model.AuthResultResultNone,
			wantHeloDomain: "mail.example.net",
		},
		{
			name:           "MAIL FROM before HELO",
			header:         "mx.example.com; spf=pass (localhost) smtp.mailfrom=user@example.org; spf=none (localhost) smtp.helo=mail.example.net",
			wantResult:     model.AuthResultResultPass,
			wantDomain:     "example.org",
			wantIdentity:   "mailfrom",
			wantHelo:       model.AuthResultResultNone,
			wantHeloDomain: "mail.example.net",
		},
		{
			// Nothing was checked against the envelope sender, so no verdict about it
			name:           "HELO only",
			header:         "mx.example.com; spf=none (localhost) smtp.helo=mail.example.net",
			wantHelo:       model.AuthResultResultNone,
			wantHeloDomain: "mail.example.net",
		},
		{
			// A MAIL FROM failure must not be masked by a passing HELO check
			name:           "HELO pass does not hide MAIL FROM fail",
			header:         "mx.example.com; spf=pass smtp.helo=mail.example.net; spf=fail smtp.mailfrom=user@example.org",
			wantResult:     model.AuthResultResultFail,
			wantDomain:     "example.org",
			wantIdentity:   "mailfrom",
			wantHelo:       model.AuthResultResultPass,
			wantHeloDomain: "mail.example.net",
		},
		{
			// Null envelope sender: the mailfrom value is a bare domain
			name:           "MAIL FROM without local part",
			header:         "mx.example.com; spf=none smtp.helo=mail.example.net; spf=pass smtp.mailfrom=example.org",
			wantResult:     model.AuthResultResultPass,
			wantDomain:     "example.org",
			wantIdentity:   "mailfrom",
			wantHelo:       model.AuthResultResultNone,
			wantHeloDomain: "mail.example.net",
		},
		{
			// RFC 8601 section 2.2 allows a pvalue to be a quoted-string: the
			// quotes delimit the value, they are not part of the hostname
			name:           "quoted HELO name",
			header:         `mx.example.com; spf=none smtp.helo="mail.example.net"`,
			wantHelo:       model.AuthResultResultNone,
			wantHeloDomain: "mail.example.net",
		},
		{
			// No ptype at all: assume the envelope sender, but claim no identity
			name:       "no ptype reported",
			header:     "mx.example.com; spf=pass",
			wantResult: model.AuthResultResultPass,
		},
		{
			// An explicit envelope sender method supersedes one with no ptype
			name:         "explicit MAIL FROM supersedes untyped result",
			header:       "mx.example.com; spf=none; spf=pass smtp.mailfrom=user@example.org",
			wantResult:   model.AuthResultResultPass,
			wantDomain:   "example.org",
			wantIdentity: "mailfrom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{}
			analyzer.parseAuthenticationResultsHeader(tt.header, results)

			assertSPFResult(t, "spf", results.Spf, tt.wantResult, tt.wantDomain, tt.wantIdentity)
			assertSPFResult(t, "spf_helo", results.SpfHelo, tt.wantHelo, tt.wantHeloDomain, "helo")
		})
	}
}

// TestParseAuthenticationResultsHeader_SPFTopmostHeaderWins pins that the
// priority between a method naming smtp.mailfrom and one reporting no ptype
// arbitrates inside a single header only.
//
// Across headers the topmost one is the authority, as it was written by the
// closest hop: it must keep the verdict it gave, whatever a header below it
// reports. A header that said nothing about an identity leaves that slot open
// for a lower one to fill, which is how a receiver splitting its methods over
// several headers stays readable.
func TestParseAuthenticationResultsHeader_SPFTopmostHeaderWins(t *testing.T) {
	const authserv = "mx.example.org"

	tests := []struct {
		name string
		// Headers as they appear in the message, topmost (most recent) first
		headers        []string
		wantResult     model.AuthResultResult
		wantDomain     string
		wantIdentity   string
		wantSpfScore   int
		wantHeloResult model.AuthResultResult
		wantHeloDomain string
		wantHeloScore  int
	}{
		{
			// The trap: the topmost header reported a bare verdict, and ranking the
			// lower smtp.mailfrom method above it would upgrade the envelope sender
			// from unchecked to authenticated
			name: "a lower header does not supersede the topmost verdict",
			headers: []string{
				authserv + "; spf=none",
				authserv + "; spf=pass smtp.mailfrom=user@other.example",
			},
			wantResult:   model.AuthResultResultNone,
			wantSpfScore: 50,
		},
		{
			name: "a lower header does not overturn a topmost fail",
			headers: []string{
				authserv + "; spf=fail smtp.mailfrom=user@example.com",
				authserv + "; spf=pass smtp.mailfrom=user@other.example",
			},
			wantResult:   model.AuthResultResultFail,
			wantDomain:   "example.com",
			wantIdentity: "mailfrom",
			wantSpfScore: 0,
		},
		{
			// Nothing was said about the envelope sender up top, so a lower header
			// may still report it: both identities end up collected
			name: "a header reporting only HELO leaves the envelope sender open",
			headers: []string{
				authserv + "; spf=pass smtp.helo=relay.example.net",
				authserv + "; spf=pass smtp.mailfrom=user@example.com",
			},
			wantResult:     model.AuthResultResultPass,
			wantDomain:     "example.com",
			wantIdentity:   "mailfrom",
			wantSpfScore:   100,
			wantHeloResult: model.AuthResultResultPass,
			wantHeloDomain: "relay.example.net",
		},
		{
			// Receivers commonly split their methods over several headers, one
			// milter each, so a header reporting no spf= at all is simply skipped
			name: "a header reporting no SPF is skipped",
			headers: []string{
				authserv + "; dkim=pass header.d=example.com",
				authserv + "; spf=pass smtp.mailfrom=user@example.com",
			},
			wantResult:   model.AuthResultResultPass,
			wantDomain:   "example.com",
			wantIdentity: "mailfrom",
			wantSpfScore: 100,
		},
		{
			// The priority does arbitrate within one header: the same receiver
			// reported both identities, and smtp.mailfrom is the envelope sender one
			// whatever order the methods came in
			name: "both identities in one header, HELO first",
			headers: []string{
				authserv + "; spf=fail smtp.helo=relay.example.net; spf=pass smtp.mailfrom=user@example.com",
			},
			wantResult:     model.AuthResultResultPass,
			wantDomain:     "example.com",
			wantIdentity:   "mailfrom",
			wantSpfScore:   100,
			wantHeloResult: model.AuthResultResultFail,
			wantHeloDomain: "relay.example.net",
			wantHeloScore:  -100,
		},
		{
			// Same header, and the bare method comes first: it is the one carrying no
			// ptype that must give way, not the topmost method
			name: "a bare method gives way to smtp.mailfrom in the same header",
			headers: []string{
				authserv + "; spf=none; spf=pass smtp.mailfrom=user@example.com",
			},
			wantResult:   model.AuthResultResultPass,
			wantDomain:   "example.com",
			wantIdentity: "mailfrom",
			wantSpfScore: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewAuthenticationAnalyzer(authserv)
			email := &EmailMessage{Header: map[string][]string{"Authentication-Results": tt.headers}}

			results := analyzer.AnalyzeAuthentication(email, authserv)

			assertSPFResult(t, "spf", results.Spf, tt.wantResult, tt.wantDomain, tt.wantIdentity)
			assertSPFResult(t, "spf_helo", results.SpfHelo, tt.wantHeloResult, tt.wantHeloDomain, "helo")

			if got := analyzer.calculateSPFScore(results); got != tt.wantSpfScore {
				t.Errorf("calculateSPFScore() = %d, want %d", got, tt.wantSpfScore)
			}
			if got := analyzer.calculateSPFHeloScore(results); got != tt.wantHeloScore {
				t.Errorf("calculateSPFHeloScore() = %d, want %d", got, tt.wantHeloScore)
			}
		})
	}
}

func TestCalculateSPFHeloScore(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	tests := []struct {
		name string
		// Overall contribution to the authentication score, in points
		helo      *model.AuthResult
		wantScore int
		wantPoint int
	}{
		{
			name:      "no HELO result",
			wantScore: 0,
			wantPoint: 0,
		},
		{
			// The common case: a relay hostname carries no SPF policy of its own
			name:      "HELO none is not penalised",
			helo:      &model.AuthResult{Result: model.AuthResultResultNone},
			wantScore: 0,
			wantPoint: 0,
		},
		{
			// Passing authenticates the relay, not the sender: it earns nothing
			name:      "HELO pass earns nothing",
			helo:      &model.AuthResult{Result: model.AuthResultResultPass},
			wantScore: 0,
			wantPoint: 0,
		},
		{
			name:      "HELO softfail",
			helo:      &model.AuthResult{Result: model.AuthResultResultSoftfail},
			wantScore: -50,
			wantPoint: -2,
		},
		{
			name:      "HELO fail",
			helo:      &model.AuthResult{Result: model.AuthResultResultFail},
			wantScore: -100,
			wantPoint: -5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{SpfHelo: tt.helo}

			if got := analyzer.calculateSPFHeloScore(results); got != tt.wantScore {
				t.Errorf("calculateSPFHeloScore() = %d, want %d", got, tt.wantScore)
			}

			// The malus is capped at 5 points of the overall authentication score
			if got := 5 * analyzer.calculateSPFHeloScore(results) / 100; got != tt.wantPoint {
				t.Errorf("HELO contribution = %d points, want %d", got, tt.wantPoint)
			}
		})
	}
}

func TestCalculateSPFScoreHeloOnly(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	// A receiver that only checked the HELO identity says nothing about the
	// envelope sender: that is as unknown as an absent policy, not a failure.
	results := &model.AuthenticationResults{
		SpfHelo: &model.AuthResult{Result: model.AuthResultResultNone},
	}

	if got := analyzer.calculateSPFScore(results); got != 50 {
		t.Errorf("calculateSPFScore() = %d, want 50", got)
	}

	// Nothing reported at all stays at zero
	if got := analyzer.calculateSPFScore(&model.AuthenticationResults{}); got != 0 {
		t.Errorf("calculateSPFScore() with no result = %d, want 0", got)
	}
}

// TestParseLegacySPFIdentities covers the Received-SPF headers whose identity=
// key names what was actually checked: envelope-from and helo are both reported
// whatever the checked identity is, so the routing cannot rely on them.
func TestParseLegacySPFIdentities(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	tests := []struct {
		name string
		// An empty want*Result means the corresponding slot must stay empty
		headers         []string
		wantSpf         model.AuthResultResult
		wantSpfDomain   string
		wantSpfIdentity string
		wantHelo        model.AuthResultResult
		wantHeloDomain  string
	}{
		{
			// pypolicyd-spf with HELO_reject and no MAIL FROM check: the verdict
			// is about the relay hostname, not about the envelope sender it names
			name: "HELO identity only",
			headers: []string{
				`Pass (sender SPF authorized) identity=helo; client-ip=192.0.2.1; ` +
					`helo=relay.example.net; envelope-from=user@example.com; receiver=mx.example.org`,
			},
			wantHelo:       model.AuthResultResultPass,
			wantHeloDomain: "relay.example.net",
		},
		{
			name: "one header per identity",
			headers: []string{
				`Fail (sender SPF not authorized) identity=helo; helo=relay.example.net; receiver=mx.example.org`,
				`Pass (sender SPF authorized) identity=mailfrom; envelope-from=user@example.com; receiver=mx.example.org`,
			},
			wantSpf:         model.AuthResultResultPass,
			wantSpfDomain:   "example.com",
			wantSpfIdentity: "mailfrom",
			wantHelo:        model.AuthResultResultFail,
			wantHeloDomain:  "relay.example.net",
		},
		{
			// Headers come most recent first, and the closest hop is the one we trust
			name: "the first verdict of an identity wins",
			headers: []string{
				`Pass (sender SPF authorized) identity=helo; helo=relay.example.net`,
				`Fail (sender SPF not authorized) identity=helo; helo=other.example.net`,
			},
			wantHelo:       model.AuthResultResultPass,
			wantHeloDomain: "relay.example.net",
		},
		{
			// Receivers wrap the announced name in angle brackets as readily as
			// they do the envelope sender
			name: "bracketed HELO name",
			headers: []string{
				`Pass (sender SPF authorized) identity=helo; helo=<relay.example.net>; receiver=mx.example.org`,
			},
			wantHelo:       model.AuthResultResultPass,
			wantHeloDomain: "relay.example.net",
		},
		{
			// A non-standard key must not be mistaken for the standard one whose
			// name it ends with, as the first match in the header is the one kept
			name: "a decoy key is not the HELO one",
			headers: []string{
				`Pass identity=helo; x-helo=decoy.example.net; helo=relay.example.net; receiver=mx.example.org`,
			},
			wantHelo:       model.AuthResultResultPass,
			wantHeloDomain: "relay.example.net",
		},
		{
			name: "a decoy key is not the envelope sender one",
			headers: []string{
				`Pass x-sender=decoy@example.net; envelope-from=<user@example.com>; receiver=mx.example.org`,
			},
			wantSpf:         model.AuthResultResultPass,
			wantSpfDomain:   "example.com",
			wantSpfIdentity: "mailfrom",
		},
		{
			// Sender-ID's PRA authenticates an address taken from the message
			// headers, so it reports on neither SPF identity
			name:    "PRA identity is not an SPF one",
			headers: []string{`Pass (sender SPF authorized) identity=pra; envelope-from=user@example.com`},
		},
		{
			// Predates the identity= key, or omits it: SPF checks the envelope
			// sender by default, and this one names the address it checked
			name:            "no identity reported",
			headers:         []string{`pass (example.com: sender SPF authorized) envelope-from=user@example.com; helo=relay.example.net`},
			wantSpf:         model.AuthResultResultPass,
			wantSpfDomain:   "example.com",
			wantSpfIdentity: "mailfrom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{Header: map[string][]string{"Received-Spf": tt.headers}}

			mailfrom, helo := analyzer.parseLegacySPF(email, "")

			assertSPFResult(t, "spf", mailfrom, tt.wantSpf, tt.wantSpfDomain, tt.wantSpfIdentity)
			assertSPFResult(t, "spf_helo", helo, tt.wantHelo, tt.wantHeloDomain, "helo")
		})
	}
}

// TestParseLegacySPFUntrustedReceiver pins that the authserv-id filtering still
// applies to every header of the pass, whichever identity it reports.
func TestParseLegacySPFUntrustedReceiver(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("mx.example.org")

	email := &EmailMessage{Header: map[string][]string{"Received-Spf": {
		`Fail (sender SPF not authorized) identity=helo; helo=relay.example.net; receiver=mx.elsewhere.example`,
		`Pass (sender SPF authorized) identity=mailfrom; envelope-from=user@example.com; receiver=mx.example.org`,
	}}}

	mailfrom, helo := analyzer.parseLegacySPF(email, "mx.example.org")

	assertSPFResult(t, "spf", mailfrom, model.AuthResultResultPass, "example.com", "mailfrom")
	assertSPFResult(t, "spf_helo", helo, "", "", "helo")
}

// A receiver= naming the trusted authority is trusted whether or not it is
// quoted: the quotes delimit the value, they are not part of the name.
func TestParseLegacySPFQuotedReceiver(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("mx.example.org")

	email := &EmailMessage{Header: map[string][]string{"Received-Spf": {
		`Pass (sender SPF authorized) identity=mailfrom; envelope-from=user@example.com; receiver="mx.example.org"`,
	}}}

	mailfrom, _ := analyzer.parseLegacySPF(email, "mx.example.org")

	assertSPFResult(t, "spf", mailfrom, model.AuthResultResultPass, "example.com", "mailfrom")
}

// TestAnalyzeAuthenticationLegacyHeloOnly walks the whole path for a receiver
// that only checked the HELO identity and reported it the legacy way: the
// verdict must not stand in for the envelope sender one, which is what the
// Authentication-Results path already guarantees.
func TestAnalyzeAuthenticationLegacyHeloOnly(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	email := &EmailMessage{Header: map[string][]string{"Received-Spf": {
		`Pass (sender SPF authorized) identity=helo; client-ip=192.0.2.1; ` +
			`helo=relay.example.net; envelope-from=user@example.com; receiver=mx.example.org`,
	}}}

	results := analyzer.AnalyzeAuthentication(email, "")

	assertSPFResult(t, "spf", results.Spf, "", "", "")
	assertSPFResult(t, "spf_helo", results.SpfHelo, model.AuthResultResultPass, "relay.example.net", "helo")

	// Scored like an unchecked envelope sender, not like an authenticated one
	if got := analyzer.calculateSPFScore(results); got != 50 {
		t.Errorf("calculateSPFScore() = %d, want 50", got)
	}
	if got := analyzer.calculateSPFHeloScore(results); got != 0 {
		t.Errorf("calculateSPFHeloScore() = %d, want 0", got)
	}
}

// TestAnalyzeAuthenticationLegacyNotConsultedWhenSpfKnown pins that the legacy
// headers stay a fallback: an Authentication-Results header reporting the
// envelope sender is the authority, and a Received-SPF written by another hop
// must not add a HELO penalty behind its back.
func TestAnalyzeAuthenticationLegacyNotConsultedWhenSpfKnown(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	email := &EmailMessage{Header: map[string][]string{
		"Authentication-Results": {"mx.example.org; spf=pass smtp.mailfrom=user@example.com"},
		"Received-Spf": {
			`Fail (sender SPF not authorized) identity=helo; helo=relay.example.net; receiver=mx.example.org`,
		},
	}}

	results := analyzer.AnalyzeAuthentication(email, "")

	assertSPFResult(t, "spf", results.Spf, model.AuthResultResultPass, "example.com", "mailfrom")
	assertSPFResult(t, "spf_helo", results.SpfHelo, "", "", "helo")
}

// TestAnalyzeAuthenticationLegacyCompletesHeloOnlyHeader pins the case that made
// the legacy path reachable again: the modern header reported the HELO identity
// alone, so the envelope sender verdict is still looked for in Received-SPF, and
// the HELO one already parsed is kept.
func TestAnalyzeAuthenticationLegacyCompletesHeloOnlyHeader(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	email := &EmailMessage{Header: map[string][]string{
		"Authentication-Results": {"mx.example.org; spf=none smtp.helo=relay.example.net"},
		"Received-Spf": {
			`Pass (sender SPF authorized) identity=mailfrom; envelope-from=user@example.com; receiver=mx.example.org`,
		},
	}}

	results := analyzer.AnalyzeAuthentication(email, "")

	assertSPFResult(t, "spf", results.Spf, model.AuthResultResultPass, "example.com", "mailfrom")
	assertSPFResult(t, "spf_helo", results.SpfHelo, model.AuthResultResultNone, "relay.example.net", "helo")
}
