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

	"git.happydns.org/happyDeliver/internal/api"
)

func TestParseSPFResult(t *testing.T) {
	tests := []struct {
		name           string
		part           string
		expectedResult api.AuthResultResult
		expectedDomain string
	}{
		{
			name:           "SPF pass with domain",
			part:           "spf=pass smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultPass,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF fail",
			part:           "spf=fail smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultFail,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF neutral",
			part:           "spf=neutral smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultNeutral,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF softfail",
			part:           "spf=softfail smtp.mailfrom=sender@example.com",
			expectedResult: api.AuthResultResultSoftfail,
			expectedDomain: "example.com",
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseSPFResult(tt.part)

			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}
			if result.Domain == nil || *result.Domain != tt.expectedDomain {
				var gotDomain string
				if result.Domain != nil {
					gotDomain = *result.Domain
				}
				t.Errorf("Domain = %v, want %v", gotDomain, tt.expectedDomain)
			}
		})
	}
}

func TestParseLegacySPF(t *testing.T) {
	tests := []struct {
		name           string
		receivedSPF    string
		expectedResult api.AuthResultResult
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
			expectedResult: api.AuthResultResultPass,
			expectedDomain: api.PtrTo("example.com"),
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
			expectedResult: api.AuthResultResultFail,
			expectedDomain: api.PtrTo("test.com"),
		},
		{
			name:           "SPF softfail",
			receivedSPF:    "softfail (example.com: transitioning domain of admin@example.org does not designate 192.0.2.30 as permitted sender) envelope-from=\"admin@example.org\"",
			expectedResult: api.AuthResultResultSoftfail,
			expectedDomain: api.PtrTo("example.org"),
		},
		{
			name:           "SPF neutral",
			receivedSPF:    "neutral (example.com: 192.0.2.40 is neither permitted nor denied by domain of info@domain.net) envelope-from=\"info@domain.net\"",
			expectedResult: api.AuthResultResultNeutral,
			expectedDomain: api.PtrTo("domain.net"),
		},
		{
			name:           "SPF none",
			receivedSPF:    "none (example.com: domain of noreply@company.io has no SPF record) envelope-from=\"noreply@company.io\"",
			expectedResult: api.AuthResultResultNone,
			expectedDomain: api.PtrTo("company.io"),
		},
		{
			name:           "SPF temperror",
			receivedSPF:    "temperror (example.com: error in processing SPF record) envelope-from=\"support@shop.example\"",
			expectedResult: api.AuthResultResultTemperror,
			expectedDomain: api.PtrTo("shop.example"),
		},
		{
			name:           "SPF permerror",
			receivedSPF:    "permerror (example.com: domain of contact@invalid.test has invalid SPF record) envelope-from=\"contact@invalid.test\"",
			expectedResult: api.AuthResultResultPermerror,
			expectedDomain: api.PtrTo("invalid.test"),
		},
		{
			name:           "SPF pass without domain extraction",
			receivedSPF:    "pass (example.com: 192.0.2.50 is authorized)",
			expectedResult: api.AuthResultResultPass,
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
			expectedResult: api.AuthResultResultPass,
			expectedDomain: api.PtrTo("mail.example.net"),
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock email message with Received-SPF header
			email := &EmailMessage{
				Header: make(map[string][]string),
			}
			if tt.receivedSPF != "" {
				email.Header["Received-Spf"] = []string{tt.receivedSPF}
			}

			result := analyzer.parseLegacySPF(email)

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
