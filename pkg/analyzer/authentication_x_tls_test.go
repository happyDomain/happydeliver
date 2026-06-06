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
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func TestParseXTLSResult(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	result := analyzer.parseXTLSResult("x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_256_GCM_SHA384 smtp.bits=256")

	if result.Result != model.AuthResultResultPass {
		t.Errorf("Result = %v, want pass", result.Result)
	}
	if result.Details == nil {
		t.Fatal("Details should not be nil")
	}
	for _, want := range []string{"TLSv1.3", "TLS_AES_256_GCM_SHA384", "256 bits"} {
		if !strings.Contains(*result.Details, want) {
			t.Errorf("Details %q should contain %q", *result.Details, want)
		}
	}
}

func TestCalculateXTLSScore(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	tests := []struct {
		name  string
		xtls  *model.AuthResult
		score int
	}{
		{"nil", nil, 0},
		{"pass", &model.AuthResult{Result: model.AuthResultResultPass}, 0},
		{"none", &model.AuthResult{Result: model.AuthResultResultNone}, -100},
		{"fail", &model.AuthResult{Result: model.AuthResultResultFail}, -100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &model.AuthenticationResults{XTls: tt.xtls}
			if got := analyzer.calculateXTLSScore(results); got != tt.score {
				t.Errorf("calculateXTLSScore = %d, want %d", got, tt.score)
			}
		})
	}
}

func TestReconcileXTLS(t *testing.T) {
	analyzer := NewAuthenticationAnalyzer("")

	t.Run("keeps existing x-tls header result", func(t *testing.T) {
		existing := &model.AuthResult{Result: model.AuthResultResultFail}
		results := &model.AuthenticationResults{XTls: existing}
		chain := &[]model.ReceivedHop{{Tls: &model.TLSInfo{Version: utils.PtrTo("TLSv1.3")}}}
		analyzer.ReconcileXTLS(results, chain)
		if results.XTls != existing {
			t.Error("existing XTls should be preserved")
		}
	})

	t.Run("synthesizes pass from encrypted inbound hop", func(t *testing.T) {
		results := &model.AuthenticationResults{}
		chain := &[]model.ReceivedHop{{Tls: &model.TLSInfo{
			Version: utils.PtrTo("TLSv1.3"),
			Cipher:  utils.PtrTo("TLS_AES_256_GCM_SHA384"),
			Bits:    utils.PtrTo(256),
		}}}
		analyzer.ReconcileXTLS(results, chain)
		if results.XTls == nil || results.XTls.Result != model.AuthResultResultPass {
			t.Fatalf("expected synthesized pass, got %+v", results.XTls)
		}
		if results.XTls.Details == nil || !strings.Contains(*results.XTls.Details, "TLSv1.3") {
			t.Errorf("details should mention TLS version, got %v", results.XTls.Details)
		}
	})

	t.Run("synthesizes pass from ESMTPS protocol without TLS parenthetical", func(t *testing.T) {
		// smtpd_tls_received_header disabled: no TLS details, but ESMTPS proves encryption.
		results := &model.AuthenticationResults{}
		chain := &[]model.ReceivedHop{{With: utils.PtrTo("ESMTPS")}}
		analyzer.ReconcileXTLS(results, chain)
		if results.XTls == nil || results.XTls.Result != model.AuthResultResultPass {
			t.Fatalf("expected synthesized pass, got %+v", results.XTls)
		}
	})

	t.Run("synthesizes none from plaintext ESMTP protocol", func(t *testing.T) {
		results := &model.AuthenticationResults{}
		chain := &[]model.ReceivedHop{{With: utils.PtrTo("ESMTP")}}
		analyzer.ReconcileXTLS(results, chain)
		if results.XTls == nil || results.XTls.Result != model.AuthResultResultNone {
			t.Fatalf("expected synthesized none, got %+v", results.XTls)
		}
	})

	t.Run("leaves nil when neither TLS info nor protocol is known", func(t *testing.T) {
		results := &model.AuthenticationResults{}
		chain := &[]model.ReceivedHop{{}}
		analyzer.ReconcileXTLS(results, chain)
		if results.XTls != nil {
			t.Errorf("expected nil XTls when undetermined, got %+v", results.XTls)
		}
	})

	t.Run("leaves nil with empty chain", func(t *testing.T) {
		results := &model.AuthenticationResults{}
		analyzer.ReconcileXTLS(results, &[]model.ReceivedHop{})
		if results.XTls != nil {
			t.Errorf("expected nil XTls, got %+v", results.XTls)
		}
	})
}

func TestProtocolIndicatesTLS(t *testing.T) {
	tests := []struct {
		with string
		want bool
	}{
		{"ESMTPS", true},
		{"ESMTPSA", true},
		{"SMTPS", true},
		{"LMTPS", true},
		{"LMTPSA", true},
		{"SMTP", false},
		{"ESMTP", false},
		{"ESMTPA", false},
		{"LMTP", false},
	}
	for _, tt := range tests {
		t.Run(tt.with, func(t *testing.T) {
			if got := protocolIndicatesTLS(utils.PtrTo(tt.with)); got != tt.want {
				t.Errorf("protocolIndicatesTLS(%q) = %v, want %v", tt.with, got, tt.want)
			}
		})
	}
	if protocolIndicatesTLS(nil) {
		t.Error("protocolIndicatesTLS(nil) should be false")
	}
}
