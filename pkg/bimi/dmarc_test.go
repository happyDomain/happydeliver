// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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

package bimi

import (
	"strings"
	"testing"
)

func pct(v int) *int { return &v }

// enforcedDMARC is the policy the rest of the package's tests run under: a
// plain p=reject published at the domain being analysed. Validation now reads
// a DMARC policy, and every case that is not about DMARC needs one that does
// not get in the way of what it does test.
func enforcedDMARC(domain string) *DMARCPolicy {
	return &DMARCPolicy{Found: true, Domain: domain, Policy: DMARCPolicyReject}
}

// The Author Domain is a subdomain throughout, so that the record found at
// "example.com" exercises the inherited branch where sp= governs, and the one
// found at "sub.example.com" the branch where it does not.
func TestCheckDMARCEnforcement(t *testing.T) {
	const authorDomain = "sub.example.com"

	tests := []struct {
		name       string
		policy     *DMARCPolicy
		want       CheckStatus
		wantSubstr string
	}{
		{
			name:       "Not evaluated",
			policy:     nil,
			want:       StatusSkipped,
			wantSubstr: "not evaluated",
		},
		{
			name:       "No DMARC record",
			policy:     &DMARCPolicy{Found: false},
			want:       StatusFail,
			wantSubstr: "No valid DMARC record was found for sub.example.com",
		},
		{
			name:       "Policy none at the Author Domain",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyNone},
			want:       StatusFail,
			wantSubstr: "publishes p=none",
		},
		{
			name:       "Policy reject",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyReject},
			want:       StatusPass,
			wantSubstr: "satisfies the BIMI enforcement requirement",
		},
		{
			name:       "Policy quarantine without pct",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyQuarantine},
			want:       StatusPass,
			wantSubstr: "satisfies the BIMI enforcement requirement",
		},
		{
			name:       "Policy quarantine with pct=100",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyQuarantine, Percentage: pct(100)},
			want:       StatusPass,
			wantSubstr: "satisfies the BIMI enforcement requirement",
		},
		{
			name:       "Policy quarantine with a partial pct",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyQuarantine, Percentage: pct(50)},
			want:       StatusFail,
			wantSubstr: "BIMI requires pct=100 under a quarantine policy",
		},
		{
			name:       "Unknown policy value",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: "unknown"},
			want:       StatusFail,
			wantSubstr: "no usable p= policy",
		},
		{
			// Not one of the conditions section 7.1 enumerates: pinned so
			// that reading t=y as a failure stays a deliberate decision.
			name:       "Test mode under an enforcing policy",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyReject, TestMode: true},
			want:       StatusFail,
			wantSubstr: "publishes t=y",
		},
		{
			// The false negative the contextual reading of section 7.1 item
			// 8 exists to avoid: this domain does display an Indicator.
			name:       "sp=none published at the Author Domain itself",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyReject, SubdomainPolicy: DMARCPolicyNone},
			want:       StatusWarning,
			wantSubstr: "turns BIMI off for every subdomain",
		},
		{
			name:       "sp=none inherited from the organizational domain",
			policy:     &DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyReject, SubdomainPolicy: DMARCPolicyNone},
			want:       StatusFail,
			wantSubstr: "publishes sp=none",
		},
		{
			// The inverse case the same computation resolves: p=none does
			// not govern the subdomain when an sp= is published above it.
			name:       "sp=reject inherited over p=none",
			policy:     &DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyNone, SubdomainPolicy: DMARCPolicyReject},
			want:       StatusPass,
			wantSubstr: "sp=reject policy published at example.com",
		},
		{
			name:       "Inherited record with no sp= falls back to p=",
			policy:     &DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyNone},
			want:       StatusFail,
			wantSubstr: "publishes p=none",
		},
		{
			name:       "Partial pct under a reject policy",
			policy:     &DMARCPolicy{Found: true, Domain: authorDomain, Policy: DMARCPolicyReject, Percentage: pct(50)},
			want:       StatusWarning,
			wantSubstr: "only requires pct=100 under a quarantine policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := CheckDMARCEnforcement(tt.policy, authorDomain)

			if check.Name != "dmarc_enforcement" {
				t.Errorf("Name = %q, want %q", check.Name, "dmarc_enforcement")
			}
			if check.Status != tt.want {
				t.Errorf("Status = %q, want %q (messages: %v)", check.Status, tt.want, check.MessageTexts())
			}
			if joined := strings.Join(check.MessageTexts(), " | "); !strings.Contains(joined, tt.wantSubstr) {
				t.Errorf("messages %q do not mention %q", joined, tt.wantSubstr)
			}
		})
	}
}

// A passing check still carries an explanation, and it must be an informational
// one: the UI renders severities, and a green check whose message reads as an
// error would contradict its own status.
func TestCheckDMARCEnforcementPassingMessageIsInformational(t *testing.T) {
	check := CheckDMARCEnforcement(
		&DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyReject},
		"example.com",
	)

	if check.Status != StatusPass {
		t.Fatalf("Status = %q, want %q", check.Status, StatusPass)
	}
	if len(check.Messages) != 1 {
		t.Fatalf("got %d messages, want 1: %v", len(check.Messages), check.MessageTexts())
	}
	if check.Messages[0].Severity != SeverityInfo {
		t.Errorf("Severity = %q, want %q", check.Messages[0].Severity, SeverityInfo)
	}
}

// A failing policy reports every reason it fails, not just the first.
func TestCheckDMARCEnforcementReportsEveryReason(t *testing.T) {
	check := CheckDMARCEnforcement(
		&DMARCPolicy{Found: true, Domain: "example.com", Policy: DMARCPolicyQuarantine, Percentage: pct(20), TestMode: true},
		"example.com",
	)

	if check.Status != StatusFail {
		t.Fatalf("Status = %q, want %q", check.Status, StatusFail)
	}
	joined := strings.Join(check.MessageTexts(), " | ")
	for _, want := range []string{"pct=100", "t=y"} {
		if !strings.Contains(joined, want) {
			t.Errorf("messages %q do not mention %q", joined, want)
		}
	}

	// The policy is quarantine, which on its own would qualify: saying so
	// beside the reasons it does not would contradict the check's status.
	if strings.Contains(joined, "satisfies the BIMI enforcement requirement") {
		t.Errorf("messages %q claim the requirement is satisfied while the check fails", joined)
	}
	for _, m := range check.Messages {
		if m.Severity == SeverityInfo {
			t.Errorf("a failing check carries an informational message: %q", m.Text)
		}
	}
}
