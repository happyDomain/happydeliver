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
	"time"
)

func TestParseDKIMSignatures(t *testing.T) {
	tests := []struct {
		name       string
		signatures []string
		expected   []DKIMHeader
	}{
		{
			name:       "Empty input",
			signatures: nil,
			expected:   nil,
		},
		{
			name:       "Empty string",
			signatures: []string{""},
			expected:   nil,
		},
		{
			name: "Simple Gmail-style",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20210112; h=from:to:subject:date:message-id; bh=abcdef1234567890=; b=SIGNATURE_DATA_HERE==`,
			},
			expected: []DKIMHeader{{Domain: "gmail.com", Selector: "20210112"}},
		},
		{
			name: "Microsoft 365 style",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=contoso.com; s=selector1; h=From:Date:Subject:Message-ID; bh=UErATeHehIIPIXPeUA==; b=SIGNATURE_DATA==`,
			},
			expected: []DKIMHeader{{Domain: "contoso.com", Selector: "selector1"}},
		},
		{
			name: "Tab-folded multiline (Postfix-style)",
			signatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/simple; d=nemunai.re; s=thot;\r\n\tt=1760866834; bh=YNB7c8Qgm8YGn9X1FAXTcdpO7t4YSZFiMrmpCfD/3zw=;\r\n\th=From:To:Subject;\r\n\tb=T4TFaypMpsHGYCl3PGLwmzOYRF11rYjC7lF8V5VFU+ldvG8WBpFn==",
			},
			expected: []DKIMHeader{{Domain: "nemunai.re", Selector: "thot"}},
		},
		{
			name: "Space-folded multiline (RFC-style)",
			signatures: []string{
				"v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=test; t=1528637909; h=from:to:subject;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8Gwps==",
			},
			expected: []DKIMHeader{{Domain: "football.example.com", Selector: "test"}},
		},
		{
			name: "d= and s= on separate continuation lines",
			signatures: []string{
				"v=1; a=rsa-sha256;\r\n\tc=relaxed/relaxed;\r\n\td=mycompany.com;\r\n\ts=selector1;\r\n\tbh=hash=;\r\n\tb=sig==",
			},
			expected: []DKIMHeader{{Domain: "mycompany.com", Selector: "selector1"}},
		},
		{
			name: "No space after semicolons",
			signatures: []string{
				`v=1;a=rsa-sha256;c=relaxed/relaxed;d=example.net;s=mail;h=from:to:subject;bh=abc=;b=xyz==`,
			},
			expected: []DKIMHeader{{Domain: "example.net", Selector: "mail"}},
		},
		{
			name: "Multiple spaces after semicolons",
			signatures: []string{
				`v=1;  a=rsa-sha256;  c=relaxed/relaxed;  d=example.com;  s=myselector;  bh=hash=;  b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "example.com", Selector: "myselector"}},
		},
		{
			name: "Ed25519 signature (RFC 8463)",
			signatures: []string{
				"v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n d=football.example.com; i=@football.example.com;\r\n q=dns/txt; s=brisbane; t=1528637909; h=from:to:subject;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQ==",
			},
			expected: []DKIMHeader{{Domain: "football.example.com", Selector: "brisbane"}},
		},
		{
			name: "Multiple signatures (ESP double-signing)",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=mydomain.com; s=mail; h=from:to:subject; bh=hash1=; b=sig1==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendib.com; s=mail; h=from:to:subject; bh=hash1=; b=sig2==`,
			},
			expected: []DKIMHeader{
				{Domain: "mydomain.com", Selector: "mail"},
				{Domain: "sendib.com", Selector: "mail"},
			},
		},
		{
			name: "Dual-algorithm signing (Ed25519 + RSA, same domain, different selectors)",
			signatures: []string{
				`v=1; a=ed25519-sha256; c=relaxed/relaxed; d=football.example.com; s=brisbane; h=from:to:subject; bh=hash=; b=edSig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=football.example.com; s=test; h=from:to:subject; bh=hash=; b=rsaSig==`,
			},
			expected: []DKIMHeader{
				{Domain: "football.example.com", Selector: "brisbane"},
				{Domain: "football.example.com", Selector: "test"},
			},
		},
		{
			name: "Amazon SES long selectors",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/simple; d=amazonses.com; s=224i4yxa5dv7c2xz3womw6peuabd; h=from:to:subject; bh=sesHash=; b=sesSig==`,
				`v=1; a=rsa-sha256; c=relaxed/simple; d=customerdomain.io; s=ug7nbtf4gccmlpwj322ax3p6ow6fovbt; h=from:to:subject; bh=sesHash=; b=customSig==`,
			},
			expected: []DKIMHeader{
				{Domain: "amazonses.com", Selector: "224i4yxa5dv7c2xz3womw6peuabd"},
				{Domain: "customerdomain.io", Selector: "ug7nbtf4gccmlpwj322ax3p6ow6fovbt"},
			},
		},
		{
			name: "Subdomain in d=",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example.co.uk; s=dkim2025; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "mail.example.co.uk", Selector: "dkim2025"}},
		},
		{
			name: "Deeply nested subdomain",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=bounce.transactional.mail.example.com; s=s2048; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "bounce.transactional.mail.example.com", Selector: "s2048"}},
		},
		{
			name: "Selector with hyphens (Microsoft 365 custom domain style)",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1-contoso-com; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "example.com", Selector: "selector1-contoso-com"}},
		},
		{
			name: "Selector with dots",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=smtp.mail; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "example.com", Selector: "smtp.mail"}},
		},
		{
			name: "Single-character selector",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=tiny.io; s=x; h=from:to:subject; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{{Domain: "tiny.io", Selector: "x"}},
		},
		{
			name: "Postmark-style timestamp selector, s= before d=",
			signatures: []string{
				`v=1; a=rsa-sha1; c=relaxed/relaxed; s=20130519032151pm; d=postmarkapp.com; h=From:Date:Subject; bh=vYFvy46eesUDGJ45hyBTH30JfN4=; b=iHeFQ+7rCiSQs3DPjR2eUSZSv4i==`,
			},
			expected: []DKIMHeader{{Domain: "postmarkapp.com", Selector: "20130519032151pm"}},
		},
		{
			name: "d= and s= at the very end",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:to:subject; bh=hash=; b=sig==; d=example.net; s=trailing`,
			},
			expected: []DKIMHeader{{Domain: "example.net", Selector: "trailing"}},
		},
		{
			name: "Full tag set",
			signatures: []string{
				`v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/simple; q=dns/txt; i=user@example.com; t=1255993973; x=1256598773; h=From:Sender:Reply-To:Subject:Date:Message-Id:To:Cc; bh=+7qxGePcmmrtZAIVQAtkSSGHfQ/ftNuvUTWJ3vXC9Zc=; b=dB85+qM+If1KGQmqMLNpqLgNtUaG5dhGjYjQD6/QXtXmViJx8tf9gLEjcHr+musLCAvr0Fsn1DA3ZLLlUxpf4AR==`,
			},
			expected: []DKIMHeader{{Domain: "example.com", Selector: "selector1"}},
		},
		{
			name: "Missing d= tag",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; s=selector1; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Missing s= tag",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Missing both d= and s= tags",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:to; bh=hash=; b=sig==`,
			},
			expected: nil,
		},
		{
			name: "Mix of valid and invalid signatures",
			signatures: []string{
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=good.com; s=sel1; h=from:to; bh=hash=; b=sig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; s=orphan; h=from:to; bh=hash=; b=sig==`,
				`v=1; a=rsa-sha256; c=relaxed/relaxed; d=also-good.com; s=sel2; h=from:to; bh=hash=; b=sig==`,
			},
			expected: []DKIMHeader{
				{Domain: "good.com", Selector: "sel1"},
				{Domain: "also-good.com", Selector: "sel2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDKIMSignatures(tt.signatures)
			if len(result) != len(tt.expected) {
				t.Fatalf("parseDKIMSignatures() returned %d results, want %d\n  got:  %+v\n  want: %+v", len(result), len(tt.expected), result, tt.expected)
			}
			for i := range tt.expected {
				if result[i].Domain != tt.expected[i].Domain {
					t.Errorf("result[%d].Domain = %q, want %q", i, result[i].Domain, tt.expected[i].Domain)
				}
				if result[i].Selector != tt.expected[i].Selector {
					t.Errorf("result[%d].Selector = %q, want %q", i, result[i].Selector, tt.expected[i].Selector)
				}
			}
		})
	}
}

func TestValidateDKIM(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected bool
	}{
		{
			name:     "Valid DKIM with version",
			record:   "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: true,
		},
		{
			name:     "Valid DKIM without version",
			record:   "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: true,
		},
		{
			name:     "Invalid DKIM - no public key",
			record:   "v=DKIM1; k=rsa",
			expected: false,
		},
		{
			name:     "Invalid DKIM - wrong version",
			record:   "v=DKIM2; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...",
			expected: false,
		},
		{
			name:     "Invalid DKIM - empty",
			record:   "",
			expected: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.validateDKIM(tt.record)
			if result != tt.expected {
				t.Errorf("validateDKIM(%q) = %v, want %v", tt.record, result, tt.expected)
			}
		})
	}
}
