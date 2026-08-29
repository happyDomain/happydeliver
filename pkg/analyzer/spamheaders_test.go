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

package analyzer

import (
	"net/mail"
	"testing"
)

func TestSpamScannerHeaders(t *testing.T) {
	tests := []struct {
		name             string
		headers          mail.Header
		wantSpamAssassin map[string]string
		wantRspamd       map[string]string
	}{
		{
			name: "SpamAssassin alone keeps the headers it names",
			headers: mail.Header{
				"X-Spam-Status":          {"No, score=2.3 required=5.0"},
				"X-Spam-Score":           {"2.3"},
				"X-Spam-Flag":            {"NO"},
				"X-Spam-Level":           {"**"},
				"X-Spam-Checker-Version": {"SpamAssassin 3.4.6 on mx.example.com"},
			},
			wantSpamAssassin: map[string]string{
				"X-Spam-Status":          "No, score=2.3 required=5.0",
				"X-Spam-Score":           "2.3",
				"X-Spam-Flag":            "NO",
				"X-Spam-Level":           "**",
				"X-Spam-Checker-Version": "SpamAssassin 3.4.6 on mx.example.com",
			},
		},
		{
			name: "rspamd alone keeps the SpamAssassin-shaped headers it wrote",
			headers: mail.Header{
				"X-Spamd-Result": {"default: False [-3.91 / 15.00];"},
				"X-Spam-Score":   {"-3.91"},
				"X-Spam-Flag":    {"NO"},
				"X-Spam-Level":   {""},
			},
			wantRspamd: map[string]string{
				"X-Spamd-Result": "default: False [-3.91 / 15.00];",
				"X-Spam-Score":   "-3.91",
				"X-Spam-Flag":    "NO",
			},
		},
		{
			name: "a bare X-Spam is enough to recognise rspamd",
			headers: mail.Header{
				"X-Spam":      {"Yes"},
				"X-Spam-Flag": {"YES"},
			},
			wantRspamd: map[string]string{
				"X-Spam":      "Yes",
				"X-Spam-Flag": "YES",
			},
		},
		{
			name: "both scanners: each status goes to its author",
			headers: mail.Header{
				"X-Spam-Status": {
					"No, rspamdscore=-4.78, required=10.00",
					"No, score=0.00, required=95.00",
				},
				"X-Spamd-Result": {"default: False [-4.78 / 15.00];"},
			},
			wantSpamAssassin: map[string]string{
				"X-Spam-Status": "No, score=0.00, required=95.00",
			},
			wantRspamd: map[string]string{
				"X-Spam-Status":  "No, rspamdscore=-4.78, required=10.00",
				"X-Spamd-Result": "default: False [-4.78 / 15.00];",
			},
		},
		{
			name: "both scanners: a mute header follows the one that reported a verdict of its own",
			headers: mail.Header{
				"X-Spam-Status":  {"No, score=0.00, required=95.00"},
				"X-Spamd-Result": {"default: False [-4.78 / 15.00];"},
				"X-Spam-Score":   {"-4.78"},
				"X-Spam-Flag":    {"NO"},
			},
			wantSpamAssassin: map[string]string{
				"X-Spam-Status": "No, score=0.00, required=95.00",
			},
			wantRspamd: map[string]string{
				"X-Spamd-Result": "default: False [-4.78 / 15.00];",
				"X-Spam-Score":   "-4.78",
				"X-Spam-Flag":    "NO",
			},
		},
		{
			name: "no scanner identified: the naming convention is SpamAssassin's",
			headers: mail.Header{
				"X-Spam-Score": {"3.2"},
			},
			wantSpamAssassin: map[string]string{"X-Spam-Score": "3.2"},
		},
		{
			name: "an X-Spam-Report with no rspamd around goes to SpamAssassin",
			headers: mail.Header{
				"X-Spam-Report": {"* 1.5 URIBL_BLOCKED ADMINISTRATOR NOTICE"},
				"X-Spam-Flag":   {"YES"},
			},
			wantSpamAssassin: map[string]string{
				"X-Spam-Report": "* 1.5 URIBL_BLOCKED ADMINISTRATOR NOTICE",
				"X-Spam-Flag":   "YES",
			},
		},
		{
			name: "the topmost occurrence of a header wins",
			headers: mail.Header{
				"X-Spam-Score": {"1.0", "2.0"},
			},
			wantSpamAssassin: map[string]string{"X-Spam-Score": "1.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{Header: tt.headers}
			set := email.SpamScannerHeaders()

			assertHeaderMap(t, "SpamAssassin", set.SpamAssassin, tt.wantSpamAssassin)
			assertHeaderMap(t, "Rspamd", set.Rspamd, tt.wantRspamd)
		})
	}
}

func assertHeaderMap(t *testing.T, name string, got, want map[string]string) {
	t.Helper()

	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s[%q] = %q, want %q", name, key, got[key], value)
		}
	}
}

// TestAnalyzeSpamAssassinRspamdOnlyHost checks that a host running rspamd alone
// produces no SpamAssassin report at all: its X-Spam-Score and X-Spam-Flag, which
// name no author, used to be read as SpamAssassin's and surfaced as a phantom
// section scored 0.
func TestAnalyzeSpamAssassinRspamdOnlyHost(t *testing.T) {
	email := &EmailMessage{Header: mail.Header{
		"X-Spam-Status":  {"No, rspamdscore=-4.78, required=10.00"},
		"X-Spam-Flag":    {"NO"},
		"X-Spam-Score":   {"-4.78"},
		"X-Rspamd-Score": {"-4.78"},
	}}

	if result := NewSpamAssassinAnalyzer().AnalyzeSpamAssassin(email); result != nil {
		t.Errorf("Expected no SpamAssassin result on an rspamd-only host, got %+v", result)
	}

	rspamd := NewRspamdAnalyzer(nil).AnalyzeRspamd(email)
	if rspamd == nil {
		t.Fatal("Expected an rspamd result")
	}
	if rspamd.Score != -4.78 {
		t.Errorf("rspamd Score = %v, want -4.78", rspamd.Score)
	}
}

// TestAnalyzeSpamAssassinBothScannersMuteScore checks that when both scanners are
// present and X-Spam-Score names neither, SpamAssassin is reported without it
// rather than with a score that may be rspamd's.
func TestAnalyzeSpamAssassinBothScannersMuteScore(t *testing.T) {
	email := &EmailMessage{Header: mail.Header{
		"X-Spam-Status":  {"Yes, score=6.10, required=5.00"},
		"X-Spamd-Result": {"default: False [-4.78 / 15.00];"},
		"X-Spam-Score":   {"-4.78"},
	}}

	result := NewSpamAssassinAnalyzer().AnalyzeSpamAssassin(email)
	if result == nil {
		t.Fatal("Expected SpamAssassin result, got nil")
	}
	if result.Score != 6.10 {
		t.Errorf("Score = %v, want 6.10 (rspamd's X-Spam-Score leaked in)", result.Score)
	}
}
