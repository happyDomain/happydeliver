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
	"net/mail"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// reportedThreshold reads back the threshold rspamd reported for a message. It
// is optional in the model, an unreported one coming back here as 0, the value
// the tables below use for it.
func reportedThreshold(result *model.RspamdResult) float32 {
	if result.Threshold == nil {
		return 0
	}
	return *result.Threshold
}

func TestAnalyzeRspamdNoHeaders(t *testing.T) {
	analyzer := NewRspamdAnalyzer(nil)
	email := &EmailMessage{Header: make(mail.Header)}

	result := analyzer.AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))

	if result != nil {
		t.Errorf("Expected nil for email without rspamd headers, got %+v", result)
	}
}

func TestParseSpamdResult(t *testing.T) {
	tests := []struct {
		name              string
		header            string
		expectedScore     float32
		expectedThreshold float32
		expectedIsSpam    bool
		expectedSymbols   map[string]float32
		expectedSymParams map[string]string
	}{
		{
			name:              "Clean email negative score",
			header:            "default: False [-3.91 / 15.00];\n\tDATE_IN_PAST(0.10); ALL_TRUSTED(-1.00)[trusted]",
			expectedScore:     -3.91,
			expectedThreshold: 15.00,
			expectedIsSpam:    false,
			expectedSymbols: map[string]float32{
				"DATE_IN_PAST": 0.10,
				"ALL_TRUSTED":  -1.00,
			},
			expectedSymParams: map[string]string{
				"ALL_TRUSTED": "trusted",
			},
		},
		{
			name:              "Spam email True flag",
			header:            "default: True [16.50 / 15.00];\n\tBAYES_99(5.00)[1.00]; SPOOFED_SENDER(3.50)",
			expectedScore:     16.50,
			expectedThreshold: 15.00,
			expectedIsSpam:    true,
			expectedSymbols: map[string]float32{
				"BAYES_99":       5.00,
				"SPOOFED_SENDER": 3.50,
			},
			expectedSymParams: map[string]string{
				"BAYES_99": "1.00",
			},
		},
		{
			// An unusable threshold is left at 0 here: effectiveThreshold is
			// the single place that substitutes the add-header default.
			name:              "Zero threshold is left unset",
			header:            "default: False [1.00 / 0.00]",
			expectedScore:     1.00,
			expectedThreshold: 0,
			expectedIsSpam:    false,
			expectedSymbols:   map[string]float32{},
		},
		{
			name:              "Symbol without params",
			header:            "default: False [2.00 / 15.00];\n\tMISSING_DATE(1.00)",
			expectedScore:     2.00,
			expectedThreshold: 15.00,
			expectedIsSpam:    false,
			expectedSymbols: map[string]float32{
				"MISSING_DATE": 1.00,
			},
		},
		{
			name:              "Case-insensitive true flag",
			header:            "default: true [8.00 / 6.00]",
			expectedScore:     8.00,
			expectedThreshold: 6.00,
			expectedIsSpam:    true,
			expectedSymbols:   map[string]float32{},
		},
		{
			name: "Zero threshold with symbols containing nested brackets in params",
			header: "default: False [0.90 / 0.00];\n" +
				"\tARC_REJECT(1.00)[cannot verify 1 of 1 signatures: {[1] = sig:mail-tester.local:signature has incorrect length: 12}];\n" +
				"\tMIME_GOOD(-0.10)[multipart/alternative,text/plain];\n" +
				"\tMIME_TRACE(0.00)[0:+,1:+,2:~]",
			expectedScore:     0.90,
			expectedThreshold: 0,
			expectedIsSpam:    false,
			expectedSymbols: map[string]float32{
				"ARC_REJECT": 1.00,
				"MIME_GOOD":  -0.10,
				"MIME_TRACE": 0.00,
			},
			expectedSymParams: map[string]string{
				"ARC_REJECT": "cannot verify 1 of 1 signatures: {[1] = sig:mail-tester.local:signature has incorrect length: 12}",
				"MIME_GOOD":  "multipart/alternative,text/plain",
				"MIME_TRACE": "0:+,1:+,2:~",
			},
		},
	}

	analyzer := NewRspamdAnalyzer(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.RspamdResult{
				Symbols: make(map[string]model.SpamTestDetail),
			}
			analyzer.parseSpamdResult(tt.header, result)

			if result.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", result.Score, tt.expectedScore)
			}
			if got := reportedThreshold(result); got != tt.expectedThreshold {
				t.Errorf("Threshold = %v, want %v", got, tt.expectedThreshold)
			}
			if result.IsSpam != tt.expectedIsSpam {
				t.Errorf("IsSpam = %v, want %v", result.IsSpam, tt.expectedIsSpam)
			}
			for symName, expectedScore := range tt.expectedSymbols {
				sym, ok := result.Symbols[symName]
				if !ok {
					t.Errorf("Symbol %s not found", symName)
					continue
				}
				if sym.Score != expectedScore {
					t.Errorf("Symbol %s score = %v, want %v", symName, sym.Score, expectedScore)
				}
			}
			for symName, expectedParam := range tt.expectedSymParams {
				sym, ok := result.Symbols[symName]
				if !ok {
					t.Errorf("Symbol %s not found for params check", symName)
					continue
				}
				if sym.Params == nil {
					t.Errorf("Symbol %s params = nil, want %q", symName, expectedParam)
				} else if *sym.Params != expectedParam {
					t.Errorf("Symbol %s params = %q, want %q", symName, *sym.Params, expectedParam)
				}
			}
		})
	}
}

func TestAnalyzeRspamd(t *testing.T) {
	tests := []struct {
		name              string
		headers           map[string]string
		expectedScore     float32
		expectedThreshold float32
		expectedIsSpam    bool
		expectedServer    *string
		expectedSymCount  int
	}{
		{
			name: "Full headers clean email",
			headers: map[string]string{
				"X-Spamd-Result":  "default: False [-3.91 / 15.00];\n\tALL_TRUSTED(-1.00)[local]",
				"X-Rspamd-Score":  "-3.91",
				"X-Rspamd-Server": "mail.example.com",
			},
			expectedScore:     -3.91,
			expectedThreshold: 15.00,
			expectedIsSpam:    false,
			expectedServer:    func() *string { s := "mail.example.com"; return &s }(),
			expectedSymCount:  1,
		},
		{
			name: "X-Rspamd-Score overrides spamd result score",
			headers: map[string]string{
				"X-Spamd-Result": "default: False [2.00 / 15.00]",
				"X-Rspamd-Score": "3.50",
			},
			expectedScore:     3.50,
			expectedThreshold: 15.00,
			expectedIsSpam:    false,
		},
		{
			name: "Spam email above threshold",
			headers: map[string]string{
				"X-Spamd-Result": "default: True [16.00 / 15.00];\n\tBAYES_99(5.00)",
				"X-Rspamd-Score": "16.00",
			},
			expectedScore:     16.00,
			expectedThreshold: 15.00,
			expectedIsSpam:    true,
			expectedSymCount:  1,
		},
		{
			name: "No X-Spamd-Result, only X-Rspamd-Score below default threshold",
			headers: map[string]string{
				"X-Rspamd-Score": "2.00",
			},
			expectedScore:  2.00,
			expectedIsSpam: false,
		},
		{
			name: "No X-Spamd-Result, X-Rspamd-Score above default add-header threshold",
			headers: map[string]string{
				"X-Rspamd-Score": "7.00",
			},
			expectedScore:  7.00,
			expectedIsSpam: true,
		},
		{
			name: "Server header is trimmed",
			headers: map[string]string{
				"X-Rspamd-Score":  "1.00",
				"X-Rspamd-Server": "  rspamd-01  ",
			},
			expectedScore:  1.00,
			expectedServer: func() *string { s := "rspamd-01"; return &s }(),
		},
	}

	analyzer := NewRspamdAnalyzer(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{Header: make(mail.Header)}
			for k, v := range tt.headers {
				email.Header[k] = []string{v}
			}

			result := analyzer.AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))

			if result == nil {
				t.Fatal("Expected non-nil result")
			}
			if result.Score != tt.expectedScore {
				t.Errorf("Score = %v, want %v", result.Score, tt.expectedScore)
			}
			if got := reportedThreshold(result); tt.expectedThreshold > 0 && got != tt.expectedThreshold {
				t.Errorf("Threshold = %v, want %v", got, tt.expectedThreshold)
			}
			if result.IsSpam != tt.expectedIsSpam {
				t.Errorf("IsSpam = %v, want %v", result.IsSpam, tt.expectedIsSpam)
			}
			if tt.expectedServer != nil {
				if result.Server == nil {
					t.Errorf("Server = nil, want %q", *tt.expectedServer)
				} else if *result.Server != *tt.expectedServer {
					t.Errorf("Server = %q, want %q", *result.Server, *tt.expectedServer)
				}
			}
			if tt.expectedSymCount > 0 && len(result.Symbols) != tt.expectedSymCount {
				t.Errorf("Symbol count = %d, want %d", len(result.Symbols), tt.expectedSymCount)
			}
		})
	}
}

func TestCalculateRspamdScore(t *testing.T) {
	tests := []struct {
		name          string
		result        *model.RspamdResult
		expectedScore int
		expectedGrade string
	}{
		{
			name:          "Nil result (rspamd not installed)",
			result:        nil,
			expectedScore: 100,
			expectedGrade: "",
		},
		{
			name: "Score well below threshold",
			result: &model.RspamdResult{
				Score:     -3.91,
				Threshold: utils.PtrTo[float32](15.00),
			},
			expectedScore: 100,
			expectedGrade: "A+",
		},
		{
			name: "Score at zero",
			result: &model.RspamdResult{
				Score:     0,
				Threshold: utils.PtrTo[float32](15.00),
			},
			// 100 - round(0*100/30) = 100 → hits ScoreToGrade(100) = "A"
			expectedScore: 100,
			expectedGrade: "A",
		},
		{
			name: "Score at threshold",
			result: &model.RspamdResult{
				Score:     15.00,
				Threshold: utils.PtrTo[float32](15.00),
			},
			// 100 - round(15*100/15) = 100 - 100 = 0
			expectedScore: 0,
			expectedGrade: "F",
		},
		{
			name: "Score above 2*threshold",
			result: &model.RspamdResult{
				Score:     31.00,
				Threshold: utils.PtrTo[float32](15.00),
			},
			expectedScore: 0,
			expectedGrade: "F",
		},
		{
			name: "Score exactly at 2*threshold",
			result: &model.RspamdResult{
				Score:     30.00,
				Threshold: utils.PtrTo[float32](15.00),
			},
			// 100 - round(30*100/15) = 100 - 200 = -100 → clamped to 0
			expectedScore: 0,
			expectedGrade: "F",
		},
		{
			name: "Unreported threshold falls back to the add-header default of 6",
			result: &model.RspamdResult{
				Score: 3,
			},
			// 100 - round(3*100/6) = 100 - 50 = 50
			expectedScore: 50,
			expectedGrade: "E",
		},
	}

	analyzer := NewRspamdAnalyzer(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := analyzer.CalculateRspamdScore(tt.result)

			if score != tt.expectedScore {
				t.Errorf("Score = %d, want %d", score, tt.expectedScore)
			}
			if tt.expectedGrade != "" && grade != tt.expectedGrade {
				t.Errorf("Grade = %q, want %q", grade, tt.expectedGrade)
			}
		})
	}
}

const sampleEmailWithRspamdHeaders = `X-Spamd-Result: default: False [-3.91 / 15.00];
	BAYES_HAM(-3.00)[99%];
	RCVD_IN_DNSWL_MED(-0.01)[1.2.3.4:from];
	R_DKIM_ALLOW(-0.20)[example.com:s=dkim];
	FROM_HAS_DN(0.00)[];
	MIME_GOOD(-0.10)[text/plain];
X-Rspamd-Score: -3.91
X-Rspamd-Server: rspamd-01.example.com
Date: Mon, 09 Mar 2026 10:00:00 +0000
From: sender@example.com
To: test@happydomain.org
Subject: Test email
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain

Hello world`

func TestAnalyzeRspamdRealEmail(t *testing.T) {
	email, err := ParseEmail([]byte(sampleEmailWithRspamdHeaders))
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}

	analyzer := NewRspamdAnalyzer(nil)
	result := analyzer.AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.IsSpam {
		t.Error("Expected IsSpam=false")
	}
	if result.Score != -3.91 {
		t.Errorf("Score = %v, want -3.91", result.Score)
	}
	if got := reportedThreshold(result); got != 15.00 {
		t.Errorf("Threshold = %v, want 15.00", got)
	}
	if result.Server == nil || *result.Server != "rspamd-01.example.com" {
		t.Errorf("Server = %v, want \"rspamd-01.example.com\"", result.Server)
	}

	expectedSymbols := []string{"BAYES_HAM", "RCVD_IN_DNSWL_MED", "R_DKIM_ALLOW", "FROM_HAS_DN", "MIME_GOOD"}
	for _, sym := range expectedSymbols {
		if _, ok := result.Symbols[sym]; !ok {
			t.Errorf("Symbol %s not found", sym)
		}
	}

	score, _ := analyzer.CalculateRspamdScore(result)
	if score != 100 {
		t.Errorf("CalculateRspamdScore = %d, want 100", score)
	}
}

// TestAnalyzeRspamdSpamStatus checks the SpamAssassin-shaped X-Spam-Status rspamd
// emits when it runs alongside one, picked out of several X-Spam-Status headers.
func TestAnalyzeRspamdSpamStatus(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spam-Status"] = []string{
		"No, rspamdscore=-4.78, required=10.00",
		"No, score=0.00, required=95.00",
	}
	email.Header["X-Rspamd-Server"] = []string{"rspamd15"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != -4.78 {
		t.Errorf("Score = %v, want -4.78", result.Score)
	}
	if got := reportedThreshold(result); got != 10 {
		t.Errorf("Threshold = %v, want 10", got)
	}
	if result.IsSpam {
		t.Error("IsSpam should be false")
	}
	if result.Server == nil || *result.Server != "rspamd15" {
		t.Errorf("Server = %v, want rspamd15", result.Server)
	}
}

// TestAnalyzeRspamdSpamStatusIgnoredWhenSpamdResultPresent checks that the richer
// X-Spamd-Result header wins over rspamd's X-Spam-Status variant when both carry a
// score and threshold, since X-Spam-Status is only meant as a fallback.
func TestAnalyzeRspamdSpamStatusIgnoredWhenSpamdResultPresent(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spamd-Result"] = []string{"default: False [-3.91 / 15.00]; BAYES_HAM(-1.0)"}
	email.Header["X-Spam-Status"] = []string{"No, rspamdscore=-4.78, required=10.00"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != -3.91 {
		t.Errorf("Score = %v, want -3.91 (from X-Spamd-Result, not X-Spam-Status)", result.Score)
	}
	if got := reportedThreshold(result); got != 15.00 {
		t.Errorf("Threshold = %v, want 15.00 (from X-Spamd-Result, not X-Spam-Status)", got)
	}
}

// TestAnalyzeRspamdSpamStatusZeroRequired checks that a "required=0.00" in rspamd's
// X-Spam-Status is not taken at face value: the add-header default is substituted,
// the message being scored against the add-header default instead. The
// substituted value is not published: only a threshold the instance actually
// reported is.
func TestAnalyzeRspamdSpamStatusZeroRequired(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spam-Status"] = []string{"No, rspamdscore=2.5, required=0.00"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != 2.5 {
		t.Errorf("Score = %v, want 2.5", result.Score)
	}
	if result.Threshold != nil {
		t.Errorf("Threshold = %v, want none reported (required=0.00 must not be taken as a real threshold)", *result.Threshold)
	}
	if result.IsSpam {
		t.Error("IsSpam should be false: score 2.5 is below the add-header default of 6")
	}
}

// TestAnalyzeRspamdSpamStatusCaseInsensitive checks that an X-Spam-Status header is
// still recognized and parsed as rspamd's even when its markers are not lowercase.
func TestAnalyzeRspamdSpamStatusCaseInsensitive(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spam-Status"] = []string{"No, RspamdScore=-1.5, Required=5.00"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != -1.5 {
		t.Errorf("Score = %v, want -1.5", result.Score)
	}
	if got := reportedThreshold(result); got != 5 {
		t.Errorf("Threshold = %v, want 5", got)
	}
}

// TestAnalyzeRspamdShapedHeadersOnly checks the configuration where rspamd writes
// none of its extended headers: the SpamAssassin-shaped ones it does write are
// attributed to it, and must be read by it, or the verdict is lost by both
// analyzers.
func TestAnalyzeRspamdShapedHeadersOnly(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spam"] = []string{"Yes"}
	email.Header["X-Rspamd-Server"] = []string{"rspamd15"}
	email.Header["X-Spam-Score"] = []string{"7.5"}
	email.Header["X-Spam-Flag"] = []string{"YES"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != 7.5 {
		t.Errorf("Score = %v, want 7.5", result.Score)
	}
	if !result.IsSpam {
		t.Error("IsSpam should be true: score 7.5 is above the add-header default of 6")
	}

	if sa := NewSpamAssassinAnalyzer().AnalyzeSpamAssassin(spamHeadersOf(email, ScannerSpamAssassin)); sa != nil {
		t.Errorf("SpamAssassin result = %+v, want nil: these headers are rspamd's", sa)
	}
}

// TestAnalyzeRspamdShapedFlagWithoutScore checks that the X-Spam-Flag verdict is
// kept when no header of the message carries a score: deriving IsSpam from an
// absent score would silently turn a spam verdict into ham.
func TestAnalyzeRspamdShapedFlagWithoutScore(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spam"] = []string{"Yes"}
	email.Header["X-Spam-Flag"] = []string{"YES"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if !result.IsSpam {
		t.Error("IsSpam should be true: X-Spam-Flag is the only verdict available")
	}
}

// TestAnalyzeRspamdShapedHeadersAreOnlyFallbacks checks that the shaped headers
// never override what rspamd's own headers already reported.
func TestAnalyzeRspamdShapedHeadersAreOnlyFallbacks(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Spamd-Result"] = []string{"default: False [-3.91 / 15.00]; BAYES_HAM(-1.0)"}
	email.Header["X-Spam-Score"] = []string{"9.0"}
	email.Header["X-Spam-Flag"] = []string{"YES"}

	result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd))
	if result == nil {
		t.Fatal("Expected rspamd result, got nil")
	}

	if result.Score != -3.91 {
		t.Errorf("Score = %v, want -3.91 (from X-Spamd-Result, not X-Spam-Score)", result.Score)
	}
	if result.IsSpam {
		t.Error("IsSpam should be false: -3.91 is well below the reported threshold")
	}
}

// TestAnalyzeRspamdStampsOnly checks that headers rspamd stamps on every message
// it touches, carrying no verdict, do not produce an empty report scored 0.
func TestAnalyzeRspamdStampsOnly(t *testing.T) {
	email := &EmailMessage{Header: make(mail.Header)}
	email.Header["X-Rspamd-Server"] = []string{"rspamd15"}
	email.Header["X-Rspamd-Queue-Id"] = []string{"4A2B3C4D5E"}

	if result := NewRspamdAnalyzer(nil).AnalyzeRspamd(spamHeadersOf(email, ScannerRspamd)); result != nil {
		t.Errorf("Expected nil result, got %+v", result)
	}
}
