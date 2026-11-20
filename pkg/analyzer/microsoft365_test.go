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
	"strconv"
	"testing"

	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

const m365CleanOutbound = "CIP:192.0.2.1;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.example.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024);DIR:OUT;SFP:1101;"

func TestSpamScannerHeadersMicrosoft365(t *testing.T) {
	email := &mailmsg.Message{Header: mail.Header{
		"X-Forefront-Antispam-Report":           {m365CleanOutbound},
		"X-Microsoft-Antispam":                  {"BCL:0;ARA:13230040|366016;"},
		"X-Forefront-Antispam-Report-Untrusted": {"CIP:255.255.255.255;SCL:9;SFV:SPM;"},
		"X-Spam-Status":                         {"No, score=0.1 required=5.0 tests=NONE"},
	}}

	set := spamScannerHeaders(email)

	assertHeaderMap(t, "Microsoft365", set.For(ScannerMicrosoft365), map[string]string{
		"X-Forefront-Antispam-Report": m365CleanOutbound,
		"X-Microsoft-Antispam":        "BCL:0;ARA:13230040|366016;",
	})
	assertHeaderMap(t, "SpamAssassin", set.For(ScannerSpamAssassin), map[string]string{
		"X-Spam-Status": "No, score=0.1 required=5.0 tests=NONE",
	})
}

func TestAnalyzeMicrosoft365(t *testing.T) {
	tests := []struct {
		name          string
		headers       ScannerHeaders
		wantNil       bool
		wantSpam      bool
		wantDirection string
		wantSCL       *int
		wantBCL       *int
		wantVerdict   string
		wantCategory  string
		wantBulk      bool
	}{
		{
			name:    "no header",
			headers: ScannerHeaders{},
			wantNil: true,
		},
		{
			name:    "a header with no verdict in it",
			headers: ScannerHeaders{"X-Microsoft-Antispam": "ARA:13230040;"},
			wantNil: true,
		},
		{
			name: "clean outbound message",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": m365CleanOutbound,
				"X-Microsoft-Antispam":        "BCL:0;ARA:13230040;",
			},
			wantDirection: m365Outbound,
			wantSCL:       utils.PtrTo(1),
			wantBCL:       utils.PtrTo(0),
			wantVerdict:   "NSPM",
			wantCategory:  "NONE",
		},
		{
			name: "spam by its category",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:5;SFV:SPM;CAT:SPM;DIR:INB;",
			},
			wantSpam:      true,
			wantDirection: m365Inbound,
			wantSCL:       utils.PtrTo(5),
			wantVerdict:   "SPM",
			wantCategory:  "SPM",
		},
		{
			name: "a high confidence level alone is not spam",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:9;SFV:NSPM;CAT:NONE;DIR:INT;",
			},
			wantDirection: m365Internal,
			wantSCL:       utils.PtrTo(9),
			wantVerdict:   "NSPM",
			wantCategory:  "NONE",
		},
		{
			name: "released from quarantine",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:1;SFV:SKQ;",
			},
			wantSpam:    true,
			wantSCL:     utils.PtrTo(1),
			wantVerdict: "SKQ",
		},
		{
			name: "spam by a rule run before the filter",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:-1;SFV:SKS;DIR:OUT;",
			},
			wantSpam:      true,
			wantDirection: m365Outbound,
			wantSCL:       utils.PtrTo(-1),
			wantVerdict:   "SKS",
		},
		{
			name: "bulk is not spam",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:1;SFV:NSPM;CAT:BULK;",
				"X-Microsoft-Antispam":        "BCL:8;",
			},
			wantSCL:      utils.PtrTo(1),
			wantBCL:      utils.PtrTo(8),
			wantVerdict:  "NSPM",
			wantCategory: "BULK",
		},
		{
			name: "bulk by the filter's own mark",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SRV:BULK;",
			},
			wantBulk: true,
		},
		{
			name: "an out-of-range level is ignored",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": "SCL:42;sfv:nspm;",
			},
			wantVerdict: "NSPM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeMicrosoft365(tt.headers)
			if tt.wantNil {
				if result != nil {
					t.Fatalf("got %+v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("got nil, want a result")
			}

			if result.IsSpam != tt.wantSpam {
				t.Errorf("IsSpam = %v, want %v", result.IsSpam, tt.wantSpam)
			}
			if got := deref(result.Direction); got != tt.wantDirection {
				t.Errorf("Direction = %q, want %q", got, tt.wantDirection)
			}
			assertLevel(t, "SCL", result.Scl, tt.wantSCL)
			assertLevel(t, "BCL", result.Bcl, tt.wantBCL)
			if got := deref(result.FilterVerdict); got != tt.wantVerdict {
				t.Errorf("FilterVerdict = %q, want %q", got, tt.wantVerdict)
			}
			if got := deref(result.Category); got != tt.wantCategory {
				t.Errorf("Category = %q, want %q", got, tt.wantCategory)
			}
			if result.Bulk != tt.wantBulk {
				t.Errorf("Bulk = %v, want %v", result.Bulk, tt.wantBulk)
			}
		})
	}
}

func TestAnalyzeMicrosoft365Verdict(t *testing.T) {
	tests := []struct {
		name        string
		report      string
		antispam    string
		wantVerdict string
		wantSpam    bool
		wantGrade   string
	}{
		{"clean", m365CleanOutbound, "BCL:0;", "Inbox", false, ""},
		{"filtering skipped", "SCL:-1;SFV:SKN;", "", "Not filtered", false, ""},
		{"bulk under the preset policies only", "SCL:1;SFV:NSPM;CAT:NONE;", "BCL:6;", "Bulk under preset policies", false, "D"},
		{"bulk", "SCL:1;SFV:NSPM;CAT:BULK;", "BCL:8;", "Bulk, junk folder", false, "E"},
		{"spam", "SCL:5;SFV:SPM;CAT:SPM;DIR:INB;", "", "Junk folder", true, "E"},
		{"spam leaving its tenant", "SCL:5;SFV:SPM;CAT:OSPM;DIR:OUT;", "", "High-risk delivery pool", true, "E"},
		{"released from quarantine", "SCL:1;SFV:SKQ;CAT:NONE;", "", "Released from quarantine", true, "E"},
		{"impersonation", "SCL:1;SFV:NSPM;CAT:UIMP;", "", "Impersonation", true, "E"},
		{"high confidence spam", "SCL:9;SFV:SPM;CAT:HSPM;", "", "Junk folder", true, "F"},
		{"high confidence phishing", "SCL:9;SFV:SPM;CAT:HPHSH;", "", "Quarantined", true, "F"},
		{"blocked file type", "SCL:1;SFV:NSPM;CAT:FTBP;", "", "Rejected", true, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := ScannerHeaders{"X-Forefront-Antispam-Report": tt.report}
			if tt.antispam != "" {
				headers["X-Microsoft-Antispam"] = tt.antispam
			}

			verdict := analyzeMicrosoft365Verdict(headers)
			if verdict == nil {
				t.Fatal("got nil, want a verdict")
			}
			if verdict.Verdict != tt.wantVerdict || verdict.IsSpam != tt.wantSpam || verdict.Grade != tt.wantGrade {
				t.Errorf("got %q spam=%v grade=%q, want %q spam=%v grade=%q",
					verdict.Verdict, verdict.IsSpam, verdict.Grade, tt.wantVerdict, tt.wantSpam, tt.wantGrade)
			}
			if _, ok := verdict.Details.(*microsoft365Details); !ok {
				t.Errorf("Details = %T, want *microsoft365Details", verdict.Details)
			}
		})
	}
}

func TestCalculateMicrosoft365Score(t *testing.T) {
	tests := []struct {
		name      string
		headers   ScannerHeaders
		wantScore int
		wantGrade string
	}{
		{
			name:      "no verdict",
			wantScore: 100,
		},
		{
			name: "a clean verdict does not count",
			headers: ScannerHeaders{
				"X-Forefront-Antispam-Report": m365CleanOutbound,
				"X-Microsoft-Antispam":        "BCL:0;",
			},
			wantScore: 100,
		},
		{
			name:      "skipped filtering does not count",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:-1;SFV:SKN;"},
			wantScore: 100,
		},
		{
			name:      "bulk under the strict policy only",
			headers:   ScannerHeaders{"X-Microsoft-Antispam": "BCL:5;"},
			wantScore: 74,
			wantGrade: "D",
		},
		{
			name:      "bulk under the default policy",
			headers:   ScannerHeaders{"X-Microsoft-Antispam": "BCL:7;"},
			wantScore: 64,
			wantGrade: "E",
		},
		{
			name:      "spam",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:5;SFV:SPM;CAT:SPM;"},
			wantScore: 64,
			wantGrade: "E",
		},
		{
			name:      "bulk by the filter's own mark",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:1;SFV:NSPM;SRV:BULK;CAT:NONE;"},
			wantScore: 64,
			wantGrade: "E",
		},
		{
			name:      "a spam confidence level alone does not count",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:9;SFV:NSPM;CAT:NONE;"},
			wantScore: 100,
		},
		{
			name:      "spoofing",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:1;SFV:NSPM;CAT:SPOOF;"},
			wantScore: 64,
			wantGrade: "E",
		},
		{
			name:      "high confidence spam",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:9;SFV:SPM;CAT:HSPM;"},
			wantScore: 49,
			wantGrade: "F",
		},
		{
			name:      "malware, whatever the levels",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:1;SFV:NSPM;CAT:MALW;"},
			wantScore: 49,
			wantGrade: "F",
		},
		{
			name:      "phishing, whatever the level",
			headers:   ScannerHeaders{"X-Forefront-Antispam-Report": "SCL:1;SFV:NSPM;CAT:PHSH;"},
			wantScore: 49,
			wantGrade: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade := CalculateMicrosoft365Score(AnalyzeMicrosoft365(tt.headers))
			if score != tt.wantScore || grade != tt.wantGrade {
				t.Errorf("got %d %q, want %d %q", score, grade, tt.wantScore, tt.wantGrade)
			}
		})
	}
}

func assertLevel(t *testing.T, name string, got, want *int) {
	t.Helper()

	switch {
	case got == nil && want == nil:
	case got == nil || want == nil || *got != *want:
		t.Errorf("%s = %v, want %v", name, ptrString(got), ptrString(want))
	}
}

func ptrString(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return strconv.Itoa(*p)
}
