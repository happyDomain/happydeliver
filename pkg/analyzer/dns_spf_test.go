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
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// TestValidateSPF exercises validateSPF (and the isValidSPFMechanism check
// it applies to every token). A record is valid when: it starts with the
// literal "v=spf1"; every subsequent whitespace-separated token, after
// stripping an optional qualifier prefix (+, -, ~, ?), is either a known
// standalone mechanism ("all", "a", "mx", "ptr"), a known mechanism with a
// ":" or "/" value ("include:_spf.example.com", "ip4:192.0.2.0/24"), or a
// known modifier ("redirect=...", "exp=...", "ra=/rp=/rr=..."); and — for the
// main (non-included) record only — it ends in an "all" mechanism (e.g.
// "-all", "~all") unless it has a "redirect=" modifier instead. It's invalid
// for using an unrecognized mechanism/modifier name, for using "=" where a
// mechanism expects ":" (e.g. "include=..." is flagged with a dedicated
// error rather than "unknown mechanism"), or for a main record missing both
// a trailing "all" and a "redirect=".
func TestValidateSPF(t *testing.T) {
	tests := []struct {
		name        string
		record      string
		expectError bool
		errorMsg    string // Expected error message (substring match)
	}{
		{
			name:        "Valid SPF with -all",
			record:      "v=spf1 include:_spf.example.com -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with ~all",
			record:      "v=spf1 ip4:192.0.2.0/24 ~all",
			expectError: false,
		},
		{
			name:        "Valid SPF with +all",
			record:      "v=spf1 +all",
			expectError: false,
		},
		{
			name:        "Valid SPF with ?all",
			record:      "v=spf1 mx ?all",
			expectError: false,
		},
		{
			name:        "Valid SPF with redirect",
			record:      "v=spf1 redirect=_spf.example.com",
			expectError: false,
		},
		{
			name:        "Valid SPF with redirect and mechanisms",
			record:      "v=spf1 ip4:192.0.2.0/24 redirect=_spf.example.com",
			expectError: false,
		},
		{
			name:        "Valid SPF with multiple mechanisms",
			record:      "v=spf1 a mx ip4:192.0.2.0/24 include:_spf.example.com -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with exp modifier",
			record:      "v=spf1 mx exp=explain.example.com -all",
			expectError: false,
		},
		{
			name:        "Invalid SPF - no version",
			record:      "include:_spf.example.com -all",
			expectError: true,
			errorMsg:    "must start with 'v=spf1'",
		},
		{
			name:        "Invalid SPF - no all mechanism or redirect",
			record:      "v=spf1 include:_spf.example.com",
			expectError: true,
			errorMsg:    "should end with an 'all' mechanism",
		},
		{
			name:        "Invalid SPF - wrong version",
			record:      "v=spf2 include:_spf.example.com -all",
			expectError: true,
			errorMsg:    "must start with 'v=spf1'",
		},
		{
			name:        "Invalid SPF - include= instead of include:",
			record:      "v=spf1 include=icloud.com ~all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - a= instead of a:",
			record:      "v=spf1 a=example.com -all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - mx= instead of mx:",
			record:      "v=spf1 mx=example.com -all",
			expectError: true,
			errorMsg:    "should use ':' not '='",
		},
		{
			name:        "Invalid SPF - unknown mechanism",
			record:      "v=spf1 foobar -all",
			expectError: true,
			errorMsg:    "unknown mechanism",
		},
		{
			name:        "Invalid SPF - unknown modifier",
			record:      "v=spf1 -all unknown=value",
			expectError: true,
			errorMsg:    "unknown modifier",
		},
		{
			name:        "Valid SPF with RFC 6652 ra modifier",
			record:      "v=spf1 mx ra=postmaster -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with RFC 6652 rp modifier",
			record:      "v=spf1 mx rp=100 -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with RFC 6652 rr modifier",
			record:      "v=spf1 mx rr=all -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with all RFC 6652 modifiers",
			record:      "v=spf1 mx ra=postmaster rp=50 rr=fail -all",
			expectError: false,
		},
		{
			name:        "Valid SPF with RFC 6652 modifiers and redirect",
			record:      "v=spf1 ip4:192.0.2.0/24 ra=abuse redirect=_spf.example.com",
			expectError: false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test as main record (isMainRecord = true) since these tests check overall SPF validity
			err := analyzer.validateSPF(tt.record, true)
			if tt.expectError {
				if err == nil {
					t.Errorf("validateSPF(%q) expected error but got nil", tt.record)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateSPF(%q) error = %q, want error containing %q", tt.record, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateSPF(%q) unexpected error: %v", tt.record, err)
				}
			}
		})
	}
}

func TestValidateSPF_IncludedRecords(t *testing.T) {
	tests := []struct {
		name         string
		record       string
		isMainRecord bool
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Main record without 'all' - should error",
			record:       "v=spf1 include:_spf.example.com",
			isMainRecord: true,
			expectError:  true,
			errorMsg:     "should end with an 'all' mechanism",
		},
		{
			name:         "Included record without 'all' - should NOT error",
			record:       "v=spf1 include:_spf.example.com",
			isMainRecord: false,
			expectError:  false,
		},
		{
			name:         "Included record with only mechanisms - should NOT error",
			record:       "v=spf1 ip4:192.0.2.0/24 mx",
			isMainRecord: false,
			expectError:  false,
		},
		{
			name:         "Main record with only mechanisms - should error",
			record:       "v=spf1 ip4:192.0.2.0/24 mx",
			isMainRecord: true,
			expectError:  true,
			errorMsg:     "should end with an 'all' mechanism",
		},
		{
			name:         "Included record with 'all' - valid",
			record:       "v=spf1 ip4:192.0.2.0/24 -all",
			isMainRecord: false,
			expectError:  false,
		},
		{
			name:         "Main record with 'all' - valid",
			record:       "v=spf1 ip4:192.0.2.0/24 -all",
			isMainRecord: true,
			expectError:  false,
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := analyzer.validateSPF(tt.record, tt.isMainRecord)
			if tt.expectError {
				if err == nil {
					t.Errorf("validateSPF(%q, isMainRecord=%v) expected error but got nil", tt.record, tt.isMainRecord)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateSPF(%q, isMainRecord=%v) error = %q, want error containing %q", tt.record, tt.isMainRecord, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateSPF(%q, isMainRecord=%v) unexpected error: %v", tt.record, tt.isMainRecord, err)
				}
			}
		})
	}
}

func TestExtractSPFRedirect(t *testing.T) {
	tests := []struct {
		name             string
		record           string
		expectedRedirect string
	}{
		{
			name:             "SPF with redirect",
			record:           "v=spf1 redirect=_spf.example.com",
			expectedRedirect: "_spf.example.com",
		},
		{
			name:             "SPF with redirect and other mechanisms",
			record:           "v=spf1 ip4:192.0.2.0/24 redirect=_spf.google.com",
			expectedRedirect: "_spf.google.com",
		},
		{
			name:             "SPF without redirect",
			record:           "v=spf1 include:_spf.example.com -all",
			expectedRedirect: "",
		},
		{
			name:             "SPF with only all mechanism",
			record:           "v=spf1 -all",
			expectedRedirect: "",
		},
		{
			name:             "Empty record",
			record:           "",
			expectedRedirect: "",
		},
	}

	analyzer := NewDNSAnalyzer(5 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.extractSPFRedirect(tt.record)
			if result != tt.expectedRedirect {
				t.Errorf("extractSPFRedirect(%q) = %q, want %q", tt.record, result, tt.expectedRedirect)
			}
		})
	}
}

func TestCheckSPFRecordsForeignRecordHint(t *testing.T) {
	// When a record of another type is served at the SPF location (e.g. by a
	// misbehaving resolver), SPF correctly reports no record but hints at the
	// misconfiguration.
	const phantom = "v=DMARC1;p=quarantine;pct=0;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;fo=1"

	analyzer := newMockAnalyzer(map[string][]string{
		"example.com": {phantom},
	}, nil)

	records := analyzer.checkSPFRecords("example.com")
	if records == nil || len(*records) != 1 {
		t.Fatalf("expected exactly one SPF result, got %v", records)
	}
	rec := (*records)[0]
	if rec.Valid {
		t.Fatalf("expected SPF record to be invalid, got valid")
	}
	if rec.Record != nil {
		t.Errorf("Record should be nil (the foreign record must not be adopted as SPF), got %q", *rec.Record)
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "No SPF record found") {
		t.Errorf("Error = %v, want to contain %q", rec.Error, "No SPF record found")
	}
	if rec.Error == nil || !strings.Contains(*rec.Error, "a DMARC record") {
		t.Errorf("Error = %v, want to mention the misplaced DMARC record", rec.Error)
	}
}

func TestNoSPFRecordErrorPlain(t *testing.T) {
	if got := noSPFRecordError(nil); got != "No SPF record found" {
		t.Errorf("noSPFRecordError(nil) = %q, want %q", got, "No SPF record found")
	}
	if got := noSPFRecordError([]string{"some unrelated txt value"}); got != "No SPF record found" {
		t.Errorf("noSPFRecordError(unrelated) = %q, want plain message", got)
	}
}

func TestCheckHeloSPFRecord(t *testing.T) {
	tests := []struct {
		name             string
		helo             string
		txt              map[string][]string
		errMap           map[string]error
		wantValid        bool
		wantRecord       *string
		wantAllQualifier *model.SPFRecordAllQualifier
		wantErrSubst     string
	}{
		{
			name: "HELO hostname publishes a valid policy",
			helo: "mail.example.com",
			txt: map[string][]string{
				"mail.example.com": {"v=spf1 ip4:192.0.2.10 -all"},
			},
			wantValid:        true,
			wantRecord:       utils.PtrTo("v=spf1 ip4:192.0.2.10 -all"),
			wantAllQualifier: utils.PtrTo(model.SPFRecordAllQualifier("-")),
		},
		{
			// The common case: a relay hostname carries no policy of its own
			name:         "no SPF record",
			helo:         "mail.example.com",
			txt:          map[string][]string{"mail.example.com": {"some-unrelated-txt"}},
			wantErrSubst: "No SPF record found",
		},
		{
			name:         "hostname does not resolve",
			helo:         "mail.example.com",
			txt:          map[string][]string{},
			wantErrSubst: "Failed to lookup TXT records",
		},
		{
			name: "multiple SPF records",
			helo: "mail.example.com",
			txt: map[string][]string{
				"mail.example.com": {"v=spf1 ip4:192.0.2.10 -all", "v=spf1 ip4:192.0.2.11 -all"},
			},
			wantRecord:   utils.PtrTo("v=spf1 ip4:192.0.2.10 -all"),
			wantErrSubst: "Multiple SPF records found",
		},
		{
			name: "invalid policy is reported but stays informational",
			helo: "mail.example.com",
			txt: map[string][]string{
				"mail.example.com": {"v=spf1 include=example.net -all"},
			},
			wantRecord:   utils.PtrTo("v=spf1 include=example.net -all"),
			wantErrSubst: "should use ':' not '='",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := newMockAnalyzer(tt.txt, tt.errMap)

			result := analyzer.checkHeloSPFRecord(tt.helo)

			if result == nil {
				t.Fatal("checkHeloSPFRecord() = nil, want a result")
			}
			if result.Domain == nil || *result.Domain != tt.helo {
				t.Errorf("Domain = %v, want %v", result.Domain, tt.helo)
			}
			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			if tt.wantRecord == nil {
				if result.Record != nil {
					t.Errorf("Record = %q, want none", *result.Record)
				}
			} else if result.Record == nil || *result.Record != *tt.wantRecord {
				t.Errorf("Record = %v, want %q", result.Record, *tt.wantRecord)
			}

			if tt.wantAllQualifier == nil {
				if result.AllQualifier != nil {
					t.Errorf("AllQualifier = %q, want none", *result.AllQualifier)
				}
			} else if result.AllQualifier == nil || *result.AllQualifier != *tt.wantAllQualifier {
				t.Errorf("AllQualifier = %v, want %q", result.AllQualifier, *tt.wantAllQualifier)
			}

			if tt.wantErrSubst == "" {
				if result.Error != nil {
					t.Errorf("Error = %q, want none", *result.Error)
				}
			} else if result.Error == nil || !strings.Contains(*result.Error, tt.wantErrSubst) {
				t.Errorf("Error = %v, want it to contain %q", result.Error, tt.wantErrSubst)
			}
		})
	}
}

// TestCheckHeloSPFRecordDoesNotAffectScore pins the informational nature of the
// check: whatever it finds, it must not move the DNS SPF score.
func TestCheckHeloSPFRecordDoesNotAffectScore(t *testing.T) {
	analyzer := newMockAnalyzer(nil, nil)

	results := &model.DNSResults{
		FromDomain: "example.com",
		SpfRecords: &[]model.SPFRecord{
			{
				Domain:       utils.PtrTo("example.com"),
				Record:       utils.PtrTo("v=spf1 ip4:192.0.2.10 -all"),
				Valid:        true,
				AllQualifier: utils.PtrTo(model.SPFRecordAllQualifier("-")),
			},
		},
	}

	want := analyzer.calculateSPFScore(results)

	for _, heloRecord := range []*model.SPFRecord{
		{Domain: utils.PtrTo("mail.example.com"), Error: utils.PtrTo("No SPF record found")},
		{Domain: utils.PtrTo("mail.example.com"), Valid: true, Record: utils.PtrTo("v=spf1 -all")},
	} {
		results.HeloSpfRecord = heloRecord

		if got := analyzer.calculateSPFScore(results); got != want {
			t.Errorf("calculateSPFScore() = %d with a HELO record, want %d", got, want)
		}
	}
}

// TestHeloLookupName pins which announcements are worth a DNS lookup: the name
// comes verbatim from the Received header, so it is not always a hostname.
func TestHeloLookupName(t *testing.T) {
	tests := []struct {
		name string
		helo string
		want string
	}{
		{
			name: "hostname",
			helo: "mail.example.com",
			want: "mail.example.com",
		},
		{
			// Announcements are compared and looked up in their canonical form
			name: "hostname is normalized",
			helo: "  Mail.Example.Com.  ",
			want: "mail.example.com",
		},
		{
			// Postfix's placeholder when the reverse lookup fails
			name: "unknown",
			helo: "unknown",
			want: "",
		},
		{
			name: "address literal",
			helo: "[192.0.2.1]",
			want: "",
		},
		{
			name: "IPv6 address literal",
			helo: "[IPv6:2001:db8::1]",
			want: "",
		},
		{
			name: "bare address",
			helo: "192.0.2.1",
			want: "",
		},
		{
			// A single label can never hold a policy of its own
			name: "single label",
			helo: "localhost",
			want: "",
		},
		{
			name: "empty",
			helo: "   ",
			want: "",
		},
		{
			// An empty label makes the name unqueryable
			name: "empty label",
			helo: "mail..example.com",
			want: "",
		},
		{
			name: "dots only",
			helo: "..",
			want: "",
		},
		{
			// Underscores are not allowed in a hostname (RFC 1123 section 2.1)
			name: "underscore",
			helo: "mail_relay.example.com",
			want: "",
		},
		{
			name: "label starting with a hyphen",
			helo: "-mail.example.com",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heloLookupName(tt.helo); got != tt.want {
				t.Errorf("heloLookupName(%q) = %q, want %q", tt.helo, got, tt.want)
			}
		})
	}
}
