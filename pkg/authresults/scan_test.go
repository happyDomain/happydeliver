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

package authresults

import (
	"testing"
)

// TestParseFieldsAsReceiversWriteThem covers the shapes the RFC does not print
// but that arrive all day: properties written without their ptype, values that
// carry their own padding, comments holding a semicolon, and methods nobody can
// read sitting between two that anybody can.
func TestParseFieldsAsReceiversWriteThem(t *testing.T) {
	for _, tt := range []struct {
		name  string
		field string
		check func(*testing.T, Header)
	}{
		{
			name:  "a property written without its ptype",
			field: "mx.example.com; dkim=pass d=example.com s=selector1",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.d", "d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com", got)
				}
				if got := method.Property("header.s", "s"); got != "selector1" {
					t.Errorf("selector is %q, want selector1", got)
				}
			},
		},
		{
			name:  "a ptype named in capitals",
			field: "mx.example.com; dkim=PASS HEADER.D=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if method.Result != "pass" {
					t.Errorf("result is %q, want pass", method.Result)
				}
				if got := method.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com", got)
				}
			},
		},
		{
			name:  "an envelope sender whose local part carries a space",
			field: `mx.example.com; spf=pass smtp.mailfrom="john doe@example.com"`,
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("spf")
				if got := method.Property("smtp.mailfrom"); got != "john doe@example.com" {
					t.Errorf("envelope sender is %q, want john doe@example.com", got)
				}
			},
		},
		{
			name:  "a value carrying its own padding",
			field: "mx.example.com; dkim=pass header.b=Zm9vYmFy== header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.b"); got != "Zm9vYmFy==" {
					t.Errorf("signature is %q, want Zm9vYmFy==", got)
				}
				if got := method.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com", got)
				}
			},
		},
		{
			name:  "a value whose padding is a slash",
			field: "mx.example.com; dkim=pass header.d=example.com header.b=Xy9z1Ab/ header.s=sel",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.b"); got != "Xy9z1Ab/" {
					t.Errorf("signature is %q, want Xy9z1Ab/", got)
				}
				if got := method.Property("header.s"); got != "sel" {
					t.Errorf("selector is %q, want sel: the value ending in a slash swallowed the property after it", got)
				}
			},
		},
		{
			name:  "a domain written down to its root",
			field: "mx.example.com; dkim=pass header.d=example.com. header.s=sel",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.d"); got != "example.com." {
					t.Errorf("domain is %q, want example.com.", got)
				}
				if got := method.Property("header.s"); got != "sel" {
					t.Errorf("selector is %q, want sel: the domain ending in a dot swallowed the property after it", got)
				}
			},
		},
		{
			name:  "a value that is a URL",
			field: "mx.example.com; bimi=pass header.d=example.com policy.authority-uri=https://bimi.example.com/vmc/ header.selector=default",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("bimi")
				if got := method.Property("policy.authority-uri"); got != "https://bimi.example.com/vmc/" {
					t.Errorf("authority is %q, want https://bimi.example.com/vmc/", got)
				}
				if got := method.Property("header.selector"); got != "default" {
					t.Errorf("selector is %q, want default: the URL swallowed the property after it", got)
				}
			},
		},
		{
			name:  "an empty value written without its quotes",
			field: "mx.example.com; dkim=fail header.b= header.d=example.com header.s=sel",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com: the empty value swallowed the property after it", got)
				}
				if got := method.Property("header.b"); got != "" {
					t.Errorf("signature is %q, want the empty value that was written", got)
				}
			},
		},
		{
			name:  "a quoted string nobody closed before the next method",
			field: `mx.example.com; dkim=fail reason="unterminated; spf=pass smtp.mailfrom=user@example.com; dmarc=pass header.from=example.com`,
			check: func(t *testing.T, h Header) {
				if len(h.Methods) != 3 {
					t.Fatalf("the field reports %d methods, want 3: %+v", len(h.Methods), h.Methods)
				}
				if method, found := h.Find("spf"); !found || method.Result != "pass" {
					t.Errorf("spf is %+v, want the pass written after the unterminated string", method)
				}
				if method, found := h.Find("dmarc"); !found || method.Result != "pass" {
					t.Errorf("dmarc is %+v, want the pass written after the unterminated string", method)
				}
			},
		},
		{
			name:  "an empty value written as a quoted string",
			field: `mx.example.com; spf=pass smtp.mailfrom="" smtp.helo=relay.example.org`,
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("spf")
				if got := method.Property("smtp.mailfrom"); got != "" {
					t.Errorf("envelope sender is %q, want the empty value that was written", got)
				}
				if got := method.Property("smtp.helo"); got != "relay.example.org" {
					t.Errorf("announced hostname is %q, want relay.example.org", got)
				}
			},
		},
		{
			name:  "a comment the receiver forgot to space",
			field: "mx.example.com; dkim=pass(2048-bit key) header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if method.Result != "pass" {
					t.Errorf("result is %q, want pass", method.Result)
				}
				if method.Comment() != "2048-bit key" {
					t.Errorf("comment is %q, want 2048-bit key", method.Comment())
				}
			},
		},
		{
			name:  "a comment holding a semicolon",
			field: "mx.example.com; iprev=pass (looked up; found) smtp.remote-ip=192.0.2.1; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				if len(h.Methods) != 2 {
					t.Fatalf("the field reports %d methods, want 2: %+v", len(h.Methods), h.Methods)
				}
				method, _ := h.Find("iprev")
				if got := method.Property("smtp.remote-ip"); got != "192.0.2.1" {
					t.Errorf("address is %q, want 192.0.2.1", got)
				}
				if method.Comment() != "looked up; found" {
					t.Errorf("comment is %q, want the whole comment", method.Comment())
				}
			},
		},
		{
			name:  "a method nobody can read between two anybody can",
			field: "mx.example.com; spf=pass smtp.mailfrom=a@example.com; garbage; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				if len(h.Methods) != 2 {
					t.Fatalf("the field reports %d methods, want 2: %+v", len(h.Methods), h.Methods)
				}
				if _, found := h.Find("dkim"); !found {
					t.Error("the method written after the unreadable one was lost")
				}
			},
		},
		{
			name:  "an empty method between two written ones",
			field: "mx.example.com; spf=pass smtp.mailfrom=a@example.com;; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				if len(h.Methods) != 2 {
					t.Fatalf("the field reports %d methods, want 2: %+v", len(h.Methods), h.Methods)
				}
			},
		},
		{
			name:  "a comment nobody closed",
			field: "mx.example.com; dkim=pass header.d=example.com; spf=pass (unterminated",
			check: func(t *testing.T, h Header) {
				if _, found := h.Find("dkim"); !found {
					t.Error("the method written before the unterminated comment was lost")
				}
			},
		},
		{
			name:  "the method as it was written",
			field: "mx.example.com; dkim=pass (good signature) header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if want := "dkim=pass (good signature) header.d=example.com"; method.Raw != want {
					t.Errorf("raw is %q, want %q", method.Raw, want)
				}
			},
		},
		{
			name:  "the first reading of a property wins",
			field: "mx.example.com; dkim=pass header.d=first.example.com header.d=second.example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.d"); got != "first.example.com" {
					t.Errorf("domain is %q, want first.example.com", got)
				}
			},
		},
		{
			name:  "a property named under a ptype it was not written with",
			field: "mx.example.com; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("d"); got != "" {
					t.Errorf("a bare name matched a property written with its ptype: %q", got)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header, read := Parse(tt.field)
			if !read {
				t.Fatal("the field was not read as one")
			}

			tt.check(t, header)
		})
	}
}

// TestParseRefusesWhatIsNotAField guards the one answer Parse gives about the
// field as a whole: a value naming no authentication service names nobody, and
// nothing in it is to be reported as a verdict.
func TestParseRefusesWhatIsNotAField(t *testing.T) {
	for _, field := range []string{"", "   ", "(only a comment)", ";"} {
		if _, read := Parse(field); read {
			t.Errorf("%q was read as a field", field)
		}
	}
}

// TestParseMethodReadsOneMethod covers reading a method on its own, which is
// what a caller holding one already does.
func TestParseMethodReadsOneMethod(t *testing.T) {
	method, read := ParseMethod("dkim=pass header.d=example.com header.s=sel")
	if !read {
		t.Fatal("the method was not read")
	}

	if method.Name != "dkim" || method.Result != "pass" {
		t.Errorf("method is %q=%q, want dkim=pass", method.Name, method.Result)
	}
	if got := method.Property("header.s"); got != "sel" {
		t.Errorf("selector is %q, want sel", got)
	}

	if _, read := ParseMethod("garbage"); read {
		t.Error("a method that names no result was read as one")
	}
}

// TestParseFieldsNobodyMeantToWrite covers the shapes that are not a method at
// all, or not quite one: what the package answers for them is what keeps a
// reader from reporting a verdict nobody gave.
func TestParseFieldsNobodyMeantToWrite(t *testing.T) {
	for _, tt := range []struct {
		name  string
		field string
		check func(*testing.T, Header)
	}{
		{
			name:  "a result with no method to report it",
			field: "mx.example.com; =pass header.d=example.com; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				if len(h.Methods) != 1 {
					t.Fatalf("the field reports %d methods, want the one that names itself: %+v", len(h.Methods), h.Methods)
				}
			},
		},
		{
			name:  "a word among the properties that is not one",
			field: "mx.example.com; dkim=pass garbage header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com: a word naming nothing swallowed the property after it", got)
				}
			},
		},
		{
			name:  "a property whose name is missing",
			field: "mx.example.com; dkim=pass header.=example.com header.d=real.example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if len(method.Properties) != 1 {
					t.Fatalf("the method holds %d properties, want the one that names itself: %+v", len(method.Properties), method.Properties)
				}
				if got := method.Property("header.d"); got != "real.example.com" {
					t.Errorf("domain is %q, want real.example.com", got)
				}
			},
		},
		{
			name:  "a method version that is not a number",
			field: "mx.example.com; dkim/one=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, found := h.Find("dkim")
				if !found {
					t.Fatal("the method was lost with the version nobody could read")
				}
				if method.Version != "" {
					t.Errorf("version is %q, want none: what was written is not one", method.Version)
				}
			},
		},
		{
			name:  "a method version nobody wrote after the slash",
			field: "mx.example.com; dkim/=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, found := h.Find("dkim")
				if !found || method.Version != "" {
					t.Errorf("method is %+v, want dkim with no version", method)
				}
			},
		},
		{
			name:  "a method the field never reported",
			field: "mx.example.com; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				if method, found := h.Find("spf"); found {
					t.Errorf("the field reported spf: %+v", method)
				}
			},
		},
		{
			name:  "a method carrying no comment",
			field: "mx.example.com; dkim=pass header.d=example.com",
			check: func(t *testing.T, h Header) {
				method, _ := h.Find("dkim")
				if got := method.Comment(); got != "" {
					t.Errorf("comment is %q, want none", got)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header, read := Parse(tt.field)
			if !read {
				t.Fatal("the field was not read as one")
			}

			tt.check(t, header)
		})
	}
}

// TestScanReadsWhatIsWrittenInsideCommentsAndQuotes covers the two places the
// grammar lets a receiver write anything at all: a comment, which may hold
// parentheses of its own, and a quoted string, which may hold a quote of its
// own. Both are read to their real end, and what follows them is still read.
func TestScanReadsWhatIsWrittenInsideCommentsAndQuotes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		field   string
		comment string
		check   func(*testing.T, Method)
	}{
		{
			name:    "a comment inside a comment",
			field:   "mx.example.com; dkim=pass (outer (inner) tail) header.d=example.com",
			comment: "outer (inner) tail",
			check: func(t *testing.T, m Method) {
				if got := m.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com", got)
				}
			},
		},
		{
			name:    "a parenthesis a comment carries rather than closes",
			field:   `mx.example.com; dkim=pass (a \) b) header.d=example.com`,
			comment: "a ) b",
			check: func(t *testing.T, m Method) {
				if got := m.Property("header.d"); got != "example.com" {
					t.Errorf("domain is %q, want example.com: the comment was closed too early", got)
				}
			},
		},
		{
			name:  "a quote a value carries rather than closes",
			field: `mx.example.com; dkim=pass header.d="ex\"ample.com" header.s=sel`,
			check: func(t *testing.T, m Method) {
				if got := m.Property("header.d"); got != `ex"ample.com` {
					t.Errorf("domain is %q, want the quote it was written with", got)
				}
				if got := m.Property("header.s"); got != "sel" {
					t.Errorf("selector is %q, want sel", got)
				}
			},
		},
		{
			name:  "a quoted string nobody closed",
			field: `mx.example.com; dkim=pass header.d="never closed`,
			check: func(t *testing.T, m Method) {
				if got := m.Property("header.d"); got != "never closed" {
					t.Errorf("domain is %q, want what was written before the field ran out", got)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header, read := Parse(tt.field)
			if !read {
				t.Fatal("the field was not read as one")
			}

			method, found := header.Find("dkim")
			if !found {
				t.Fatal("the method was lost")
			}

			if method.Comment() != tt.comment {
				t.Errorf("comment is %q, want %q", method.Comment(), tt.comment)
			}

			tt.check(t, method)
		})
	}
}
