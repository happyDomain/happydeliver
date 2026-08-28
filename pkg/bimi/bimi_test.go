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
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubResolver returns canned TXT records (or an error) for LookupTXT.
type stubResolver struct {
	txt []string
	err error
}

func (r stubResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.txt, r.err
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.HTTPClient == nil {
		t.Error("HTTPClient should be set")
	} else if v.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("HTTPClient.Timeout = %s, want 30s", v.HTTPClient.Timeout)
	}
	if v.Resolver == nil {
		t.Error("Resolver should be set")
	}
}

func TestValidatorDefaults(t *testing.T) {
	// With no HTTPClient set, httpClient() falls back to http.DefaultClient.
	v := &Validator{}
	if v.httpClient() != http.DefaultClient {
		t.Error("httpClient() should default to http.DefaultClient")
	}
	// With no Now set, now() falls back to time.Now (a recent timestamp).
	before := time.Now().Add(-time.Minute)
	if got := v.now(); got.Before(before) {
		t.Errorf("now() = %s, expected a recent time", got)
	}
}

func TestDescribeMisplacedRecord(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		ownFamily string
		want      string
	}{
		{"DMARC misplaced at BIMI", "DMARC1", "BIMI", "a DMARC record"},
		{"SPF misplaced at BIMI", "spf1", "BIMI", "an SPF record"},
		{"DKIM misplaced at BIMI", "DKIM1", "BIMI", "a DKIM record"},
		{"BIMI at BIMI location is own family", "BIMI1", "BIMI", ""},
		{"BIMI misplaced elsewhere", "BIMI1", "DKIM", "a BIMI record"},
		{"Unknown version", "STSv1", "BIMI", ""},
		{"Empty version", "", "BIMI", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeMisplacedRecord(tt.version, tt.ownFamily); got != tt.want {
				t.Errorf("describeMisplacedRecord(%q, %q) = %q, want %q", tt.version, tt.ownFamily, got, tt.want)
			}
		})
	}
}

func TestLookupNilResolver(t *testing.T) {
	v := &Validator{}
	_, err := v.Lookup(context.Background(), "example.com", "default")
	if err == nil || !strings.Contains(err.Error(), "Resolver is nil") {
		t.Errorf("err = %v, want a nil-resolver error", err)
	}
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		name        string
		txt         string
		wantValid   bool
		wantLogoURL string
		wantVMCURL  string
	}{
		{
			name:        "Valid record with logo and VMC",
			txt:         "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			wantValid:   true,
			wantLogoURL: "https://example.com/logo.svg",
			wantVMCURL:  "https://example.com/vmc.pem",
		},
		{
			name:        "Declination record (empty l=)",
			txt:         "v=BIMI1; l=;",
			wantValid:   true,
			wantLogoURL: "",
		},
		{
			name:        "Missing version",
			txt:         "l=https://example.com/logo.svg",
			wantValid:   false,
			wantLogoURL: "https://example.com/logo.svg",
		},
		{
			name:      "Missing l= tag",
			txt:       "v=BIMI1;",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := ParseRecord("example.com", "default", tt.txt)
			if rec.Valid != tt.wantValid {
				t.Errorf("Valid = %t, want %t (error: %q)", rec.Valid, tt.wantValid, rec.Error)
			}
			if rec.LogoURL != tt.wantLogoURL {
				t.Errorf("LogoURL = %q, want %q", rec.LogoURL, tt.wantLogoURL)
			}
			if rec.VMCURL != tt.wantVMCURL {
				t.Errorf("VMCURL = %q, want %q", rec.VMCURL, tt.wantVMCURL)
			}
		})
	}
}

func TestParseRecordForeignRecordHint(t *testing.T) {
	// A DMARC record mistakenly published at the BIMI location must be
	// reported as "no BIMI record found" with a hint, not as a malformed
	// BIMI record.
	rec := ParseRecord("example.com", "default", "v=DMARC1;p=quarantine;rua=mailto:dmarc@example.com")
	if rec.Valid {
		t.Fatalf("Valid = true, want false")
	}
	if rec.VMCURL != "" {
		t.Errorf("VMCURL = %q, want empty (must not match DMARC's rua= as a= tag)", rec.VMCURL)
	}
	if !strings.Contains(rec.Error, "No BIMI record found") || !strings.Contains(rec.Error, "a DMARC record") {
		t.Errorf("Error = %q, want to mention the misplaced DMARC record", rec.Error)
	}
}

func TestLookup(t *testing.T) {
	t.Run("No record", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: nil}}
		_, err := v.Lookup(context.Background(), "example.com", "default")
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})

	t.Run("Resolver failure", func(t *testing.T) {
		boom := errors.New("boom")
		v := &Validator{Resolver: stubResolver{err: boom}}
		_, err := v.Lookup(context.Background(), "example.com", "default")
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	})

	t.Run("Concatenates split TXT parts", func(t *testing.T) {
		v := &Validator{Resolver: stubResolver{txt: []string{"v=BIMI1; l=", "https://example.com/logo.svg"}}}
		rec, err := v.Lookup(context.Background(), "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.LogoURL != "https://example.com/logo.svg" {
			t.Errorf("LogoURL = %q", rec.LogoURL)
		}
	})
}

// TestNewHTTPClientRefusesNonPublicAddress checks the guard the whole package
// relies on: the fetched URLs come from the analysed domain's DNS, so a client
// built by NewHTTPClient must not reach an internal service, whatever name
// resolves to it.
func TestNewHTTPClientRefusesNonPublicAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	v := &Validator{HTTPClient: NewHTTPClient(0)}
	_, _, problems := v.fetchFile(context.Background(), server.URL, MaxLogoSize)

	if len(problems) == 0 || !strings.Contains(problems[0], "non-public address") {
		t.Errorf("expected the loopback server to be refused, got %v", problems)
	}
}

func TestRejectInsecureRedirect(t *testing.T) {
	secure, _ := http.NewRequest(http.MethodGet, "https://example.com/logo.svg", nil)
	if err := rejectInsecureRedirect(secure, nil); err != nil {
		t.Errorf("an HTTPS redirect must be followed, got %v", err)
	}

	insecure, _ := http.NewRequest(http.MethodGet, "http://example.com/logo.svg", nil)
	if err := rejectInsecureRedirect(insecure, nil); err == nil {
		t.Error("a redirect away from HTTPS must be refused")
	}
}

func TestFetchFileInvalidURL(t *testing.T) {
	v := &Validator{}
	// A control character in the URL makes url.Parse fail.
	_, _, problems := v.fetchFile(context.Background(), "https://example.com/\x7f", MaxLogoSize)
	if len(problems) == 0 || !strings.Contains(problems[0], "Invalid URL") {
		t.Errorf("expected an invalid-URL problem, got %v", problems)
	}
}

func TestFetchFileRequiresHTTPS(t *testing.T) {
	v := &Validator{}
	_, _, problems := v.fetchFile(context.Background(), "http://example.com/logo.svg", MaxLogoSize)
	if len(problems) == 0 || !strings.Contains(problems[0], "HTTPS") {
		t.Errorf("expected HTTPS requirement problem, got %v", problems)
	}
}

func TestFetchFile(t *testing.T) {
	const logoContent = `<svg xmlns="http://www.w3.org/2000/svg"><title>Example Corp</title></svg>`

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Write([]byte(logoContent))
	})
	mux.HandleFunc("/huge.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(bytes.Repeat([]byte("a"), int(MaxLogoSize)+10))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}

	t.Run("Successful fetch", func(t *testing.T) {
		content, contentType, problems := v.fetchFile(context.Background(), server.URL+"/logo.svg", MaxLogoSize)
		if len(problems) > 0 {
			t.Fatalf("unexpected problems: %v", problems)
		}
		if contentType != "image/svg+xml" {
			t.Errorf("contentType = %q, want image/svg+xml", contentType)
		}
		if string(content) != logoContent {
			t.Errorf("unexpected content")
		}
	})

	t.Run("404 response", func(t *testing.T) {
		_, _, problems := v.fetchFile(context.Background(), server.URL+"/missing.svg", MaxLogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "404") {
			t.Errorf("expected 404 problem, got %v", problems)
		}
	})

	t.Run("Too large", func(t *testing.T) {
		_, _, problems := v.fetchFile(context.Background(), server.URL+"/huge.svg", MaxLogoSize)
		if len(problems) == 0 || !strings.Contains(problems[0], "maximum allowed size") {
			t.Errorf("expected size problem, got %v", problems)
		}
	})
}

func TestValidateAssets(t *testing.T) {
	const logoContent = validTinyPSSVG

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(logoContent))
	})
	mux.HandleFunc("/bad.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	v := &Validator{HTTPClient: server.Client()}
	ctx := context.Background()

	t.Run("Fetchable logo passes", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/logo.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if !rec.Valid {
			t.Errorf("expected checks to pass, got checks: %+v", rec.Checks)
		}
	})

	t.Run("Non-compliant logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/bad.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if rec.Valid {
			t.Errorf("expected checks to fail for non-compliant logo")
		}
	})

	t.Run("Declination record skips checks", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if !rec.Valid {
			t.Errorf("declination record should not fail checks")
		}
		for _, check := range rec.Checks {
			if check.Status != StatusSkipped {
				t.Errorf("check %s = %s, want skipped", check.Name, check.Status)
			}
		}
	})

	t.Run("Unreachable logo fails", func(t *testing.T) {
		rec := &Record{
			Selector: "default",
			Domain:   "example.com",
			LogoURL:  server.URL + "/missing.svg",
			Valid:    true,
		}
		v.ValidateAssets(ctx, rec)
		if rec.Valid {
			t.Errorf("expected checks to fail for unreachable logo")
		}
	})
}

func TestAnalyze(t *testing.T) {
	const logoContent = validTinyPSSVG

	mux := http.NewServeMux()
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write([]byte(logoContent))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()

	t.Run("Valid record runs asset checks", func(t *testing.T) {
		txt := "v=BIMI1; l=" + server.URL + "/logo.svg"
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{txt}}}

		rec, err := v.Analyze(ctx, "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Valid {
			t.Errorf("expected valid record, error: %q, checks: %+v", rec.Error, rec.Checks)
		}
		if len(rec.Checks) == 0 {
			t.Error("expected asset checks to be populated")
		}
	})

	t.Run("Invalid record skips asset checks", func(t *testing.T) {
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: []string{"v=BIMI1;"}}}

		rec, err := v.Analyze(ctx, "example.com", "default")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Valid {
			t.Error("expected invalid record for missing l= tag")
		}
		if rec.Checks != nil {
			t.Errorf("expected no asset checks for a syntactically invalid record, got %+v", rec.Checks)
		}
	})

	t.Run("Propagates lookup error", func(t *testing.T) {
		v := &Validator{HTTPClient: server.Client(), Resolver: stubResolver{txt: nil}}
		_, err := v.Analyze(ctx, "example.com", "default")
		if !errors.Is(err, ErrNoRecord) {
			t.Errorf("err = %v, want ErrNoRecord", err)
		}
	})
}
