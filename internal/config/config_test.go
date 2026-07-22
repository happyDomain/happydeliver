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

package config

import (
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetFlags installs a fresh global flag.CommandLine bound to o, restoring the
// previous one when the test finishes. Both parseLine and declareFlags operate
// on the process-wide flag.CommandLine, so tests that touch flags must isolate
// that global state.
func resetFlags(t *testing.T, o *Config) {
	t.Helper()
	old := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	declareFlags(o)
	t.Cleanup(func() {
		flag.CommandLine = old
	})
}

func TestGetHostname(t *testing.T) {
	// getHostname mirrors os.Hostname(); it should not return an error-driven
	// empty string on a normal machine, but at minimum must match os.Hostname.
	want, _ := os.Hostname()
	if got := getHostname(); got != want {
		t.Errorf("getHostname() = %q, want %q", got, want)
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()

	if c.Bind != ":8080" {
		t.Errorf("Bind = %q, want %q", c.Bind, ":8080")
	}
	if c.ReportRetention != 0 {
		t.Errorf("ReportRetention = %v, want 0", c.ReportRetention)
	}
	if c.RateLimit != 1 {
		t.Errorf("RateLimit = %d, want 1", c.RateLimit)
	}
	if c.Database.Type != "sqlite" {
		t.Errorf("Database.Type = %q, want sqlite", c.Database.Type)
	}
	if c.Database.DSN != "happydeliver.db" {
		t.Errorf("Database.DSN = %q, want happydeliver.db", c.Database.DSN)
	}
	if c.Email.Domain != "happydeliver.local" {
		t.Errorf("Email.Domain = %q, want happydeliver.local", c.Email.Domain)
	}
	if c.Email.TestAddressPrefix != "test-" {
		t.Errorf("Email.TestAddressPrefix = %q, want test-", c.Email.TestAddressPrefix)
	}
	if c.Email.LMTPAddr != "127.0.0.1:2525" {
		t.Errorf("Email.LMTPAddr = %q, want 127.0.0.1:2525", c.Email.LMTPAddr)
	}
	if c.Email.ReceiverHostname != getHostname() {
		t.Errorf("Email.ReceiverHostname = %q, want %q", c.Email.ReceiverHostname, getHostname())
	}
	if c.Analysis.DNSTimeout != 5*time.Second {
		t.Errorf("Analysis.DNSTimeout = %v, want 5s", c.Analysis.DNSTimeout)
	}
	if c.Analysis.HTTPTimeout != 10*time.Second {
		t.Errorf("Analysis.HTTPTimeout = %v, want 10s", c.Analysis.HTTPTimeout)
	}
	if c.Analysis.RBLs == nil || len(c.Analysis.RBLs) != 0 {
		t.Errorf("Analysis.RBLs = %v, want empty non-nil slice", c.Analysis.RBLs)
	}
	if c.Analysis.DNSWLs == nil || len(c.Analysis.DNSWLs) != 0 {
		t.Errorf("Analysis.DNSWLs = %v, want empty non-nil slice", c.Analysis.DNSWLs)
	}
	if c.Analysis.CheckAllIPs {
		t.Error("Analysis.CheckAllIPs = true, want false")
	}
}

func TestValidate(t *testing.T) {
	valid := func() *Config {
		return &Config{
			Email:    EmailConfig{Domain: "example.com", TestAddressPrefix: "test-"},
			Database: DatabaseConfig{Type: "sqlite", DSN: "happydeliver.db"},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid sqlite", func(*Config) {}, false},
		{"valid postgres", func(c *Config) { c.Database.Type = "postgres" }, false},
		{"empty domain", func(c *Config) { c.Email.Domain = "" }, true},
		{"invalid domain", func(c *Config) { c.Email.Domain = "not a valid domain" }, true},
		{"unsupported db type", func(c *Config) { c.Database.Type = "mysql" }, true},
		{"empty dsn", func(c *Config) { c.Database.DSN = "" }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseLine(t *testing.T) {
	t.Run("sets flag value", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseLine(c, "bind = :9090"); err != nil {
			t.Fatalf("parseLine() error = %v", err)
		}
		if c.Bind != ":9090" {
			t.Errorf("Bind = %q, want :9090", c.Bind)
		}
	})

	t.Run("strips HAPPYDELIVER_ prefix and normalizes key", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseLine(c, "HAPPYDELIVER_DATABASE_TYPE = postgres"); err != nil {
			t.Fatalf("parseLine() error = %v", err)
		}
		if c.Database.Type != "postgres" {
			t.Errorf("Database.Type = %q, want postgres", c.Database.Type)
		}
	})

	t.Run("strips HAPPYDOMAIN_ prefix", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseLine(c, "HAPPYDOMAIN_DOMAIN = example.org"); err != nil {
			t.Fatalf("parseLine() error = %v", err)
		}
		if c.Email.Domain != "example.org" {
			t.Errorf("Email.Domain = %q, want example.org", c.Email.Domain)
		}
	})

	t.Run("empty value is ignored", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseLine(c, "bind ="); err != nil {
			t.Fatalf("parseLine() error = %v", err)
		}
		if c.Bind != ":8080" {
			t.Errorf("Bind = %q, want unchanged :8080", c.Bind)
		}
	})

	t.Run("unknown flag returns error", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseLine(c, "does-not-exist = value"); err == nil {
			t.Error("parseLine() error = nil, want error for unknown flag")
		}
	})
}

func TestParseFile(t *testing.T) {
	t.Run("parses valid file", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		dir := t.TempDir()
		fname := filepath.Join(dir, "happydeliver.conf")
		content := "# a comment\n" +
			"\n" +
			"bind = :7070\n" +
			"database-type = postgres\n" +
			"# another comment = ignored\n"
		if err := os.WriteFile(fname, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := parseFile(c, fname); err != nil {
			t.Fatalf("parseFile() error = %v", err)
		}
		if c.Bind != ":7070" {
			t.Errorf("Bind = %q, want :7070", c.Bind)
		}
		if c.Database.Type != "postgres" {
			t.Errorf("Database.Type = %q, want postgres", c.Database.Type)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		if err := parseFile(c, filepath.Join(t.TempDir(), "nope.conf")); err == nil {
			t.Error("parseFile() error = nil, want error for missing file")
		}
	})

	t.Run("invalid line returns error", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		dir := t.TempDir()
		fname := filepath.Join(dir, "bad.conf")
		if err := os.WriteFile(fname, []byte("unknown-key = value\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := parseFile(c, fname); err == nil {
			t.Error("parseFile() error = nil, want error for invalid line")
		}
	})
}

func TestParseEnvironmentVariables(t *testing.T) {
	t.Run("applies prefixed variables", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		t.Setenv("HAPPYDELIVER_BIND", ":6060")
		t.Setenv("HAPPYDOMAIN_DOMAIN", "env.example.com")

		if err := parseEnvironmentVariables(c); err != nil {
			t.Fatalf("parseEnvironmentVariables() error = %v", err)
		}
		if c.Bind != ":6060" {
			t.Errorf("Bind = %q, want :6060", c.Bind)
		}
		if c.Email.Domain != "env.example.com" {
			t.Errorf("Email.Domain = %q, want env.example.com", c.Email.Domain)
		}
	})

	t.Run("ignores unrelated variables", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		t.Setenv("SOME_OTHER_VAR", "whatever")

		if err := parseEnvironmentVariables(c); err != nil {
			t.Fatalf("parseEnvironmentVariables() error = %v", err)
		}
		if c.Bind != ":8080" {
			t.Errorf("Bind = %q, want unchanged :8080", c.Bind)
		}
	})

	t.Run("invalid prefixed variable returns error", func(t *testing.T) {
		c := DefaultConfig()
		resetFlags(t, c)

		t.Setenv("HAPPYDELIVER_UNKNOWN_KEY", "value")

		if err := parseEnvironmentVariables(c); err == nil {
			t.Error("parseEnvironmentVariables() error = nil, want error")
		}
	})
}

func TestConsolidateConfig(t *testing.T) {
	// ConsolidateConfig calls declareFlags and parseCLI itself, so give it a
	// pristine global flag set and args, then restore them afterwards.
	oldFlags := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	oldArgs := os.Args
	os.Args = []string{"happydeliver", "-bind", ":4040"}
	t.Cleanup(func() {
		flag.CommandLine = oldFlags
		os.Args = oldArgs
	})

	// Run from an empty directory so no on-disk config file is picked up.
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	t.Setenv("HAPPYDELIVER_DATABASE_TYPE", "postgres")

	opts, err := ConsolidateConfig()
	if err != nil {
		t.Fatalf("ConsolidateConfig() error = %v", err)
	}
	// CLI override
	if opts.Bind != ":4040" {
		t.Errorf("Bind = %q, want :4040", opts.Bind)
	}
	// environment override
	if opts.Database.Type != "postgres" {
		t.Errorf("Database.Type = %q, want postgres", opts.Database.Type)
	}
	// untouched default
	if opts.Email.Domain != "happydeliver.local" {
		t.Errorf("Email.Domain = %q, want default happydeliver.local", opts.Email.Domain)
	}
}

func TestParseCLI(t *testing.T) {
	c := DefaultConfig()
	resetFlags(t, c)

	oldArgs := os.Args
	os.Args = []string{"happydeliver", "-bind", ":5050", "-database-type", "postgres"}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := parseCLI(c); err != nil {
		t.Fatalf("parseCLI() error = %v", err)
	}
	if c.Bind != ":5050" {
		t.Errorf("Bind = %q, want :5050", c.Bind)
	}
	if c.Database.Type != "postgres" {
		t.Errorf("Database.Type = %q, want postgres", c.Database.Type)
	}
}

func TestStringArray(t *testing.T) {
	t.Run("String with nil array", func(t *testing.T) {
		s := StringArray{}
		if got := s.String(); got != "" {
			t.Errorf("String() = %q, want empty", got)
		}
	})

	t.Run("Set appends comma-separated values", func(t *testing.T) {
		var arr []string
		s := StringArray{Array: &arr}

		if err := s.Set("a,b"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if err := s.Set("c"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		want := []string{"a", "b", "c"}
		if len(arr) != len(want) {
			t.Fatalf("array = %v, want %v", arr, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Errorf("array[%d] = %q, want %q", i, arr[i], want[i])
			}
		}
		if got := s.String(); got != "[a b c]" {
			t.Errorf("String() = %q, want [a b c]", got)
		}
	})
}

func TestURL(t *testing.T) {
	t.Run("String with nil URL", func(t *testing.T) {
		u := URL{}
		if got := u.String(); got != "" {
			t.Errorf("String() = %q, want empty", got)
		}
	})

	t.Run("Set parses valid URL", func(t *testing.T) {
		var target url.URL
		u := URL{URL: &target}

		if err := u.Set("https://example.com/survey"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if target.Host != "example.com" || target.Scheme != "https" {
			t.Errorf("parsed URL = %+v, want https://example.com", target)
		}
		if got := u.String(); got != "https://example.com/survey" {
			t.Errorf("String() = %q, want https://example.com/survey", got)
		}
	})

	t.Run("Set rejects invalid URL", func(t *testing.T) {
		var target url.URL
		u := URL{URL: &target}

		if err := u.Set("://bad url with space"); err == nil {
			t.Error("Set() error = nil, want error for invalid URL")
		}
	})
}
