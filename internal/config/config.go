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

package config

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"git.happydns.org/happyDeliver/pkg/bimi"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

func getHostname() string {
	h, _ := os.Hostname()
	return h
}

// Config represents the application configuration
type Config struct {
	DevProxy         string
	Bind             string
	Database         DatabaseConfig
	Email            EmailConfig
	Analysis         AnalysisConfig
	ReportRetention  time.Duration // How long to keep reports. 0 = keep forever
	RateLimit        uint          // API rate limit (requests per second per IP)
	SurveyURL        url.URL       // URL for user feedback survey
	CustomLogoURL    string        // URL for custom logo image in the web UI
	DisableTestList  bool          // Disable the public test listing endpoint
	DisableEmlUpload bool          // Disable the EML file upload endpoint
	MaxMessageSize   int64         // Maximum size in bytes of a message, whether received over LMTP or uploaded as EML
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Type string
	DSN  string
}

// EmailConfig contains email domain and routing settings
type EmailConfig struct {
	Domain            string
	TestAddressPrefix string
	LMTPAddr          string
	ReceiverHostname  string
}

// AnalysisConfig contains timeout and behavior settings for email analysis
type AnalysisConfig struct {
	DNSTimeout   time.Duration
	HTTPTimeout  time.Duration
	RBLs         []string
	DNSWLs       []string
	CheckAllIPs  bool   // Check all IPs found in headers, not just the first one
	RspamdAPIURL string // rspamd API URL for fetching symbol descriptions (empty = use embedded list)
	// RspamdScanURL is the rspamd normal worker an uploaded message is
	// submitted to, for want of a filter annotation of our own on it. This is
	// the scanning worker (11333 by default), not the controller
	// RspamdAPIURL names: the controller's own /checkv2 is behind its
	// password, while the normal worker is what an MTA talks to. Empty, the
	// default, leaves uploaded messages unscanned.
	RspamdScanURL string
	// VMCRootsFile names the PEM file of BIMI root certificates a Verified
	// Mark Certificate chain must lead back to. Empty uses the bundle
	// embedded in the binary, bimi.DisableVMCRoots skips the check.
	VMCRootsFile string
	// VMCRoots is the pool built from VMCRootsFile by Validate. It is not
	// configurable directly: the file is read once at startup so a broken
	// trust policy is reported there rather than on every analysis.
	VMCRoots  *x509.CertPool `json:"-"`
	Blacklist BlacklistConfig
}

const (
	// DefaultBlacklistCollectTimeout is the ceiling for one full
	// checker-blacklist aggregation. It matches what the module gives itself,
	// its shared HTTP client and OISD's per-feed budget both being 60s, and a
	// shorter parent silently overrides those rather than adding to them.
	//
	// Each source carries its own deadline, so this ceiling only really binds
	// while a feed cache is cold. That happens on any instance, the warmup
	// being off by default, so the ceiling has to cover it rather than count
	// on the caches being filled ahead of time.
	DefaultBlacklistCollectTimeout = 60 * time.Second

	// DefaultBlacklistWarmupInterval matches the TTL of the two feeds worth
	// warming on a schedule: OISD, which the module sizes for 262144 entries,
	// and Disconnect. The shorter-lived feeds upstream (OpenPhish 1h, Botvrij
	// 6h, PhishTank 12h) do expire between two warmups and are reloaded by
	// whichever check finds them stale, which is the cheaper trade: they are
	// one to two orders of magnitude smaller.
	//
	// Repeating oftener is an explicit choice, not a default: these are other
	// people's feeds.
	DefaultBlacklistWarmupInterval = 24 * time.Hour
)

// BlacklistConfig holds per-source credentials/options for the
// domain-oriented checker-blacklist provider, plus the host-side budgets
// happyDeliver applies around it. Credential keys must match the option IDs
// declared by each source in the checker-blacklist module (see
// checker/virustotal.go, checker/safebrowsing.go, …) — AsCheckerOptions is
// where that mapping lives, and where it is tested. Free sources (Quad9, OISD,
// URLhaus, OpenPhish, Disconnect, Botvrij, …) need no configuration. The
// duration fields below are ours and are not forwarded to the checker.
type BlacklistConfig struct {
	VirusTotalAPIKey   string
	SafeBrowsingAPIKey string
	// CollectTimeout bounds the whole checker-blacklist aggregation, not a
	// single outbound call the way Analysis.HTTPTimeout does: Collect fans out
	// every source concurrently, and the feed-backed ones (OISD, Disconnect,
	// Botvrij, OpenPhish, PhishTank) download their full list when their cache
	// is cold. Too short and they all error out, which leaves the verdict
	// inconclusive. 0 falls back to the default.
	CollectTimeout time.Duration
	// Warmup fills the feed caches in background rather than leaving them to
	// the first check that needs them. Off by default: it downloads several
	// feeds on every start, which is an operator's call to make, not a thing
	// to discover. Left off, a check simply reloads a stale feed itself,
	// which CollectTimeout is sized for.
	Warmup bool
	// WarmupInterval is how often the warmup repeats once enabled. 0 runs it
	// at startup only.
	WarmupInterval time.Duration
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DevProxy:        "",
		Bind:            ":8080",
		ReportRetention: 0,        // Keep reports forever by default
		RateLimit:       1,        // is in fact 2 requests per 2 seconds per IP (default)
		MaxMessageSize:  50 << 20, // 50 MiB, matching the largest message Gmail accepts
		Database: DatabaseConfig{
			Type: "sqlite",
			DSN:  "happydeliver.db",
		},
		Email: EmailConfig{
			Domain:            "happydeliver.local",
			TestAddressPrefix: "test-",
			LMTPAddr:          "127.0.0.1:2525",
			ReceiverHostname:  getHostname(),
		},
		Analysis: AnalysisConfig{
			DNSTimeout:  5 * time.Second,
			HTTPTimeout: 10 * time.Second,
			RBLs:        []string{},
			DNSWLs:      []string{},
			CheckAllIPs: false, // By default, only check the first IP
			Blacklist: BlacklistConfig{
				CollectTimeout: DefaultBlacklistCollectTimeout,
				Warmup:         false, // Opt-in: warming downloads other people's feeds
				WarmupInterval: DefaultBlacklistWarmupInterval,
			},
		},
	}
}

// ConsolidateConfig fills an Options struct by reading configuration from
// config files, environment, then command line.
//
// Should be called only one time.
func ConsolidateConfig() (opts *Config, err error) {
	// Define defaults options
	opts = DefaultConfig()

	declareFlags(opts)

	// Establish a list of possible configuration file locations
	configLocations := []string{
		"happydeliver.conf",
	}

	if home, err := os.UserConfigDir(); err == nil {
		configLocations = append(
			configLocations,
			path.Join(home, "happydeliver", "happydeliver.conf"),
			path.Join(home, "happydomain", "happydeliver.conf"),
		)
	}

	configLocations = append(configLocations, path.Join("etc", "happydeliver.conf"))

	// If config file exists, read configuration from it
	for _, filename := range configLocations {
		if _, e := os.Stat(filename); !os.IsNotExist(e) && !os.IsPermission(e) {
			log.Printf("Loading configuration from %s\n", filename)
			err = parseFile(opts, filename)
			if err != nil {
				return
			}
			break
		}
	}

	// Then, overwrite that by what is present in the environment
	err = parseEnvironmentVariables(opts)
	if err != nil {
		return
	}

	// Finaly, command line takes precedence
	err = parseCLI(opts)
	if err != nil {
		return
	}

	return
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Email.Domain == "" {
		return fmt.Errorf("email domain cannot be empty")
	}

	if _, err := openapi_types.Email(fmt.Sprintf("%s1234-5678-9090@%s", c.Email.TestAddressPrefix, c.Email.Domain)).MarshalJSON(); err != nil {
		return fmt.Errorf("invalid email domain: %w", err)
	}

	roots, err := bimi.LoadVMCRoots(c.Analysis.VMCRootsFile)
	if err != nil {
		return fmt.Errorf("invalid BIMI root certificates: %w", err)
	}
	c.Analysis.VMCRoots = roots

	if c.Database.Type != "sqlite" && c.Database.Type != "postgres" {
		return fmt.Errorf("unsupported database type: %s", c.Database.Type)
	}

	if c.Database.DSN == "" {
		return fmt.Errorf("database DSN cannot be empty")
	}

	return nil
}

// parseLine treats a config line and place the read value in the variable
// declared to the corresponding flag.
func parseLine(o *Config, line string) (err error) {
	fields := strings.SplitN(line, "=", 2)
	orig_key := strings.TrimSpace(fields[0])
	value := strings.TrimSpace(fields[1])

	if len(value) == 0 {
		return
	}

	key := strings.TrimPrefix(strings.TrimPrefix(orig_key, "HAPPYDELIVER_"), "HAPPYDOMAIN_")
	key = strings.Replace(key, "_", "-", -1)
	key = strings.ToLower(key)

	err = flag.Set(key, value)

	return
}
