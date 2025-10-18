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
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Config represents the application configuration
type Config struct {
	DevProxy string
	Bind     string
	Database DatabaseConfig
	Email    EmailConfig
	Analysis AnalysisConfig
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
}

// AnalysisConfig contains timeout and behavior settings for email analysis
type AnalysisConfig struct {
	DNSTimeout  time.Duration
	HTTPTimeout time.Duration
	RBLs        []string
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DevProxy: "",
		Bind:     ":8081",
		Database: DatabaseConfig{
			Type: "sqlite",
			DSN:  "happydeliver.db",
		},
		Email: EmailConfig{
			Domain:            "happydeliver.local",
			TestAddressPrefix: "test-",
			LMTPAddr:          "127.0.0.1:2525",
		},
		Analysis: AnalysisConfig{
			DNSTimeout:  5 * time.Second,
			HTTPTimeout: 10 * time.Second,
			RBLs:        []string{},
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
		if _, e := os.Stat(filename); !os.IsNotExist(e) {
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
