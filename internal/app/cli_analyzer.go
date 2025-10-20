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

package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/api"
	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/pkg/analyzer"
)

// RunAnalyzer runs the standalone email analyzer (from stdin)
func RunAnalyzer(cfg *config.Config, args []string, reader io.Reader, writer io.Writer) error {
	// Parse command-line flags
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output results as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	log.Printf("Email analyzer ready, reading from stdin...")

	// Read email from stdin
	emailData, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read email from stdin: %w", err)
	}

	// Create analyzer with configuration
	emailAnalyzer := analyzer.NewEmailAnalyzer(cfg)

	// Analyze the email (using a dummy test ID for standalone mode)
	result, err := emailAnalyzer.AnalyzeEmailBytes(emailData, uuid.New())
	if err != nil {
		return fmt.Errorf("failed to analyze email: %w", err)
	}

	log.Printf("Analyzing email from: %s", result.Email.From)

	// Output results
	if *jsonOutput {
		return outputJSON(result, writer)
	}
	return outputHumanReadable(result, emailAnalyzer, writer)
}

// outputJSON outputs the report as JSON
func outputJSON(result *analyzer.AnalysisResult, writer io.Writer) error {
	reportJSON, err := json.MarshalIndent(result.Report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	fmt.Fprintln(writer, string(reportJSON))
	return nil
}

// outputHumanReadable outputs a human-readable summary
func outputHumanReadable(result *analyzer.AnalysisResult, emailAnalyzer *analyzer.EmailAnalyzer, writer io.Writer) error {
	// Header
	fmt.Fprintln(writer, "\n"+strings.Repeat("=", 70))
	fmt.Fprintln(writer, "EMAIL DELIVERABILITY ANALYSIS REPORT")
	fmt.Fprintln(writer, strings.Repeat("=", 70))

	// Score summary
	summary := emailAnalyzer.GetScoreSummaryText(result)
	fmt.Fprintln(writer, summary)

	// Detailed checks
	fmt.Fprintln(writer, "\n"+strings.Repeat("-", 70))
	fmt.Fprintln(writer, "DETAILED CHECK RESULTS")
	fmt.Fprintln(writer, strings.Repeat("-", 70))

	// Group checks by category
	categories := make(map[api.CheckCategory][]api.Check)
	for _, check := range result.Report.Checks {
		categories[check.Category] = append(categories[check.Category], check)
	}

	// Print checks by category
	categoryOrder := []api.CheckCategory{
		api.Authentication,
		api.Dns,
		api.Blacklist,
		api.Content,
		api.Headers,
	}

	for _, category := range categoryOrder {
		checks, ok := categories[category]
		if !ok || len(checks) == 0 {
			continue
		}

		fmt.Fprintf(writer, "\n%s:\n", category)
		for _, check := range checks {
			statusSymbol := "✓"
			if check.Status == api.CheckStatusFail {
				statusSymbol = "✗"
			} else if check.Status == api.CheckStatusWarn {
				statusSymbol = "⚠"
			}

			fmt.Fprintf(writer, "  %s %s: %s\n", statusSymbol, check.Name, check.Message)
			if check.Advice != nil && *check.Advice != "" {
				fmt.Fprintf(writer, "    → %s\n", *check.Advice)
			}
		}
	}

	fmt.Fprintln(writer, "\n"+strings.Repeat("=", 70))
	return nil
}
