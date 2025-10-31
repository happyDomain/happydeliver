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
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/api"
	"git.happydns.org/happyDeliver/internal/config"
)

// EmailAnalyzer provides high-level email analysis functionality
// This is the main entry point for analyzing emails from both LMTP and CLI
type EmailAnalyzer struct {
	generator *ReportGenerator
}

// NewEmailAnalyzer creates a new email analyzer with the given configuration
func NewEmailAnalyzer(cfg *config.Config) *EmailAnalyzer {
	generator := NewReportGenerator(
		cfg.Analysis.DNSTimeout,
		cfg.Analysis.HTTPTimeout,
		cfg.Analysis.RBLs,
		cfg.Analysis.CheckAllIPs,
	)

	return &EmailAnalyzer{
		generator: generator,
	}
}

// AnalysisResult contains the complete analysis result
type AnalysisResult struct {
	Email   *EmailMessage
	Results *AnalysisResults
	Report  *api.Report
}

// AnalyzeEmailBytes performs complete email analysis from raw bytes
func (a *EmailAnalyzer) AnalyzeEmailBytes(rawEmail []byte, testID uuid.UUID) (*AnalysisResult, error) {
	// Parse the email
	emailMsg, err := ParseEmail(bytes.NewReader(rawEmail))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// Analyze the email
	results := a.generator.AnalyzeEmail(emailMsg)

	// Generate the report
	report := a.generator.GenerateReport(testID, results)

	return &AnalysisResult{
		Email:   emailMsg,
		Results: results,
		Report:  report,
	}, nil
}

// APIAdapter adapts the EmailAnalyzer to work with the API package
// This adapter implements the interface expected by the API handler
type APIAdapter struct {
	analyzer *EmailAnalyzer
}

// NewAPIAdapter creates a new API adapter for the email analyzer
func NewAPIAdapter(cfg *config.Config) *APIAdapter {
	return &APIAdapter{
		analyzer: NewEmailAnalyzer(cfg),
	}
}

// AnalyzeEmailBytes performs analysis and returns JSON bytes directly
func (a *APIAdapter) AnalyzeEmailBytes(rawEmail []byte, testID uuid.UUID) ([]byte, error) {
	result, err := a.analyzer.AnalyzeEmailBytes(rawEmail, testID)
	if err != nil {
		return nil, err
	}

	// Marshal report to JSON
	reportJSON, err := json.Marshal(result.Report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	return reportJSON, nil
}

// AnalyzeDomain performs DNS analysis for a domain and returns the results
func (a *APIAdapter) AnalyzeDomain(domain string) (*api.DNSResults, int, string) {
	// Perform DNS analysis
	dnsResults := a.analyzer.generator.dnsAnalyzer.AnalyzeDomainOnly(domain)

	// Calculate score
	score, grade := a.analyzer.generator.dnsAnalyzer.CalculateDomainOnlyScore(dnsResults)

	return dnsResults, score, grade
}

// CheckBlacklistIP checks a single IP address against DNS blacklists
func (a *APIAdapter) CheckBlacklistIP(ip string) ([]api.BlacklistCheck, int, int, string, error) {
	// Check the IP against all configured RBLs
	checks, listedCount, err := a.analyzer.generator.rblChecker.CheckIP(ip)
	if err != nil {
		return nil, 0, 0, "", err
	}

	// Calculate score using the existing function
	// Create a minimal RBLResults structure for scoring
	results := &RBLResults{
		Checks:      map[string][]api.BlacklistCheck{ip: checks},
		IPsChecked:  []string{ip},
		ListedCount: listedCount,
	}
	score, grade := a.analyzer.generator.rblChecker.CalculateRBLScore(results)

	return checks, listedCount, score, grade, nil
}
