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

package receiver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/analyzer"
	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/storage"
)

// EmailReceiver handles incoming emails from the MTA
type EmailReceiver struct {
	storage  storage.Storage
	config   *config.Config
	analyzer *analyzer.EmailAnalyzer
}

// NewEmailReceiver creates a new email receiver
func NewEmailReceiver(store storage.Storage, cfg *config.Config) *EmailReceiver {
	return &EmailReceiver{
		storage:  store,
		config:   cfg,
		analyzer: analyzer.NewEmailAnalyzer(cfg),
	}
}

// ProcessEmail reads an email from the reader, analyzes it, and stores the results
func (r *EmailReceiver) ProcessEmail(emailData io.Reader, recipientEmail string) error {
	// Read the entire email
	rawEmail, err := io.ReadAll(emailData)
	if err != nil {
		return fmt.Errorf("failed to read email: %w", err)
	}

	return r.ProcessEmailBytes(rawEmail, recipientEmail)
}

// ProcessEmailBytes processes an email from a byte slice
func (r *EmailReceiver) ProcessEmailBytes(rawEmail []byte, recipientEmail string) error {

	log.Printf("Received email for %s (%d bytes)", recipientEmail, len(rawEmail))

	// Extract test ID from recipient email address
	testID, err := r.extractTestID(recipientEmail)
	if err != nil {
		return fmt.Errorf("failed to extract test ID: %w", err)
	}

	log.Printf("Extracted test ID: %s", testID)

	// Check if a report already exists for this test ID
	reportExists, err := r.storage.ReportExists(testID)
	if err != nil {
		return fmt.Errorf("failed to check report existence: %w", err)
	}

	if reportExists {
		log.Printf("Report already exists for test %s, skipping analysis", testID)
		return nil
	}

	log.Printf("Analyzing email for test %s", testID)

	// Analyze the email using the shared analyzer
	result, err := r.analyzer.AnalyzeEmailBytes(rawEmail, testID)
	if err != nil {
		return fmt.Errorf("failed to analyze email: %w", err)
	}

	log.Printf("Analysis complete. Score: %.2f/10", result.Report.Score)

	// Marshal report to JSON
	reportJSON, err := json.Marshal(result.Report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	// Store the report
	if _, err := r.storage.CreateReport(testID, rawEmail, reportJSON); err != nil {
		return fmt.Errorf("failed to store report: %w", err)
	}

	log.Printf("Report stored successfully for test %s", testID)
	return nil
}

// extractTestID extracts the UUID from the test email address
// Expected format: test-<uuid>@domain.com
func (r *EmailReceiver) extractTestID(email string) (uuid.UUID, error) {
	// Remove angle brackets if present (e.g., <test-uuid@domain.com>)
	email = strings.Trim(email, "<>")

	// Extract the local part (before @)
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return uuid.Nil, fmt.Errorf("invalid email format: %s", email)
	}

	localPart := parts[0]

	// Remove the prefix (e.g., "test-")
	if !strings.HasPrefix(localPart, r.config.Email.TestAddressPrefix) {
		return uuid.Nil, fmt.Errorf("email does not have expected prefix: %s", email)
	}

	uuidStr := strings.TrimPrefix(localPart, r.config.Email.TestAddressPrefix)

	// Parse UUID
	testID, err := uuid.Parse(uuidStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID in email address: %s", uuidStr)
	}

	return testID, nil
}

// ExtractRecipientFromHeaders attempts to extract the recipient email from email headers
// This is useful when the email is piped and we need to determine the recipient
func ExtractRecipientFromHeaders(rawEmail []byte) (string, error) {
	emailStr := string(rawEmail)

	// Look for common recipient headers
	headerPatterns := []string{
		`(?i)^To:\s*(.+)$`,
		`(?i)^X-Original-To:\s*(.+)$`,
		`(?i)^Delivered-To:\s*(.+)$`,
		`(?i)^Envelope-To:\s*(.+)$`,
	}

	for _, pattern := range headerPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(emailStr)
		if len(matches) > 1 {
			recipient := strings.TrimSpace(matches[1])
			// Clean up the email address
			recipient = strings.Trim(recipient, "<>")
			// Take only the first email if there are multiple
			if idx := strings.Index(recipient, ","); idx != -1 {
				recipient = recipient[:idx]
			}
			if recipient != "" {
				return recipient, nil
			}
		}
	}

	return "", fmt.Errorf("could not extract recipient from email headers")
}
