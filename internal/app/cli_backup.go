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
	"fmt"
	"io"
	"os"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/storage"
)

// BackupData represents the structure of a backup file
type BackupData struct {
	Version string           `json:"version"`
	Reports []storage.Report `json:"reports"`
}

// RunBackup exports the database to stdout as JSON
func RunBackup(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.Type, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer store.Close()

	fmt.Fprintf(os.Stderr, "Connected to %s database\n", cfg.Database.Type)

	// Get all reports from the database
	reports, err := storage.GetAllReports(store)
	if err != nil {
		return fmt.Errorf("failed to retrieve reports: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d reports to backup\n", len(reports))

	// Create backup data structure
	backup := BackupData{
		Version: "1.0",
		Reports: reports,
	}

	// Encode to JSON and write to stdout
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(backup); err != nil {
		return fmt.Errorf("failed to encode backup data: %w", err)
	}

	return nil
}

// RunRestore imports the database from a JSON file or stdin
func RunRestore(cfg *config.Config, inputPath string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Determine input source
	var reader io.Reader
	if inputPath == "" || inputPath == "-" {
		fmt.Fprintln(os.Stderr, "Reading backup from stdin...")
		reader = os.Stdin
	} else {
		inFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open backup file: %w", err)
		}
		defer inFile.Close()
		fmt.Fprintf(os.Stderr, "Reading backup from file: %s\n", inputPath)
		reader = inFile
	}

	// Decode JSON
	var backup BackupData
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&backup); err != nil {
		if err == io.EOF {
			return fmt.Errorf("backup file is empty or corrupted")
		}
		return fmt.Errorf("failed to decode backup data: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Backup version: %s\n", backup.Version)
	fmt.Fprintf(os.Stderr, "Found %d reports in backup\n", len(backup.Reports))

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.Type, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer store.Close()

	fmt.Fprintf(os.Stderr, "Connected to %s database\n", cfg.Database.Type)

	// Restore reports
	restored, skipped, failed := 0, 0, 0
	for _, report := range backup.Reports {
		// Check if report already exists
		exists, err := store.ReportExists(report.TestID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to check if report %s exists: %v\n", report.TestID, err)
			failed++
			continue
		}

		if exists {
			fmt.Fprintf(os.Stderr, "Report %s already exists, skipping\n", report.TestID)
			skipped++
			continue
		}

		// Create the report
		_, err = storage.CreateReportFromBackup(store, &report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to restore report %s: %v\n", report.TestID, err)
			failed++
			continue
		}

		restored++
	}

	fmt.Fprintf(os.Stderr, "Restore completed: %d restored, %d skipped, %d failed\n", restored, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("restore completed with %d failures", failed)
	}

	return nil
}
