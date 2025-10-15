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

package storage

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Storage interface defines operations for persisting and retrieving data
type Storage interface {
	// Test operations
	CreateTest(id uuid.UUID) (*Test, error)
	GetTest(id uuid.UUID) (*Test, error)
	UpdateTestStatus(id uuid.UUID, status TestStatus) error

	// Report operations
	CreateReport(testID uuid.UUID, rawEmail []byte, reportJSON []byte) (*Report, error)
	GetReport(testID uuid.UUID) (reportJSON []byte, rawEmail []byte, err error)

	// Close closes the database connection
	Close() error
}

// DBStorage implements Storage using GORM
type DBStorage struct {
	db *gorm.DB
}

// NewStorage creates a new storage instance based on database type
func NewStorage(dbType, dsn string) (Storage, error) {
	var dialector gorm.Dialector

	switch dbType {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&Test{}, &Report{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	return &DBStorage{db: db}, nil
}

// CreateTest creates a new test with pending status
func (s *DBStorage) CreateTest(id uuid.UUID) (*Test, error) {
	test := &Test{
		ID:     id,
		Status: StatusPending,
	}

	if err := s.db.Create(test).Error; err != nil {
		return nil, fmt.Errorf("failed to create test: %w", err)
	}

	return test, nil
}

// GetTest retrieves a test by ID
func (s *DBStorage) GetTest(id uuid.UUID) (*Test, error) {
	var test Test
	if err := s.db.First(&test, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get test: %w", err)
	}
	return &test, nil
}

// UpdateTestStatus updates the status of a test
func (s *DBStorage) UpdateTestStatus(id uuid.UUID, status TestStatus) error {
	result := s.db.Model(&Test{}).Where("id = ?", id).Update("status", status)
	if result.Error != nil {
		return fmt.Errorf("failed to update test status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateReport creates a new report for a test
func (s *DBStorage) CreateReport(testID uuid.UUID, rawEmail []byte, reportJSON []byte) (*Report, error) {
	dbReport := &Report{
		TestID:     testID,
		RawEmail:   rawEmail,
		ReportJSON: reportJSON,
	}

	if err := s.db.Create(dbReport).Error; err != nil {
		return nil, fmt.Errorf("failed to create report: %w", err)
	}

	// Update test status to analyzed
	if err := s.UpdateTestStatus(testID, StatusAnalyzed); err != nil {
		return nil, fmt.Errorf("failed to update test status: %w", err)
	}

	return dbReport, nil
}

// GetReport retrieves a report by test ID, returning the raw JSON and email bytes
func (s *DBStorage) GetReport(testID uuid.UUID) ([]byte, []byte, error) {
	var dbReport Report
	if err := s.db.First(&dbReport, "test_id = ?", testID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("failed to get report: %w", err)
	}

	return dbReport.ReportJSON, dbReport.RawEmail, nil
}

// Close closes the database connection
func (s *DBStorage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
