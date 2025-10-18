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
	"context"
	"log"
	"time"

	"git.happydns.org/happyDeliver/internal/storage"
)

const (
	// How often to run the cleanup check
	cleanupInterval = 1 * time.Hour
)

// CleanupService handles periodic cleanup of old reports
type CleanupService struct {
	store     storage.Storage
	retention time.Duration
	ticker    *time.Ticker
	done      chan struct{}
}

// NewCleanupService creates a new cleanup service
func NewCleanupService(store storage.Storage, retention time.Duration) *CleanupService {
	return &CleanupService{
		store:     store,
		retention: retention,
		done:      make(chan struct{}),
	}
}

// Start begins the cleanup service in a background goroutine
func (s *CleanupService) Start(ctx context.Context) {
	if s.retention <= 0 {
		log.Println("Report retention is disabled (keeping reports forever)")
		return
	}

	log.Printf("Starting cleanup service: will delete reports older than %s", s.retention)

	// Run cleanup immediately on startup
	s.runCleanup()

	// Then run periodically
	s.ticker = time.NewTicker(cleanupInterval)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.runCleanup()
			case <-ctx.Done():
				s.Stop()
				return
			case <-s.done:
				return
			}
		}
	}()
}

// Stop stops the cleanup service
func (s *CleanupService) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.done)
}

// runCleanup performs the actual cleanup operation
func (s *CleanupService) runCleanup() {
	cutoffTime := time.Now().Add(-s.retention)
	log.Printf("Running cleanup: deleting reports older than %s", cutoffTime.Format(time.RFC3339))

	deleted, err := s.store.DeleteOldReports(cutoffTime)
	if err != nil {
		log.Printf("Error during cleanup: %v", err)
		return
	}

	if deleted > 0 {
		log.Printf("Cleanup completed: deleted %d old report(s)", deleted)
	} else {
		log.Printf("Cleanup completed: no old reports to delete")
	}
}
