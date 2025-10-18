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
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Report represents the analysis report for a test
type Report struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	TestID     uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"` // The test ID extracted from email address
	RawEmail   []byte    `gorm:"type:bytea;not null"`            // Full raw email with headers
	ReportJSON []byte    `gorm:"type:bytea;not null"`            // JSON-encoded report data
	CreatedAt  time.Time `gorm:"not null"`
}

// BeforeCreate is a GORM hook that generates a UUID before creating a report
func (r *Report) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}
