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

package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/storage"
	"git.happydns.org/happyDeliver/internal/utils"
)

// APIHandler implements the ServerInterface for handling API requests
type APIHandler struct {
	storage   storage.Storage
	config    *config.Config
	startTime time.Time
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(store storage.Storage, cfg *config.Config) *APIHandler {
	return &APIHandler{
		storage:   store,
		config:    cfg,
		startTime: time.Now(),
	}
}

// CreateTest creates a new deliverability test
// (POST /test)
func (h *APIHandler) CreateTest(c *gin.Context) {
	// Generate a unique test ID (no database record created)
	testID := uuid.New()

	// Convert UUID to base32 string for the API response
	base32ID := utils.UUIDToBase32(testID)

	// Generate test email address using Base32-encoded UUID
	email := fmt.Sprintf("%s%s@%s",
		h.config.Email.TestAddressPrefix,
		base32ID,
		h.config.Email.Domain,
	)

	// Return response
	c.JSON(http.StatusCreated, TestResponse{
		Id:      base32ID,
		Email:   openapi_types.Email(email),
		Status:  TestResponseStatusPending,
		Message: stringPtr("Send your test email to the given address"),
	})
}

// GetTest retrieves test metadata
// (GET /test/{id})
func (h *APIHandler) GetTest(c *gin.Context, id string) {
	// Convert base32 ID to UUID
	testUUID, err := utils.Base32ToUUID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: stringPtr(err.Error()),
		})
		return
	}

	// Check if a report exists for this test ID
	reportExists, err := h.storage.ReportExists(testUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Error{
			Error:   "internal_error",
			Message: "Failed to check test status",
			Details: stringPtr(err.Error()),
		})
		return
	}

	// Determine status based on report existence
	var apiStatus TestStatus
	if reportExists {
		apiStatus = TestStatusAnalyzed
	} else {
		apiStatus = TestStatusPending
	}

	// Generate test email address using Base32-encoded UUID
	email := fmt.Sprintf("%s%s@%s",
		h.config.Email.TestAddressPrefix,
		id,
		h.config.Email.Domain,
	)

	c.JSON(http.StatusOK, Test{
		Id:     id,
		Email:  openapi_types.Email(email),
		Status: apiStatus,
	})
}

// GetReport retrieves the detailed analysis report
// (GET /report/{id})
func (h *APIHandler) GetReport(c *gin.Context, id string) {
	// Convert base32 ID to UUID
	testUUID, err := utils.Base32ToUUID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: stringPtr(err.Error()),
		})
		return
	}

	reportJSON, _, err := h.storage.GetReport(testUUID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, Error{
				Error:   "not_found",
				Message: "Report not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, Error{
			Error:   "internal_error",
			Message: "Failed to retrieve report",
			Details: stringPtr(err.Error()),
		})
		return
	}

	// Return raw JSON directly
	c.Data(http.StatusOK, "application/json", reportJSON)
}

// GetRawEmail retrieves the raw annotated email
// (GET /report/{id}/raw)
func (h *APIHandler) GetRawEmail(c *gin.Context, id string) {
	// Convert base32 ID to UUID
	testUUID, err := utils.Base32ToUUID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: stringPtr(err.Error()),
		})
		return
	}

	_, rawEmail, err := h.storage.GetReport(testUUID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, Error{
				Error:   "not_found",
				Message: "Email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, Error{
			Error:   "internal_error",
			Message: "Failed to retrieve raw email",
			Details: stringPtr(err.Error()),
		})
		return
	}

	c.Data(http.StatusOK, "text/plain", rawEmail)
}

// GetStatus retrieves service health status
// (GET /status)
func (h *APIHandler) GetStatus(c *gin.Context) {
	// Calculate uptime
	uptime := int(time.Since(h.startTime).Seconds())

	// Check database connectivity by trying to check if a report exists
	dbStatus := StatusComponentsDatabaseUp
	if _, err := h.storage.ReportExists(uuid.New()); err != nil {
		dbStatus = StatusComponentsDatabaseDown
	}

	// Determine overall status
	overallStatus := Healthy
	if dbStatus == StatusComponentsDatabaseDown {
		overallStatus = Unhealthy
	}

	mtaStatus := StatusComponentsMtaUp
	c.JSON(http.StatusOK, Status{
		Status:  overallStatus,
		Version: "0.1.0-dev",
		Components: &struct {
			Database *StatusComponentsDatabase `json:"database,omitempty"`
			Mta      *StatusComponentsMta      `json:"mta,omitempty"`
		}{
			Database: &dbStatus,
			Mta:      &mtaStatus,
		},
		Uptime: &uptime,
	})
}
