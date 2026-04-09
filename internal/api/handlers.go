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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/storage"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/internal/version"
)

// EmailAnalyzer defines the interface for email analysis
// This interface breaks the circular dependency with pkg/analyzer
type EmailAnalyzer interface {
	AnalyzeEmailBytes(rawEmail []byte, testID uuid.UUID) (reportJSON []byte, err error)
	AnalyzeDomain(domain string) (dnsResults *model.DNSResults, score int, grade string)
	CheckBlacklistIP(ip string) (checks []model.BlacklistCheck, whitelists []model.BlacklistCheck, listedCount int, score int, grade string, err error)
}

// APIHandler implements the ServerInterface for handling API requests
type APIHandler struct {
	storage   storage.Storage
	config    *config.Config
	analyzer  EmailAnalyzer
	startTime time.Time
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(store storage.Storage, cfg *config.Config, analyzer EmailAnalyzer) *APIHandler {
	return &APIHandler{
		storage:   store,
		config:    cfg,
		analyzer:  analyzer,
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
	c.JSON(http.StatusCreated, model.TestResponse{
		Id:      base32ID,
		Email:   openapi_types.Email(email),
		Status:  model.TestResponseStatusPending,
		Message: utils.PtrTo("Send your test email to the given address"),
	})
}

// GetTest retrieves test metadata
// (GET /test/{id})
func (h *APIHandler) GetTest(c *gin.Context, id string) {
	// Convert base32 ID to UUID
	testUUID, err := utils.Base32ToUUID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Check if a report exists for this test ID
	reportExists, err := h.storage.ReportExists(testUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to check test status",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Determine status based on report existence
	var apiStatus model.TestStatus
	if reportExists {
		apiStatus = model.TestStatusAnalyzed
	} else {
		apiStatus = model.TestStatusPending
	}

	// Generate test email address using Base32-encoded UUID
	email := fmt.Sprintf("%s%s@%s",
		h.config.Email.TestAddressPrefix,
		id,
		h.config.Email.Domain,
	)

	c.JSON(http.StatusOK, model.Test{
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
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	reportJSON, _, err := h.storage.GetReport(testUUID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, model.Error{
				Error:   "not_found",
				Message: "Report not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to retrieve report",
			Details: utils.PtrTo(err.Error()),
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
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	_, rawEmail, err := h.storage.GetReport(testUUID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, model.Error{
				Error:   "not_found",
				Message: "Email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to retrieve raw email",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	c.Data(http.StatusOK, "text/plain", rawEmail)
}

// ReanalyzeReport re-analyzes an existing email and regenerates the report
// (POST /report/{id}/reanalyze)
func (h *APIHandler) ReanalyzeReport(c *gin.Context, id string) {
	// Convert base32 ID to UUID
	testUUID, err := utils.Base32ToUUID(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_id",
			Message: "Invalid test ID format",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Retrieve the existing report (mainly to get the raw email)
	_, rawEmail, err := h.storage.GetReport(testUUID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, model.Error{
				Error:   "not_found",
				Message: "Email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to retrieve email",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Re-analyze the email using the current analyzer
	reportJSON, err := h.analyzer.AnalyzeEmailBytes(rawEmail, testUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "analysis_error",
			Message: "Failed to re-analyze email",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Update the report in storage
	if err := h.storage.UpdateReport(testUUID, reportJSON); err != nil {
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to update report",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Return the updated report JSON directly
	c.Data(http.StatusOK, "application/json", reportJSON)
}

// GetStatus retrieves service health status
// (GET /status)
func (h *APIHandler) GetStatus(c *gin.Context) {
	// Calculate uptime
	uptime := int(time.Since(h.startTime).Seconds())

	// Check database connectivity by trying to check if a report exists
	dbStatus := model.StatusComponentsDatabaseUp
	if _, err := h.storage.ReportExists(uuid.New()); err != nil {
		dbStatus = model.StatusComponentsDatabaseDown
	}

	// Determine overall status
	overallStatus := model.Healthy
	if dbStatus == model.StatusComponentsDatabaseDown {
		overallStatus = model.Unhealthy
	}

	mtaStatus := model.StatusComponentsMtaUp
	c.JSON(http.StatusOK, model.Status{
		Status:  overallStatus,
		Version: version.Version,
		Components: &struct {
			Database *model.StatusComponentsDatabase `json:"database,omitempty"`
			Mta      *model.StatusComponentsMta      `json:"mta,omitempty"`
		}{
			Database: &dbStatus,
			Mta:      &mtaStatus,
		},
		Uptime: &uptime,
	})
}

// TestDomain performs synchronous domain analysis
// (POST /domain)
func (h *APIHandler) TestDomain(c *gin.Context) {
	var request model.DomainTestRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_request",
			Message: "Invalid request body",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Perform domain analysis
	dnsResults, score, grade := h.analyzer.AnalyzeDomain(request.Domain)

	// Convert grade string to DomainTestResponseGrade enum
	var responseGrade model.DomainTestResponseGrade
	switch grade {
	case "A+":
		responseGrade = model.DomainTestResponseGradeA
	case "A":
		responseGrade = model.DomainTestResponseGradeA1
	case "B":
		responseGrade = model.DomainTestResponseGradeB
	case "C":
		responseGrade = model.DomainTestResponseGradeC
	case "D":
		responseGrade = model.DomainTestResponseGradeD
	case "E":
		responseGrade = model.DomainTestResponseGradeE
	case "F":
		responseGrade = model.DomainTestResponseGradeF
	default:
		responseGrade = model.DomainTestResponseGradeF
	}

	// Build response
	response := model.DomainTestResponse{
		Domain:     request.Domain,
		Score:      score,
		Grade:      responseGrade,
		DnsResults: *dnsResults,
	}

	c.JSON(http.StatusOK, response)
}

// CheckBlacklist checks an IP address against DNS blacklists
// (POST /blacklist)
func (h *APIHandler) CheckBlacklist(c *gin.Context) {
	var request model.BlacklistCheckRequest

	// Bind and validate request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_request",
			Message: "Invalid request body",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Perform blacklist check using analyzer
	checks, whitelists, listedCount, score, grade, err := h.analyzer.CheckBlacklistIP(request.Ip)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.Error{
			Error:   "invalid_ip",
			Message: "Invalid IP address",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	// Build response
	response := model.BlacklistCheckResponse{
		Ip:          request.Ip,
		Blacklists:  checks,
		Whitelists:  &whitelists,
		ListedCount: listedCount,
		Score:       score,
		Grade:       model.BlacklistCheckResponseGrade(grade),
	}

	c.JSON(http.StatusOK, response)
}

// ListTests returns a paginated list of test summaries
// (GET /tests)
func (h *APIHandler) ListTests(c *gin.Context, params ListTestsParams) {
	if h.config.DisableTestList {
		c.JSON(http.StatusForbidden, model.Error{
			Error:   "feature_disabled",
			Message: "Test listing is disabled on this instance",
		})
		return
	}

	offset := 0
	limit := 20
	if params.Offset != nil {
		offset = *params.Offset
	}
	if params.Limit != nil {
		limit = *params.Limit
		if limit > 100 {
			limit = 100
		}
	}

	tests, total, err := h.storage.ListReportSummaries(offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error{
			Error:   "internal_error",
			Message: "Failed to list tests",
			Details: utils.PtrTo(err.Error()),
		})
		return
	}

	c.JSON(http.StatusOK, model.TestListResponse{
		Tests:  tests,
		Total:  int(total),
		Offset: offset,
		Limit:  limit,
	})
}
