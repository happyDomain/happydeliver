// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025-2026 happyDomain
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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/storage"
	"git.happydns.org/happyDeliver/internal/utils"
)

const sampleEML = "From: sender@example.net\r\n" +
	"To: recipient@example.com\r\n" +
	"Subject: Hello\r\n" +
	"\r\n" +
	"Body\r\n"

// fakeStorage records what a handler stored, so tests can assert on it without a database.
type fakeStorage struct {
	reports    map[uuid.UUID][]byte
	rawEmails  map[uuid.UUID][]byte
	createErr  error
	updateErr  error
	lastCreate uuid.UUID
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{
		reports:   map[uuid.UUID][]byte{},
		rawEmails: map[uuid.UUID][]byte{},
	}
}

func (f *fakeStorage) CreateReport(testID uuid.UUID, rawEmail []byte, reportJSON []byte) (*storage.Report, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.lastCreate = testID
	f.reports[testID] = reportJSON
	f.rawEmails[testID] = rawEmail
	return &storage.Report{TestID: testID, RawEmail: rawEmail, ReportJSON: reportJSON}, nil
}

func (f *fakeStorage) GetReport(testID uuid.UUID) ([]byte, []byte, error) {
	reportJSON, ok := f.reports[testID]
	if !ok {
		return nil, nil, storage.ErrNotFound
	}
	return reportJSON, f.rawEmails[testID], nil
}

func (f *fakeStorage) ReportExists(testID uuid.UUID) (bool, error) {
	_, ok := f.reports[testID]
	return ok, nil
}

func (f *fakeStorage) UpdateReport(testID uuid.UUID, reportJSON []byte) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.reports[testID] = reportJSON
	return nil
}

func (f *fakeStorage) DeleteOldReports(olderThan time.Time) (int64, error) { return 0, nil }

func (f *fakeStorage) ListReportSummaries(offset, limit int) ([]model.TestSummary, int64, error) {
	return nil, 0, nil
}

func (f *fakeStorage) Close() error { return nil }

// fakeAnalyzer records the source it was called with and returns a minimal report.
type fakeAnalyzer struct {
	lastSource model.ReportSource
	lastRaw    []byte
	err        error
}

func (f *fakeAnalyzer) AnalyzeEmailBytes(rawEmail []byte, testID uuid.UUID, source model.ReportSource) ([]byte, error) {
	f.lastSource = source
	f.lastRaw = rawEmail
	if f.err != nil {
		return nil, f.err
	}
	return json.Marshal(map[string]any{
		"id":      "report",
		"test_id": "test",
		"score":   42,
		"grade":   "B",
		"source":  source,
	})
}

func (f *fakeAnalyzer) AnalyzeDomain(domain string) (*model.DNSResults, int, string) {
	return &model.DNSResults{}, 0, "F"
}

func (f *fakeAnalyzer) CheckBlacklistIP(ip string) ([]model.BlacklistCheck, []model.BlacklistCheck, int, int, string, error) {
	return nil, nil, 0, 0, "F", nil
}

func newTestHandler(t *testing.T, cfg *config.Config) (*APIHandler, *fakeStorage, *fakeAnalyzer) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	store := newFakeStorage()
	analyzer := &fakeAnalyzer{}

	return NewAPIHandler(store, cfg, analyzer), store, analyzer
}

// uploadRequest builds a multipart request carrying body under the given field name.
func uploadRequest(t *testing.T, field, filename, body string) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("Failed to build multipart body: %v", err)
	}
	if _, err := part.Write([]byte(body)); err != nil {
		t.Fatalf("Failed to write multipart body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/test/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestUploadEml(t *testing.T) {
	t.Run("analyzes and stores the file as an upload", func(t *testing.T) {
		handler, store, analyzer := newTestHandler(t, nil)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = uploadRequest(t, "file", "message.eml", sampleEML)

		handler.UploadEml(c)

		if rec.Code != http.StatusCreated {
			t.Fatalf("Status = %d, expected %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
		}

		var resp model.EmlUploadResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if resp.Status != model.EmlUploadResponseStatusAnalyzed {
			t.Errorf("Status = %q, expected analyzed", resp.Status)
		}
		if resp.Source != model.EmlUploadResponseSourceUploaded {
			t.Errorf("Source = %q, expected upload", resp.Source)
		}
		if resp.Id == "" {
			t.Error("Expected a test id in the response")
		}

		// The analyzer must be told this is not a message we received ourselves
		if analyzer.lastSource != model.ReportSourceUploaded {
			t.Errorf("Analyzed with source %q, expected %q", analyzer.lastSource, model.ReportSourceUploaded)
		}
		if string(analyzer.lastRaw) != sampleEML {
			t.Errorf("Analyzed %q, expected the uploaded bytes", analyzer.lastRaw)
		}

		// The raw file is kept, so /report/{id}/raw and reanalysis keep working
		if string(store.rawEmails[store.lastCreate]) != sampleEML {
			t.Error("Expected the uploaded file to be stored")
		}

		// The stored report is reachable under the id handed back to the client
		rec = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/report/"+resp.Id, nil)
		handler.GetReport(c, resp.Id)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetReport status = %d, expected 200: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"source":"uploaded"`) {
			t.Errorf("Stored report does not record the upload source: %s", rec.Body.String())
		}
	})

	t.Run("rejects a missing file", func(t *testing.T) {
		handler, _, _ := newTestHandler(t, nil)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = uploadRequest(t, "eml", "message.eml", sampleEML)

		handler.UploadEml(c)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Status = %d, expected %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	})

	t.Run("rejects a file over the limit", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.MaxMessageSize = 64

		handler, store, _ := newTestHandler(t, cfg)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = uploadRequest(t, "file", "message.eml", strings.Repeat("x", 4096))

		handler.UploadEml(c)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Status = %d, expected %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if len(store.reports) != 0 {
			t.Error("Expected nothing to be stored for an oversized upload")
		}
	})

	t.Run("rejects an unparsable file", func(t *testing.T) {
		handler, store, analyzer := newTestHandler(t, nil)
		analyzer.err = errors.New("failed to parse email")

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = uploadRequest(t, "file", "not-an-email.txt", "this is not an email")

		handler.UploadEml(c)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Status = %d, expected %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if len(store.reports) != 0 {
			t.Error("Expected nothing to be stored when the analysis failed")
		}
	})

	t.Run("refuses when the feature is disabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.DisableEmlUpload = true

		handler, _, analyzer := newTestHandler(t, cfg)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = uploadRequest(t, "file", "message.eml", sampleEML)

		handler.UploadEml(c)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Status = %d, expected %d: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if analyzer.lastSource != "" {
			t.Error("Expected the file not to be analyzed at all")
		}
	})
}

func TestReanalyzeReportKeepsSource(t *testing.T) {
	tests := []struct {
		name     string
		stored   string
		expected model.ReportSource
	}{
		{
			name:     "an upload stays an upload",
			stored:   `{"source":"uploaded"}`,
			expected: model.ReportSourceUploaded,
		},
		{
			name:     "a received message stays received",
			stored:   `{"source":"received"}`,
			expected: model.ReportSourceReceived,
		},
		{
			name:     "a report predating the field counts as received",
			stored:   `{"score":42}`,
			expected: model.ReportSourceReceived,
		},
		{
			name:     "an unreadable report falls back to received",
			stored:   `not json`,
			expected: model.ReportSourceReceived,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store, analyzer := newTestHandler(t, nil)

			testID := uuid.New()
			store.reports[testID] = []byte(tt.stored)
			store.rawEmails[testID] = []byte(sampleEML)

			base32ID := utils.UUIDToBase32(testID)

			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/report/%s/reanalyze", base32ID), nil)

			handler.ReanalyzeReport(c, base32ID)

			if rec.Code != http.StatusOK {
				t.Fatalf("Status = %d, expected 200: %s", rec.Code, rec.Body.String())
			}
			if analyzer.lastSource != tt.expected {
				t.Errorf("Reanalyzed with source %q, expected %q", analyzer.lastSource, tt.expected)
			}
		})
	}
}
