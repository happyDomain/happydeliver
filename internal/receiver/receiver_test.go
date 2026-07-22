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

package receiver

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/storage"
	"git.happydns.org/happyDeliver/internal/utils"
)

// mockStorage is a minimal in-memory storage.Storage implementation for tests.
type mockStorage struct {
	reportExists    bool
	reportExistsErr error
	createErr       error

	existsCalls   int
	createdEmails [][]byte
}

func (m *mockStorage) CreateReport(testID uuid.UUID, rawEmail []byte, reportJSON []byte) (*storage.Report, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.createdEmails = append(m.createdEmails, rawEmail)
	return &storage.Report{TestID: testID, RawEmail: rawEmail, ReportJSON: reportJSON}, nil
}

func (m *mockStorage) GetReport(testID uuid.UUID) ([]byte, []byte, error) {
	return nil, nil, errors.New("not implemented")
}

func (m *mockStorage) ReportExists(testID uuid.UUID) (bool, error) {
	m.existsCalls++
	return m.reportExists, m.reportExistsErr
}

func (m *mockStorage) UpdateReport(testID uuid.UUID, reportJSON []byte) error { return nil }

func (m *mockStorage) DeleteOldReports(olderThan time.Time) (int64, error) { return 0, nil }

func (m *mockStorage) ListReportSummaries(offset, limit int) ([]model.TestSummary, int64, error) {
	return nil, 0, nil
}

func (m *mockStorage) Close() error { return nil }

// errReader is an io.Reader that always fails, to exercise read-error paths.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// testConfig returns a minimal config suitable for the receiver/analyzer.
func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Email.Domain = "example.com"
	cfg.Email.TestAddressPrefix = "test-"
	return cfg
}

// testRecipient builds a valid recipient address for the given test UUID.
func testRecipient(id uuid.UUID) string {
	return "test-" + utils.UUIDToBase32(id) + "@example.com"
}

func TestNewEmailReceiver(t *testing.T) {
	cfg := testConfig()
	store := &mockStorage{}
	r := NewEmailReceiver(store, cfg)
	if r == nil {
		t.Fatal("NewEmailReceiver returned nil")
	}
	if r.storage != store {
		t.Error("storage not wired to the provided store")
	}
	if r.config != cfg {
		t.Error("config not wired to the provided config")
	}
	if r.analyzer == nil {
		t.Error("analyzer not initialized")
	}
}

func TestProcessEmailReadError(t *testing.T) {
	r := NewEmailReceiver(&mockStorage{}, testConfig())
	err := r.ProcessEmail(errReader{}, testRecipient(uuid.New()))
	if err == nil {
		t.Fatal("expected error when reader fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read email") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessEmailDelegates(t *testing.T) {
	// reportExists=true short-circuits before analysis, so a minimal body is fine.
	store := &mockStorage{reportExists: true}
	r := NewEmailReceiver(store, testConfig())
	err := r.ProcessEmail(strings.NewReader("Subject: hi\r\n\r\nbody\r\n"), testRecipient(uuid.New()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.existsCalls != 1 {
		t.Errorf("expected ProcessEmailBytes to be reached (1 exists call), got %d", store.existsCalls)
	}
}

func TestProcessEmailBytesInvalidRecipient(t *testing.T) {
	r := NewEmailReceiver(&mockStorage{}, testConfig())
	err := r.ProcessEmailBytes([]byte("body"), "not-a-test-address@example.com")
	if err == nil {
		t.Fatal("expected error for recipient without test prefix, got nil")
	}
	if !strings.Contains(err.Error(), "failed to extract test ID") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessEmailBytesReportExistsError(t *testing.T) {
	store := &mockStorage{reportExistsErr: errors.New("db down")}
	r := NewEmailReceiver(store, testConfig())
	err := r.ProcessEmailBytes([]byte("body"), testRecipient(uuid.New()))
	if err == nil {
		t.Fatal("expected error when ReportExists fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to check report existence") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessEmailBytesReportAlreadyExists(t *testing.T) {
	store := &mockStorage{reportExists: true}
	r := NewEmailReceiver(store, testConfig())
	err := r.ProcessEmailBytes([]byte("body"), testRecipient(uuid.New()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.createdEmails) != 0 {
		t.Errorf("expected analysis to be skipped, but a report was created")
	}
}

func TestProcessEmailBytesSuccess(t *testing.T) {
	store := &mockStorage{reportExists: false}
	r := NewEmailReceiver(store, testConfig())
	id := uuid.New()
	raw := []byte("Subject: hi\r\n\r\nbody\r\n")
	if err := r.ProcessEmailBytes(raw, testRecipient(id)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.createdEmails) != 1 {
		t.Fatalf("expected 1 stored report, got %d", len(store.createdEmails))
	}
	if string(store.createdEmails[0]) != string(raw) {
		t.Errorf("stored raw email does not match the input")
	}
}

func TestProcessEmailBytesCreateError(t *testing.T) {
	store := &mockStorage{reportExists: false, createErr: errors.New("write failed")}
	r := NewEmailReceiver(store, testConfig())
	err := r.ProcessEmailBytes([]byte("Subject: hi\r\n\r\nbody\r\n"), testRecipient(uuid.New()))
	if err == nil {
		t.Fatal("expected error when CreateReport fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to store report") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessEmailBytesReceiverHostnameMismatch(t *testing.T) {
	// Set a receiver hostname that won't match the (absent) Received chain,
	// exercising the mismatch-warning branch without changing the outcome.
	cfg := testConfig()
	cfg.Email.ReceiverHostname = "mx.expected.example.com"
	store := &mockStorage{reportExists: false}
	r := NewEmailReceiver(store, cfg)
	// A Received hop whose "by" differs from the configured hostname drives the
	// warning branch.
	raw := []byte("Received: from sender.example.org by mx.actual.example.com with ESMTP id 1\r\n" +
		"Subject: hi\r\n\r\nbody\r\n")
	if err := r.ProcessEmailBytes(raw, testRecipient(uuid.New())); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.createdEmails) != 1 {
		t.Errorf("expected report to be stored despite hostname config, got %d", len(store.createdEmails))
	}
}

func TestExtractTestID(t *testing.T) {
	r := NewEmailReceiver(&mockStorage{}, testConfig())

	t.Run("valid with angle brackets", func(t *testing.T) {
		id := uuid.New()
		got, err := r.extractTestID("<" + testRecipient(id) + ">")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Errorf("expected %s, got %s", id, got)
		}
	})

	t.Run("missing at sign", func(t *testing.T) {
		if _, err := r.extractTestID("test-whatever"); err == nil {
			t.Fatal("expected error for address without @, got nil")
		}
	})

	t.Run("wrong prefix", func(t *testing.T) {
		if _, err := r.extractTestID("nope-abcd@example.com"); err == nil {
			t.Fatal("expected error for missing prefix, got nil")
		}
	})

	t.Run("invalid base32", func(t *testing.T) {
		if _, err := r.extractTestID("test-not!valid!base32@example.com"); err == nil {
			t.Fatal("expected error for invalid base32, got nil")
		}
	})

	t.Run("wrong decoded length", func(t *testing.T) {
		// "AA" decodes to a single byte, far short of the 16 a UUID needs.
		if _, err := r.extractTestID("test-AA@example.com"); err == nil {
			t.Fatal("expected error for wrong decoded length, got nil")
		}
	})
}

func TestBase32ToUUIDRoundTrip(t *testing.T) {
	id := uuid.New()
	encoded := utils.UUIDToBase32(id)
	got, err := base32ToUUID(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != id {
		t.Errorf("round trip mismatch: expected %s, got %s", id, got)
	}

	t.Run("hyphens are ignored", func(t *testing.T) {
		withHyphens := encoded[:4] + "-" + encoded[4:]
		got, err := base32ToUUID(withHyphens)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Errorf("hyphenated round trip mismatch: expected %s, got %s", id, got)
		}
	})

	t.Run("invalid characters", func(t *testing.T) {
		if _, err := base32ToUUID("1890!!"); err == nil {
			t.Fatal("expected error for invalid base32, got nil")
		}
	})
}

func TestExtractRecipientFromHeaders(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "To header",
			email: "To: user@example.com",
			want:  "user@example.com",
		},
		{
			name:  "angle brackets stripped",
			email: "To: <user@example.com>",
			want:  "user@example.com",
		},
		{
			name:  "multiple recipients keeps first",
			email: "To: first@example.com, second@example.com",
			want:  "first@example.com",
		},
		{
			name:  "To header among other headers",
			email: "Subject: hi\r\nTo: user@example.com\r\nFrom: sender@example.org\r\n\r\nbody",
			want:  "user@example.com",
		},
		{
			name:  "X-Original-To fallback",
			email: "X-Original-To: orig@example.com",
			want:  "orig@example.com",
		},
		{
			name:  "X-Original-To among other headers",
			email: "Subject: hi\r\nX-Original-To: orig@example.com\r\n\r\nbody",
			want:  "orig@example.com",
		},
		{
			name:  "Delivered-To fallback",
			email: "Delivered-To: deliv@example.com",
			want:  "deliv@example.com",
		},
		{
			name:  "Envelope-To fallback",
			email: "Envelope-To: env@example.com",
			want:  "env@example.com",
		},
		{
			name:  "To wins over later fallback headers",
			email: "To: primary@example.com\r\nX-Original-To: orig@example.com\r\n\r\nbody",
			want:  "primary@example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractRecipientFromHeaders([]byte(tt.email))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}

	t.Run("no recipient header", func(t *testing.T) {
		if _, err := ExtractRecipientFromHeaders([]byte("Subject: hi\r\n\r\nbody")); err == nil {
			t.Fatal("expected error when no recipient header is present, got nil")
		}
	})
}
