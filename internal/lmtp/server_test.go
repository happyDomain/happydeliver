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

package lmtp

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

	existsCalls   int
	createdEmails [][]byte
}

func (m *mockStorage) CreateReport(testID uuid.UUID, rawEmail []byte, reportJSON []byte) (*storage.Report, error) {
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

// testRecipient builds a valid recipient address for a random test UUID.
func testRecipient() string {
	return "test-" + utils.UUIDToBase32(uuid.New()) + "@example.com"
}

func TestNewBackend(t *testing.T) {
	cfg := testConfig()
	b := NewBackend(&mockStorage{}, cfg)
	if b == nil {
		t.Fatal("NewBackend returned nil")
	}
	if b.receiver == nil {
		t.Error("backend receiver is nil")
	}
	if b.config != cfg {
		t.Error("backend config not set to the provided config")
	}
}

func TestNewSession(t *testing.T) {
	b := NewBackend(&mockStorage{}, testConfig())
	sess, err := b.NewSession(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := sess.(*Session)
	if !ok {
		t.Fatalf("expected *Session, got %T", sess)
	}
	if s.backend != b {
		t.Error("session backend not wired to the creating backend")
	}
}

func TestSessionAuthPlain(t *testing.T) {
	s := &Session{}
	if err := s.AuthPlain("user", "pass"); err != nil {
		t.Errorf("AuthPlain should always succeed, got %v", err)
	}
}

func TestSessionMail(t *testing.T) {
	s := &Session{}
	if err := s.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.from != "sender@example.com" {
		t.Errorf("expected from to be set, got %q", s.from)
	}
}

func TestSessionRcpt(t *testing.T) {
	s := &Session{}
	if err := s.Rcpt("a@example.com", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.Rcpt("b@example.com", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(s.recipients))
	}
	if s.recipients[0] != "a@example.com" || s.recipients[1] != "b@example.com" {
		t.Errorf("recipients not appended in order: %v", s.recipients)
	}
}

func TestSessionReset(t *testing.T) {
	s := &Session{from: "sender@example.com", recipients: []string{"a@example.com"}}
	s.Reset()
	if s.from != "" {
		t.Errorf("expected from cleared, got %q", s.from)
	}
	if s.recipients != nil {
		t.Errorf("expected recipients cleared, got %v", s.recipients)
	}
}

func TestSessionLogout(t *testing.T) {
	s := &Session{}
	if err := s.Logout(); err != nil {
		t.Errorf("Logout should succeed, got %v", err)
	}
}

func TestStartServerListenError(t *testing.T) {
	// An unparseable address makes net.Listen fail immediately, so
	// StartServer returns before blocking in Serve.
	err := StartServer("invalid:address:99999", &mockStorage{}, testConfig())
	if err == nil {
		t.Fatal("expected an error for an invalid bind address, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create LMTP listener") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSessionData(t *testing.T) {
	t.Run("processes each recipient", func(t *testing.T) {
		// reportExists=true short-circuits analysis, so we exercise the
		// per-recipient loop without depending on the analyzer.
		store := &mockStorage{reportExists: true}
		b := NewBackend(store, testConfig())
		s := &Session{backend: b, from: "sender@example.com"}
		s.recipients = []string{testRecipient(), testRecipient()}

		if err := s.Data(strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store.existsCalls != 2 {
			t.Errorf("expected ReportExists called once per recipient (2), got %d", store.existsCalls)
		}
	})

	t.Run("prepends Return-Path from envelope sender", func(t *testing.T) {
		store := &mockStorage{reportExists: false}
		b := NewBackend(store, testConfig())
		s := &Session{backend: b, from: "sender@example.com"}
		s.recipients = []string{testRecipient()}

		if err := s.Data(strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(store.createdEmails) != 1 {
			t.Fatalf("expected 1 stored email, got %d", len(store.createdEmails))
		}
		got := string(store.createdEmails[0])
		if !strings.HasPrefix(got, "Return-Path: <sender@example.com>\r\n") {
			t.Errorf("stored email missing prepended Return-Path header: %q", got[:min(len(got), 60)])
		}
	})

	t.Run("returns error for invalid recipient", func(t *testing.T) {
		store := &mockStorage{reportExists: true}
		b := NewBackend(store, testConfig())
		s := &Session{backend: b, from: "sender@example.com"}
		s.recipients = []string{"not-a-test-address@example.com"}

		if err := s.Data(strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err == nil {
			t.Fatal("expected error for recipient without test prefix, got nil")
		}
	})

	t.Run("returns error when reading data fails", func(t *testing.T) {
		store := &mockStorage{reportExists: true}
		b := NewBackend(store, testConfig())
		s := &Session{backend: b, from: "sender@example.com", recipients: []string{testRecipient()}}

		if err := s.Data(errReader{}); err == nil {
			t.Fatal("expected error when the data reader fails, got nil")
		}
	})

	t.Run("no recipients is a no-op", func(t *testing.T) {
		store := &mockStorage{reportExists: true}
		b := NewBackend(store, testConfig())
		s := &Session{backend: b, from: "sender@example.com"}

		if err := s.Data(strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store.existsCalls != 0 {
			t.Errorf("expected no processing without recipients, got %d calls", store.existsCalls)
		}
	})
}
