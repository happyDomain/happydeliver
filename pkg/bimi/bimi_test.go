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

package bimi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// stubResolver returns canned TXT records (or an error) for LookupTXT.
type stubResolver struct {
	txt []string
	err error
}

func (r stubResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.txt, r.err
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.HTTPClient == nil {
		t.Error("HTTPClient should be set")
	} else if v.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("HTTPClient.Timeout = %s, want 30s", v.HTTPClient.Timeout)
	}
	if v.Resolver == nil {
		t.Error("Resolver should be set")
	}
}

func TestValidatorDefaults(t *testing.T) {
	// With no HTTPClient set, httpClient() falls back to http.DefaultClient.
	v := &Validator{}
	if v.httpClient() != http.DefaultClient {
		t.Error("httpClient() should default to http.DefaultClient")
	}
	// With no Now set, now() falls back to time.Now (a recent timestamp).
	before := time.Now().Add(-time.Minute)
	if got := v.now(); got.Before(before) {
		t.Errorf("now() = %s, expected a recent time", got)
	}
}
