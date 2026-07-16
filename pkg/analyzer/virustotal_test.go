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

package analyzer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func newTestVTClient(t *testing.T, handler http.Handler, upload bool) *VirusTotalClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := NewVirusTotalClient("test-api-key", upload, 5*time.Second)
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond
	return client
}

func vtFileResponse(malicious, suspicious, harmless, undetected int) string {
	return fmt.Sprintf(`{"data":{"attributes":{"last_analysis_stats":{"malicious":%d,"suspicious":%d,"harmless":%d,"undetected":%d}}}}`,
		malicious, suspicious, harmless, undetected)
}

func TestVirusTotalMalicious(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, vtFileResponse(42, 3, 10, 20))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "malicious" {
		t.Errorf("Expected status malicious, got %q (%s)", scan.Status, scan.Error)
	}
	if scan.Positives != 45 || scan.Total != 75 {
		t.Errorf("Expected 45/75, got %d/%d", scan.Positives, scan.Total)
	}
	if scan.Permalink != "https://www.virustotal.com/gui/file/"+testSHA256 {
		t.Errorf("Unexpected permalink: %q", scan.Permalink)
	}
}

func TestVirusTotalClean(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, vtFileResponse(0, 0, 70, 4))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "clean" {
		t.Errorf("Expected status clean, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestVirusTotalSuspicious(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, vtFileResponse(0, 2, 60, 12))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "suspicious" {
		t.Errorf("Expected status suspicious, got %q", scan.Status)
	}
}

func TestVirusTotalUnknownNoUpload(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, []byte("some content"))
	if scan.Status != "unknown" {
		t.Errorf("Expected status unknown, got %q", scan.Status)
	}
}

func TestVirusTotalInvalidKey(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "error" {
		t.Errorf("Expected status error, got %q", scan.Status)
	}
}

func TestVirusTotalRateLimited(t *testing.T) {
	client := newTestVTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "error" {
		t.Errorf("Expected status error, got %q", scan.Status)
	}
}

func TestVirusTotalUploadAndPoll(t *testing.T) {
	polls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /files", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"data":{"id":"analysis-123"}}`)
	})
	mux.HandleFunc("GET /analyses/analysis-123", func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls < 2 {
			fmt.Fprint(w, `{"data":{"attributes":{"status":"queued"}}}`)
			return
		}
		fmt.Fprint(w, `{"data":{"attributes":{"status":"completed","stats":{"malicious":5,"suspicious":0,"harmless":50,"undetected":10}}}}`)
	})

	client := newTestVTClient(t, mux, true)
	scan := client.CheckHash(context.Background(), testSHA256, []byte("unknown file content"))
	if scan.Status != "malicious" {
		t.Fatalf("Expected status malicious after poll, got %q (%s)", scan.Status, scan.Error)
	}
	if scan.Positives != 5 {
		t.Errorf("Expected 5 positives, got %d", scan.Positives)
	}
}

func TestVirusTotalUploadPollTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /files", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"id":"analysis-slow"}}`)
	})
	mux.HandleFunc("GET /analyses/analysis-slow", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"attributes":{"status":"queued"}}}`)
	})

	client := newTestVTClient(t, mux, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	scan := client.CheckHash(ctx, testSHA256, []byte("unknown file content"))
	if scan.Status != "pending" {
		t.Errorf("Expected status pending on poll timeout, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestNewVirusTotalClientDisabled(t *testing.T) {
	if client := NewVirusTotalClient("", false, time.Second); client != nil {
		t.Error("Expected nil client for empty API key")
	}
}
