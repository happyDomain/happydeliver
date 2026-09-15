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

package virustotal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func newTestClient(t *testing.T, handler http.Handler, upload bool) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := New("test-api-key", upload, 5*time.Second)
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond
	return client
}

func vtFileResponse(malicious, suspicious, harmless, undetected int) string {
	return fmt.Sprintf(`{"data":{"attributes":{"last_analysis_stats":{"malicious":%d,"suspicious":%d,"harmless":%d,"undetected":%d}}}}`,
		malicious, suspicious, harmless, undetected)
}

func TestCheckMalicious(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestCheckClean(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, vtFileResponse(0, 0, 70, 4))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "clean" {
		t.Errorf("Expected status clean, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestCheckSuspicious(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, vtFileResponse(0, 2, 60, 12))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "suspicious" {
		t.Errorf("Expected status suspicious, got %q", scan.Status)
	}
}

func TestCheckUnknownNoUpload(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, []byte("some content"))
	if scan.Status != "unknown" {
		t.Errorf("Expected status unknown, got %q", scan.Status)
	}
}

func TestCheckInvalidKey(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "error" {
		t.Errorf("Expected status error, got %q", scan.Status)
	}
}

func TestCheckRateLimited(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "error" {
		t.Errorf("Expected status error, got %q", scan.Status)
	}
}

func TestCheckUploadAndPoll(t *testing.T) {
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

	client := newTestClient(t, mux, true)
	scan := client.CheckHash(context.Background(), testSHA256, []byte("unknown file content"))
	if scan.Status != "malicious" {
		t.Fatalf("Expected status malicious after poll, got %q (%s)", scan.Status, scan.Error)
	}
	if scan.Positives != 5 {
		t.Errorf("Expected 5 positives, got %d", scan.Positives)
	}
}

func TestCheckUploadPollTimeout(t *testing.T) {
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

	client := newTestClient(t, mux, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	scan := client.CheckHash(ctx, testSHA256, []byte("unknown file content"))
	if scan.Status != "pending" {
		t.Errorf("Expected status pending on poll timeout, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestNewDisabled(t *testing.T) {
	if client := New("", false, time.Second); client != nil {
		t.Error("Expected nil client for empty API key")
	}
}

// TestCheckPending: a sample no engine has looked at yet is not a clean one.
func TestCheckPending(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, vtFileResponse(0, 0, 0, 0))
	}), false)

	scan := client.CheckHash(context.Background(), testSHA256, nil)
	if scan.Status != "pending" {
		t.Errorf("Expected status pending for a sample without a verdict, got %q", scan.Status)
	}
	if scan.Permalink != "https://www.virustotal.com/gui/file/"+testSHA256 {
		t.Errorf("Expected the permalink to name the file, got %q", scan.Permalink)
	}
}

// TestCheckDegradesToAnError holds every reply that is not a verdict to being
// reported as an error rather than as a clean file.
func TestCheckDegradesToAnError(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"unexpected status": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		},
		"reply that is not JSON": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html>a proxy error page</html>")
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, handler, false)

			scan := client.CheckHash(context.Background(), testSHA256, nil)
			if scan.Status != "error" || scan.Error == "" {
				t.Errorf("Expected an error naming its cause, got %+v", scan)
			}
		})
	}

	t.Run("server that is not there", func(t *testing.T) {
		client := New("test-api-key", false, time.Second)
		client.baseURL = "http://127.0.0.1:1"

		scan := client.CheckHash(context.Background(), testSHA256, nil)
		if scan.Status != "error" || scan.Error == "" {
			t.Errorf("Expected an error naming its cause, got %+v", scan)
		}
	})
}

// TestCheckUnknownIsNotUploadedWithoutContent: the upload takes the file, and
// a file too large for VirusTotal stays unknown rather than failing.
func TestCheckUnknownIsNotUploadedWithoutContent(t *testing.T) {
	uploads := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /files", func(w http.ResponseWriter, r *http.Request) {
		uploads++
		fmt.Fprint(w, `{"data":{"id":"analysis-123"}}`)
	})
	client := newTestClient(t, mux, true)

	for name, content := range map[string][]byte{
		"no content": nil,
		"too large":  make([]byte, maxUploadSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			scan := client.CheckHash(context.Background(), testSHA256, content)
			if scan.Status != "unknown" {
				t.Errorf("Expected status unknown, got %q", scan.Status)
			}
		})
	}
	if uploads != 0 {
		t.Errorf("Expected nothing to be uploaded, got %d upload(s)", uploads)
	}
}

// TestCheckUploadFails: an upload the API refuses is reported, with what the
// API said.
func TestCheckUploadFails(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"refused": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":{"code":"QuotaExceededError"}}`)
		},
		"garbled": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "not json")
		},
		"hung up": hangUp,
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})
			mux.HandleFunc("POST /files", handler)
			client := newTestClient(t, mux, true)

			scan := client.CheckHash(context.Background(), testSHA256, []byte("unknown file content"))
			if scan.Status != "error" || scan.Error == "" {
				t.Errorf("Expected the upload failure to be reported, got %+v", scan)
			}
		})
	}
}

// TestCheckPollRidesOutTransientFailures: a poll that fails is tried again,
// not taken for a verdict.
func TestCheckPollRidesOutTransientFailures(t *testing.T) {
	polls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /files", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"id":"analysis-flaky"}}`)
	})
	mux.HandleFunc("GET /analyses/analysis-flaky", func(w http.ResponseWriter, r *http.Request) {
		polls++
		switch polls {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case 2:
			hangUp(w, r)
			return
		}
		fmt.Fprint(w, `{"data":{"attributes":{"status":"completed","stats":{"malicious":0,"suspicious":0,"harmless":60,"undetected":5}}}}`)
	})

	client := newTestClient(t, mux, true)
	scan := client.CheckHash(context.Background(), testSHA256, []byte("unknown file content"))
	if scan.Status != "clean" {
		t.Errorf("Expected status clean once the poll answered, got %q (%s)", scan.Status, scan.Error)
	}
	if polls != 3 {
		t.Errorf("Expected the poll to be tried again after each failure, got %d poll(s)", polls)
	}
}

// TestCheckPollThatCannotBeRead: a poll answering something that is not an
// analysis ends the wait with an error rather than polling forever.
func TestCheckPollThatCannotBeRead(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /files", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"id":"analysis-garbled"}}`)
	})
	mux.HandleFunc("GET /analyses/analysis-garbled", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	})

	client := newTestClient(t, mux, true)
	scan := client.CheckHash(context.Background(), testSHA256, []byte("unknown file content"))
	if scan.Status != "error" || scan.Error == "" {
		t.Errorf("Expected the garbled analysis to be reported, got %+v", scan)
	}
}

// hangUp closes the connection without answering, the way a server that fell
// over mid-request does.
func hangUp(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	conn.Close()
}
