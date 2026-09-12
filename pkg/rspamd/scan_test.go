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

package rspamd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const sampleMessage = "From: sender@example.com\r\n" +
	"Subject: HELLO THERE\r\n" +
	"Content-Type: text/html\r\n" +
	"\r\n" +
	"<html><body><p>Hello</p></body></html>"

// submission is what the handler standing in for rspamd was sent. It is filled
// while Scan runs, so a test reads it once Scan has returned.
type submission struct {
	Request *http.Request
	Body    []byte
}

// scannerAgainst stands a scanner up in front of a handler pretending to be an
// rspamd controller, and reports what that handler was sent.
func scannerAgainst(t *testing.T, handler http.HandlerFunc) (*Scanner, *submission) {
	t.Helper()

	sent := &submission{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Body, _ = io.ReadAll(r.Body)
		sent.Request = r.Clone(r.Context())
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	scanner := NewScanner(server.URL, time.Second, nil)
	if scanner == nil {
		t.Fatal("no scanner was built for a configured URL")
	}

	return scanner, sent
}

func replyWith(t *testing.T, body string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("writing the reply: %v", err)
		}
	}
}

func TestScannerIsOffByDefault(t *testing.T) {
	for _, url := range []string{"", "   "} {
		if scanner := NewScanner(url, time.Second, nil); scanner != nil {
			t.Errorf("a scanner was built for the URL %q, want none", url)
		}
	}

	// And a nil scanner is usable, so no caller needs a branch of its own.
	var scanner *Scanner
	if result := scanner.Scan([]byte(sampleMessage)); result != nil {
		t.Error("a scanner that was never configured returned a result")
	}
}

func TestScannerSendsTheMessageAsItArrived(t *testing.T) {
	scanner, sent := scannerAgainst(t, replyWith(t, `{"score":0,"symbols":{}}`))

	scanner.Scan([]byte(sampleMessage))

	request := sent.Request
	if request == nil {
		t.Fatal("nothing was sent")
	}
	if request.Method != http.MethodPost {
		t.Errorf("sent a %s, want a POST", request.Method)
	}
	if request.URL.Path != "/checkv2" {
		t.Errorf("posted to %q, want /checkv2", request.URL.Path)
	}
	if got := request.Header.Get("Content-Type"); got != "message/rfc822" {
		t.Errorf("declared the body as %q, want message/rfc822", got)
	}
	// A length rather than a chunked body: some controller versions handle
	// chunked poorly.
	if request.ContentLength != int64(len(sampleMessage)) {
		t.Errorf("declared a length of %d, want %d", request.ContentLength, len(sampleMessage))
	}
	if string(sent.Body) != sampleMessage {
		t.Errorf("sent %q, want the message unchanged", string(sent.Body))
	}

	// Nothing about the connection is claimed: an uploaded file has none, and
	// inventing one is what the XCLIENT relay exists to avoid.
	for _, header := range []string{"IP", "Helo", "From", "Rcpt", "Hostname", "User"} {
		if value := request.Header.Get(header); value != "" {
			t.Errorf("claimed %s: %q, want no envelope at all", header, value)
		}
	}
}

func TestScannerReadsAReply(t *testing.T) {
	reply := `{
	  "is_skipped": false,
	  "score": 4.5,
	  "required_score": 15.0,
	  "action": "add header",
	  "symbols": {
	    "SUBJ_ALL_CAPS": {"name":"SUBJ_ALL_CAPS","score":3.0,"options":["HELLO THERE"],"description":"Subject contains mostly capital letters"},
	    "MIME_HTML_ONLY": {"name":"MIME_HTML_ONLY","score":0.2,"options":[]},
	    "R_SPF_NA": {"name":"R_SPF_NA","score":0.0,"options":["   "]}
	  }
	}`

	scanner, _ := scannerAgainst(t, replyWith(t, reply))

	result := scanner.Scan([]byte(sampleMessage))
	if result == nil {
		t.Fatal("a well-formed reply produced no result")
	}

	if result.Score != 4.5 {
		t.Errorf("read a score of %v, want 4.5", result.Score)
	}
	if result.Threshold == nil || *result.Threshold != 15 {
		t.Errorf("read a threshold of %v, want 15", result.Threshold)
	}
	if result.Action == nil || *result.Action != "add header" {
		t.Errorf("read the action %v, want \"add header\"", result.Action)
	}
	// "add header" is not a rejection, so the message is not spam by the
	// schema's own definition.
	if result.IsSpam {
		t.Error("an added header was read as a rejection")
	}
	if len(result.Symbols) != 3 {
		t.Fatalf("read %d symbol(s), want 3", len(result.Symbols))
	}

	caps := result.Symbols["SUBJ_ALL_CAPS"]
	if caps.Score != 3 {
		t.Errorf("SUBJ_ALL_CAPS scored %v, want 3", caps.Score)
	}
	if caps.Params == nil || *caps.Params != "HELLO THERE" {
		t.Errorf("SUBJ_ALL_CAPS carries the options %v, want \"HELLO THERE\"", caps.Params)
	}
	if caps.Description == nil || *caps.Description == "" {
		t.Error("SUBJ_ALL_CAPS lost the description the reply gave it")
	}

	// A symbol raised without options carries no location.
	if html := result.Symbols["MIME_HTML_ONLY"]; html.Params != nil {
		t.Errorf("MIME_HTML_ONLY carries the options %q, want none", *html.Params)
	}
	// Nor does one whose options are blank.
	if spf := result.Symbols["R_SPF_NA"]; spf.Params != nil {
		t.Errorf("R_SPF_NA carries the options %q, want none", *spf.Params)
	}
}

func TestScannerJoinsSeveralOptions(t *testing.T) {
	scanner, _ := scannerAgainst(t, replyWith(t,
		`{"symbols":{"DBL_PHISH":{"name":"DBL_PHISH","score":7.5,"options":["bad.example.com","dbl.spamhaus.org"]}}}`))

	result := scanner.Scan([]byte(sampleMessage))
	if result == nil {
		t.Fatal("no result")
	}

	// The header path parses "SYMBOL(score)[a,b]" into one string; joining the
	// list the same way keeps one shape for both paths.
	symbol := result.Symbols["DBL_PHISH"]
	if symbol.Params == nil || *symbol.Params != "bad.example.com, dbl.spamhaus.org" {
		t.Errorf("options came out as %v, want them joined", symbol.Params)
	}
}

func TestScannerFallsBackToTheCatalogue(t *testing.T) {
	server := httptest.NewServer(replyWith(t,
		`{"symbols":{"ZERO_FONT":{"name":"ZERO_FONT","score":1.0}}}`))
	t.Cleanup(server.Close)

	scanner := NewScanner(server.URL, time.Second, map[string]string{
		"ZERO_FONT": "Zero sized font used",
	})

	result := scanner.Scan([]byte(sampleMessage))
	if result == nil {
		t.Fatal("no result")
	}

	symbol := result.Symbols["ZERO_FONT"]
	if symbol.Description == nil || *symbol.Description != "Zero sized font used" {
		t.Errorf("described ZERO_FONT as %v, want the catalogue's description", symbol.Description)
	}
}

func TestScannerDegradesQuietly(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "a controller asking for a password",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				// Not JSON: it must not be parsed as a result.
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, "Unauthorized\n")
			},
		},
		{
			name: "a reply that is not a scan",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "<html>a proxy error page</html>")
			},
		},
		{
			name: "a server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "settings told rspamd to skip the message",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, `{"is_skipped":true,"score":0,"symbols":{}}`)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner, _ := scannerAgainst(t, test.handler)

			if result := scanner.Scan([]byte(sampleMessage)); result != nil {
				t.Errorf("produced a result anyway: %+v", result)
			}
		})
	}

	t.Run("a server that is not there", func(t *testing.T) {
		// A port nothing listens on: the reply never comes, and the report
		// still has to be produced.
		scanner := NewScanner("http://127.0.0.1:1", time.Second, nil)
		if result := scanner.Scan([]byte(sampleMessage)); result != nil {
			t.Errorf("produced a result without a server: %+v", result)
		}
	})

	t.Run("an empty message is not submitted", func(t *testing.T) {
		scanner, sent := scannerAgainst(t, replyWith(t, `{"symbols":{}}`))
		if result := scanner.Scan(nil); result != nil {
			t.Error("submitted nothing and got a result")
		}
		if sent.Request != nil {
			t.Error("an empty message was submitted anyway")
		}
	})
}

// TestScannerThrottlesItsComplaints covers the log, because every upload
// triggers a scan: an rspamd that has been down for an hour must not have
// written a line per analysis.
func TestScannerThrottlesItsComplaints(t *testing.T) {
	scanner := NewScanner("http://127.0.0.1:1", 50*time.Millisecond, nil)

	var logged int
	for range 5 {
		before := scanner.suppressed
		scanner.Scan([]byte(sampleMessage))
		if scanner.suppressed == before {
			logged++
		}
	}

	if logged != 1 {
		t.Errorf("wrote %d log line(s) for five identical failures, want 1", logged)
	}
	if scanner.suppressed != 4 {
		t.Errorf("counted %d suppressed failure(s), want 4", scanner.suppressed)
	}

	// A different failure is worth a line of its own straight away, rather
	// than waiting out the interval behind an unrelated one.
	scanner.logFailure(io.ErrUnexpectedEOF)
	if scanner.suppressed != 0 {
		t.Errorf("a new kind of failure was suppressed: %d", scanner.suppressed)
	}
}
