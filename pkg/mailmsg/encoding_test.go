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

package mailmsg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// collectContent flattens a Part tree into the concatenation of every
// leaf part's (decoded) content, so a test can look for a marker regardless of
// how deeply the part is nested.
func collectContent(parts []Part) string {
	var sb strings.Builder
	for _, p := range parts {
		if len(p.Parts) > 0 {
			sb.WriteString(collectContent(p.Parts))
		}
		sb.WriteString(p.Content)
		sb.WriteString("\n")
	}
	return sb.String()
}

// TestBodyEncodingFixtures exercises the Content-Transfer-Encoding handling in
// the parser against the `test_email/*-encoding.eml` fixtures.
//
// For supported encodings we assert the readable marker appears *after*
// decoding. For unsupported encodings we assert the parser degrades
// gracefully: it never errors, and the raw (still-encoded) payload is passed
// through untouched — so the decoded marker must be absent and the raw marker
// present.
func TestBodyEncodingFixtures(t *testing.T) {
	tests := []struct {
		file string
		// wantPresent must appear in the flattened part content.
		wantPresent string
		// wantAbsent, if set, must NOT appear (used to confirm an unsupported
		// encoding was not silently mis-decoded).
		wantAbsent string
		// wantNoContent marks a fixture whose only part is not text: the
		// parser deliberately never reads such a body, so no content at all
		// is expected. wantPresent is then ignored.
		wantNoContent bool
		supported     bool
	}{
		// --- Supported: content must be decoded ---
		{file: "14-7bit-encoding.eml", wantPresent: "HAPPYDELIVER-DECODED-7BIT", supported: true},
		{file: "15-8bit-encoding.eml", wantPresent: "HAPPYDELIVER-DECODED-8BIT", supported: true},
		{file: "16-binary-encoding.eml", wantPresent: "HAPPYDELIVER-DECODED-BINARY", supported: true},
		{file: "17-base64-encoding.eml", wantPresent: "HAPPYDELIVER-DECODED-BASE64", wantAbsent: "SEFQUFlE", supported: true},

		// --- Unsupported: payload must pass through raw, never crash ---
		// uuencode is not a MIME transfer encoding: go-message does not decode
		// it, so the "begin 644" envelope reaches the report as-is.
		{file: "18-uuencode-encoding.eml", wantPresent: "begin 644", supported: false},
		{file: "19-yenc-encoding.eml", wantPresent: "NOT-DECODED-YENC-RAW", supported: false},
		// application/mac-binhex40 is not a text part: the parser must not
		// error out on it, and must not have spent anything decoding it.
		{file: "20-binhex-encoding.eml", wantNoContent: true, supported: false},
		{file: "21-unknown-encoding.eml", wantPresent: "NOT-DECODED-UNKNOWN-RAW", supported: false},
	}

	dir := filepath.Join("..", "..", "test_email")

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			email, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse returned error (parser must never fail on this fixture): %v", err)
			}

			content := collectContent(email.Parts)

			if tc.wantNoContent {
				if strings.TrimSpace(content) != "" {
					t.Errorf("expected no content for a non-text part, got:\n%s", content)
				}
				return
			}

			if !strings.Contains(content, tc.wantPresent) {
				t.Errorf("expected marker %q in decoded content, got:\n%s", tc.wantPresent, content)
			}
			if tc.wantAbsent != "" && strings.Contains(content, tc.wantAbsent) {
				t.Errorf("did not expect encoded artifact %q to survive in content:\n%s", tc.wantAbsent, content)
			}
		})
	}
}
