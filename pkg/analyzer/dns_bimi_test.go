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
	"strings"
	"testing"
)

// Record parsing and asset validation are covered by the reusable pkg/bimi
// package. These tests exercise the analyzer adapter: DNS lookup wiring and
// the mapping of *bimi.Record onto the API *model.BIMIRecord.

func TestCheckBIMIRecordLookup(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		txt          map[string][]string
		wantValid    bool
		wantLogoURL  string
		wantVMCURL   string
		wantErrSubst string
	}{
		{
			name:   "no BIMI record published",
			domain: "example.com",
			txt:    map[string][]string{},
			// _bimi lookup returns NXDOMAIN via the mock resolver
			wantValid:    false,
			wantErrSubst: "Failed to lookup BIMI record",
		},
		{
			name:   "malformed record (missing version)",
			domain: "example.com",
			txt: map[string][]string{
				"default._bimi.example.com": {"l=https://example.com/logo.svg"},
			},
			wantValid:    false,
			wantLogoURL:  "https://example.com/logo.svg",
			wantErrSubst: "v=BIMI1",
		},
		{
			name:   "declination record is syntactically valid",
			domain: "example.com",
			txt: map[string][]string{
				"default._bimi.example.com": {"v=BIMI1; l=;"},
			},
			// No assets to fetch: all checks skipped, record stays valid.
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := newMockAnalyzer(tt.txt, nil)
			rec := analyzer.checkBIMIRecord(tt.domain, "default")

			if rec.Valid != tt.wantValid {
				errStr := ""
				if rec.Error != nil {
					errStr = *rec.Error
				}
				t.Errorf("Valid = %t, want %t (error: %q)", rec.Valid, tt.wantValid, errStr)
			}
			if tt.wantLogoURL != "" {
				if rec.LogoUrl == nil || *rec.LogoUrl != tt.wantLogoURL {
					t.Errorf("LogoUrl = %v, want %q", rec.LogoUrl, tt.wantLogoURL)
				}
			}
			if tt.wantVMCURL != "" {
				if rec.VmcUrl == nil || *rec.VmcUrl != tt.wantVMCURL {
					t.Errorf("VmcUrl = %v, want %q", rec.VmcUrl, tt.wantVMCURL)
				}
			}
			if tt.wantErrSubst != "" {
				if rec.Error == nil || !strings.Contains(*rec.Error, tt.wantErrSubst) {
					t.Errorf("Error = %v, want substring %q", rec.Error, tt.wantErrSubst)
				}
			}
		})
	}
}
