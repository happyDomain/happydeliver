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

package attachment

import (
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

// TestAnalysisCarriesEverythingTheEnginesSaid holds the report to dropping
// nothing: each field an engine filled is shown, each one it left empty is
// left out rather than shown as an empty string, and a reading that did not
// happen leaves no analysis behind.
func TestAnalysisCarriesEverythingTheEnginesSaid(t *testing.T) {
	analyzer := newOfflineAnalyzer()

	if analyzer.Analysis(nil, nil) != nil {
		t.Error("Expected no analysis of a reading that did not happen")
	}

	results := &Results{Attachments: []Attachment{{
		SHA256: "abc123",
		Size:   6,
		Inline: true,
		Scans: []Scan{
			{
				Scanner:        "virustotal",
				Status:         model.ScanResultStatusMalicious,
				Verdict:        "Trojan.Generic",
				EnginesFlagged: 51,
				EnginesTotal:   70,
				Link:           "https://www.virustotal.com/gui/file/abc123",
				Detail:         "known sample",
				Metadata:       map[string]string{"first_seen": "2026-01-01"},
			},
			{Scanner: "clamav", Status: model.ScanResultStatusDisabled},
		},
	}}}

	// A caller that observed without reading leaves the findings out.
	analysis := analyzer.Analysis(results, nil)
	if !analysis.HasAttachments || analysis.Attachments == nil || len(*analysis.Attachments) != 1 {
		t.Fatalf("Expected one attachment in the analysis, got %+v", analysis)
	}

	check := (*analysis.Attachments)[0]
	if check.Filename != nil || check.DeclaredContentType != nil || check.DetectedContentType != nil {
		t.Errorf("Expected what the part did not say left out, got %+v", check)
	}
	if check.Inline == nil || !*check.Inline {
		t.Error("Expected the part reported as inline")
	}
	if check.Issues != nil {
		t.Errorf("Expected no findings from a reading that did not happen, got %+v", check.Issues)
	}
	if check.Scans == nil || len(*check.Scans) != 2 {
		t.Fatalf("Expected both scans carried over, got %+v", check.Scans)
	}

	full := (*check.Scans)[0]
	if full.Verdict == nil || *full.Verdict != "Trojan.Generic" {
		t.Errorf("Expected the verdict carried over, got %v", full.Verdict)
	}
	if full.EnginesFlagged == nil || *full.EnginesFlagged != 51 || full.EnginesTotal == nil || *full.EnginesTotal != 70 {
		t.Errorf("Expected the engine count carried over, got %v/%v", full.EnginesFlagged, full.EnginesTotal)
	}
	if full.Link == nil || *full.Link != "https://www.virustotal.com/gui/file/abc123" {
		t.Errorf("Expected the link carried over, got %v", full.Link)
	}
	if full.Detail == nil || *full.Detail != "known sample" {
		t.Errorf("Expected the detail carried over, got %v", full.Detail)
	}
	if full.Metadata == nil || (*full.Metadata)["first_seen"] != "2026-01-01" {
		t.Errorf("Expected the metadata carried over, got %v", full.Metadata)
	}

	empty := (*check.Scans)[1]
	if empty.Status != model.ScanResultStatusDisabled || empty.Verdict != nil || empty.EnginesTotal != nil || empty.Link != nil || empty.Detail != nil || empty.Metadata != nil {
		t.Errorf("Expected an engine that said nothing shown with nothing, got %+v", empty)
	}
}
