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
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

func TestNewDNSAnalyzer(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "Default timeout",
			timeout:         0,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "Custom timeout",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewDNSAnalyzer(tt.timeout)
			if analyzer.Timeout != tt.expectedTimeout {
				t.Errorf("Timeout = %v, want %v", analyzer.Timeout, tt.expectedTimeout)
			}
			if analyzer.resolver == nil {
				t.Error("Resolver should not be nil")
			}
		})
	}
}

// TestCalculateDNSScoreExcludesPTRWithoutSenderIP checks that the PTR/FCrDNS check
// is left out of the weighted average (instead of counted as a 0/20 failure) when no
// sender IP could be recovered from the Received chain, e.g. for an uploaded EML.
func TestCalculateDNSScoreExcludesPTRWithoutSenderIP(t *testing.T) {
	analyzer := NewDNSAnalyzer(10 * time.Second)

	results := &model.DNSResults{
		FromDomain: "example.com",
		FromMxRecords: &[]model.MXRecord{
			{Host: "mx.example.com.", Priority: 10, Valid: true},
		},
		RpMxRecords: &[]model.MXRecord{
			{Host: "mx.example.com.", Priority: 10, Valid: true},
		},
		SpfRecords: &[]model.SPFRecord{
			{
				Domain:       utils.PtrTo("example.com"),
				Record:       utils.PtrTo("v=spf1 ip4:203.0.113.1 -all"),
				Valid:        true,
				AllQualifier: (*model.SPFRecordAllQualifier)(utils.PtrTo("-")),
			},
		},
		DkimRecords: &[]model.DKIMRecord{
			{
				Domain:           "example.com",
				Selector:         "s1",
				Valid:            true,
				KeyType:          utils.PtrTo("rsa"),
				KeySize:          utils.PtrTo(2048),
				SigningAlgorithm: utils.PtrTo("rsa-sha256"),
			},
		},
		DmarcRecord: &model.DMARCRecord{
			Valid:         true,
			Policy:        (*model.DMARCRecordPolicy)(utils.PtrTo("quarantine")),
			SpfAlignment:  (*model.DMARCRecordSpfAlignment)(utils.PtrTo("relaxed")),
			DkimAlignment: (*model.DMARCRecordDkimAlignment)(utils.PtrTo("relaxed")),
		},
	}

	scoreWithoutIP, gradeWithoutIP := analyzer.CalculateDNSScore(results, "")
	if scoreWithoutIP != 95 {
		t.Errorf("score without sender IP = %d, want 95 (PTR excluded from average)", scoreWithoutIP)
	}
	if gradeWithoutIP != "A" {
		t.Errorf("grade without sender IP = %q, want %q", gradeWithoutIP, "A")
	}

	// With a sender IP but no PTR record resolved, PTR genuinely failed and must
	// still count as a 0/20 in the average.
	scoreWithIP, gradeWithIP := analyzer.CalculateDNSScore(results, "203.0.113.1")
	if scoreWithIP >= scoreWithoutIP {
		t.Errorf("score with sender IP and no PTR record = %d, want less than %d (unexcused PTR failure)", scoreWithIP, scoreWithoutIP)
	}
	if gradeWithIP != "C" {
		t.Errorf("grade with sender IP and no PTR record = %q, want %q", gradeWithIP, "C")
	}
}
