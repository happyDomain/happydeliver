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

package analyzer

import (
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
)

func TestCheckHeloPtrMatch(t *testing.T) {
	tests := []struct {
		name       string
		helo       string
		ptrRecords []string
		want       bool
	}{
		{"exact match", "mail.example.com", []string{"mail.example.com"}, true},
		{"case insensitive", "Mail.Example.COM", []string{"mail.example.com"}, true},
		{"trailing dot ignored", "mail.example.com.", []string{"mail.example.com"}, true},
		{"mismatch", "relay.example.org", []string{"mail.example.com"}, false},
		{"match among several", "smtp.example.com", []string{"mail.example.com", "smtp.example.com"}, true},
		{"empty helo", "", []string{"mail.example.com"}, false},
		{"no ptr records", "mail.example.com", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkHeloPtrMatch(tt.helo, tt.ptrRecords); got != tt.want {
				t.Errorf("checkHeloPtrMatch(%q, %v) = %v, want %v", tt.helo, tt.ptrRecords, got, tt.want)
			}
		})
	}
}

func TestCalculatePTRScoreHeloMismatch(t *testing.T) {
	d := NewDNSAnalyzer(0)
	senderIP := "80.67.179.207"
	ptr := []string{"mail.example.com"}
	forward := []string{senderIP}

	matchTrue := true
	matchFalse := false

	tests := []struct {
		name    string
		results *model.DNSResults
		want    int
	}{
		{
			name: "helo matches ptr - no penalty (PTR+FCrDNS)",
			results: &model.DNSResults{
				PtrRecords:        &ptr,
				PtrForwardRecords: &forward,
				HeloPtrMatch:      &matchTrue,
			},
			want: 100,
		},
		{
			name: "helo mismatch - 15 point penalty",
			results: &model.DNSResults{
				PtrRecords:        &ptr,
				PtrForwardRecords: &forward,
				HeloPtrMatch:      &matchFalse,
			},
			want: 85,
		},
		{
			name: "no helo info - no penalty",
			results: &model.DNSResults{
				PtrRecords:        &ptr,
				PtrForwardRecords: &forward,
			},
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.calculatePTRScore(tt.results, senderIP); got != tt.want {
				t.Errorf("calculatePTRScore() = %d, want %d", got, tt.want)
			}
		})
	}
}
