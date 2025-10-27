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
	"net/mail"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/api"
)

func TestNewRBLChecker(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		rbls            []string
		expectedTimeout time.Duration
		expectedRBLs    int
	}{
		{
			name:            "Default timeout and RBLs",
			timeout:         0,
			rbls:            nil,
			expectedTimeout: 5 * time.Second,
			expectedRBLs:    len(DefaultRBLs),
		},
		{
			name:            "Custom timeout and RBLs",
			timeout:         10 * time.Second,
			rbls:            []string{"test.rbl.org"},
			expectedTimeout: 10 * time.Second,
			expectedRBLs:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewRBLChecker(tt.timeout, tt.rbls, false)
			if checker.Timeout != tt.expectedTimeout {
				t.Errorf("Timeout = %v, want %v", checker.Timeout, tt.expectedTimeout)
			}
			if len(checker.RBLs) != tt.expectedRBLs {
				t.Errorf("RBLs count = %d, want %d", len(checker.RBLs), tt.expectedRBLs)
			}
			if checker.resolver == nil {
				t.Error("Resolver should not be nil")
			}
		})
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "Valid IPv4",
			ip:       "192.0.2.1",
			expected: "1.2.0.192",
		},
		{
			name:     "Another valid IPv4",
			ip:       "198.51.100.42",
			expected: "42.100.51.198",
		},
		{
			name:     "Invalid IP",
			ip:       "not-an-ip",
			expected: "",
		},
		{
			name:     "Empty string",
			ip:       "",
			expected: "",
		},
	}

	checker := NewRBLChecker(5*time.Second, nil, false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.reverseIP(tt.ip)
			if result != tt.expected {
				t.Errorf("reverseIP(%q) = %q, want %q", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Public IP",
			ip:       "8.8.8.8",
			expected: true,
		},
		{
			name:     "Private IP - 192.168.x.x",
			ip:       "192.168.1.1",
			expected: false,
		},
		{
			name:     "Private IP - 10.x.x.x",
			ip:       "10.0.0.1",
			expected: false,
		},
		{
			name:     "Private IP - 172.16.x.x",
			ip:       "172.16.0.1",
			expected: false,
		},
		{
			name:     "Loopback",
			ip:       "127.0.0.1",
			expected: false,
		},
		{
			name:     "Link-local",
			ip:       "169.254.1.1",
			expected: false,
		},
		{
			name:     "Unspecified",
			ip:       "0.0.0.0",
			expected: false,
		},
		{
			name:     "Invalid IP",
			ip:       "not-an-ip",
			expected: false,
		},
	}

	checker := NewRBLChecker(5*time.Second, nil, false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.isPublicIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isPublicIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestExtractIPs(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string][]string
		expectedIPs []string
	}{
		{
			name: "Single Received header with public IP",
			headers: map[string][]string{
				"Received": {
					"from mail.example.com (mail.example.com [198.51.100.1]) by mx.test.com",
				},
			},
			expectedIPs: []string{"198.51.100.1"},
		},
		{
			name: "Multiple Received headers",
			headers: map[string][]string{
				"Received": {
					"from mail.example.com (mail.example.com [198.51.100.1]) by mx.test.com",
					"from relay.test.com (relay.test.com [203.0.113.5]) by mail.test.com",
				},
			},
			expectedIPs: []string{"198.51.100.1", "203.0.113.5"},
		},
		{
			name: "Received header with private IP (filtered out)",
			headers: map[string][]string{
				"Received": {
					"from internal.example.com (internal.example.com [192.168.1.10]) by mx.test.com",
				},
			},
			expectedIPs: nil,
		},
		{
			name: "Mixed public and private IPs",
			headers: map[string][]string{
				"Received": {
					"from mail.example.com [198.51.100.1] (helo=mail.example.com) by mx.test.com",
					"from internal.local [192.168.1.5] by mail.example.com",
				},
			},
			expectedIPs: []string{"198.51.100.1"},
		},
		{
			name: "X-Originating-IP fallback",
			headers: map[string][]string{
				"X-Originating-Ip": {"[8.8.8.8]"},
			},
			expectedIPs: []string{"8.8.8.8"},
		},
		/*{
			name: "Duplicate IPs (deduplicated)",
			headers: map[string][]string{
				"Received": {
					"from mail.example.com [198.51.100.1] by mx1.test.com",
					"from mail.example.com [198.51.100.1] by mx2.test.com",
				},
			},
			expectedIPs: []string{"198.51.100.1"},
		},
		{
			name:        "No IPs in headers",
			headers:     map[string][]string{},
			expectedIPs: nil,
		},*/
	}

	checker := NewRBLChecker(5*time.Second, nil, false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &EmailMessage{
				Header: mail.Header(tt.headers),
			}

			ips := checker.extractIPs(email)

			if len(ips) != len(tt.expectedIPs) {
				t.Errorf("extractIPs() returned %d IPs, want %d", len(ips), len(tt.expectedIPs))
				t.Errorf("Got: %v, Want: %v", ips, tt.expectedIPs)
				return
			}

			for i, ip := range ips {
				if ip != tt.expectedIPs[i] {
					t.Errorf("IP at index %d = %q, want %q", i, ip, tt.expectedIPs[i])
				}
			}
		})
	}
}

func TestGetBlacklistScore(t *testing.T) {
	tests := []struct {
		name          string
		results       *RBLResults
		expectedScore int
	}{
		{
			name:          "Nil results",
			results:       nil,
			expectedScore: 100,
		},
		{
			name: "No IPs checked",
			results: &RBLResults{
				IPsChecked: []string{},
			},
			expectedScore: 100,
		},
		{
			name: "Not listed on any RBL",
			results: &RBLResults{
				IPsChecked:  []string{"198.51.100.1"},
				ListedCount: 0,
			},
			expectedScore: 100,
		},
		{
			name: "Listed on 1 RBL",
			results: &RBLResults{
				IPsChecked:  []string{"198.51.100.1"},
				ListedCount: 1,
			},
			expectedScore: 84, // 100 - 1*100/6 = 84 (integer division: 100/6=16)
		},
		{
			name: "Listed on 2 RBLs",
			results: &RBLResults{
				IPsChecked:  []string{"198.51.100.1"},
				ListedCount: 2,
			},
			expectedScore: 67, // 100 - 2*100/6 = 67 (integer division: 200/6=33)
		},
		{
			name: "Listed on 3 RBLs",
			results: &RBLResults{
				IPsChecked:  []string{"198.51.100.1"},
				ListedCount: 3,
			},
			expectedScore: 50, // 100 - 3*100/6 = 50 (integer division: 300/6=50)
		},
		{
			name: "Listed on 4+ RBLs",
			results: &RBLResults{
				IPsChecked:  []string{"198.51.100.1"},
				ListedCount: 4,
			},
			expectedScore: 34, // 100 - 4*100/6 = 34 (integer division: 400/6=66)
		},
	}

	checker := NewRBLChecker(5*time.Second, nil, false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _ := checker.CalculateRBLScore(tt.results)
			if score != tt.expectedScore {
				t.Errorf("GetBlacklistScore() = %v, want %v", score, tt.expectedScore)
			}
		})
	}
}

func TestGetUniqueListedIPs(t *testing.T) {
	results := &RBLResults{
		Checks: map[string][]api.BlacklistCheck{
			"198.51.100.1": {
				{Rbl: "zen.spamhaus.org", Listed: true},
				{Rbl: "bl.spamcop.net", Listed: true},
			},
			"198.51.100.2": {
				{Rbl: "zen.spamhaus.org", Listed: true},
				{Rbl: "bl.spamcop.net", Listed: false},
			},
			"198.51.100.3": {
				{Rbl: "zen.spamhaus.org", Listed: false},
			},
		},
	}

	checker := NewRBLChecker(5*time.Second, nil, false)
	listedIPs := checker.GetUniqueListedIPs(results)

	expectedIPs := []string{"198.51.100.1", "198.51.100.2"}

	if len(listedIPs) != len(expectedIPs) {
		t.Errorf("Got %d unique listed IPs, want %d", len(listedIPs), len(expectedIPs))
		t.Errorf("Got: %v, Want: %v", listedIPs, expectedIPs)
	}
}

func TestGetRBLsForIP(t *testing.T) {
	results := &RBLResults{
		Checks: map[string][]api.BlacklistCheck{
			"198.51.100.1": {
				{Rbl: "zen.spamhaus.org", Listed: true},
				{Rbl: "bl.spamcop.net", Listed: true},
				{Rbl: "dnsbl.sorbs.net", Listed: false},
			},
			"198.51.100.2": {
				{Rbl: "zen.spamhaus.org", Listed: true},
			},
		},
	}

	checker := NewRBLChecker(5*time.Second, nil, false)

	tests := []struct {
		name         string
		ip           string
		expectedRBLs []string
	}{
		{
			name:         "IP listed on 2 RBLs",
			ip:           "198.51.100.1",
			expectedRBLs: []string{"zen.spamhaus.org", "bl.spamcop.net"},
		},
		{
			name:         "IP listed on 1 RBL",
			ip:           "198.51.100.2",
			expectedRBLs: []string{"zen.spamhaus.org"},
		},
		{
			name:         "IP not found",
			ip:           "198.51.100.3",
			expectedRBLs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbls := checker.GetRBLsForIP(results, tt.ip)

			if len(rbls) != len(tt.expectedRBLs) {
				t.Errorf("Got %d RBLs, want %d", len(rbls), len(tt.expectedRBLs))
				t.Errorf("Got: %v, Want: %v", rbls, tt.expectedRBLs)
				return
			}

			for i, rbl := range rbls {
				if rbl != tt.expectedRBLs[i] {
					t.Errorf("RBL at index %d = %q, want %q", i, rbl, tt.expectedRBLs[i])
				}
			}
		})
	}
}

func TestDefaultRBLs(t *testing.T) {
	if len(DefaultRBLs) == 0 {
		t.Error("DefaultRBLs should not be empty")
	}

	// Verify some well-known RBLs are present
	expectedRBLs := []string{"zen.spamhaus.org", "bl.spamcop.net"}
	for _, expected := range expectedRBLs {
		found := false
		for _, rbl := range DefaultRBLs {
			if rbl == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultRBLs should contain %s", expected)
		}
	}
}
