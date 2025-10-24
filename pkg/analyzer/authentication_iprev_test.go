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

	"git.happydns.org/happyDeliver/internal/api"
)

func TestParseIPRevResult(t *testing.T) {
	tests := []struct {
		name             string
		part             string
		expectedResult   api.IPRevResultResult
		expectedIP       *string
		expectedHostname *string
	}{
		{
			name:             "IPRev pass with IP and hostname",
			part:             "iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("195.110.101.58"),
			expectedHostname: api.PtrTo("authsmtp74.register.it"),
		},
		{
			name:             "IPRev pass without smtp prefix",
			part:             "iprev=pass remote-ip=192.0.2.1 (mail.example.com)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.1"),
			expectedHostname: api.PtrTo("mail.example.com"),
		},
		{
			name:             "IPRev fail",
			part:             "iprev=fail smtp.remote-ip=198.51.100.42 (unknown.host.com)",
			expectedResult:   api.Fail,
			expectedIP:       api.PtrTo("198.51.100.42"),
			expectedHostname: api.PtrTo("unknown.host.com"),
		},
		{
			name:             "IPRev temperror",
			part:             "iprev=temperror smtp.remote-ip=203.0.113.1",
			expectedResult:   api.Temperror,
			expectedIP:       api.PtrTo("203.0.113.1"),
			expectedHostname: nil,
		},
		{
			name:             "IPRev permerror",
			part:             "iprev=permerror smtp.remote-ip=192.0.2.100",
			expectedResult:   api.Permerror,
			expectedIP:       api.PtrTo("192.0.2.100"),
			expectedHostname: nil,
		},
		{
			name:             "IPRev with IPv6",
			part:             "iprev=pass smtp.remote-ip=2001:db8::1 (ipv6.example.com)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("2001:db8::1"),
			expectedHostname: api.PtrTo("ipv6.example.com"),
		},
		{
			name:             "IPRev with subdomain hostname",
			part:             "iprev=pass smtp.remote-ip=192.0.2.50 (mail.subdomain.example.com)",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.50"),
			expectedHostname: api.PtrTo("mail.subdomain.example.com"),
		},
		{
			name:             "IPRev pass without parentheses",
			part:             "iprev=pass smtp.remote-ip=192.0.2.200",
			expectedResult:   api.Pass,
			expectedIP:       api.PtrTo("192.0.2.200"),
			expectedHostname: nil,
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseIPRevResult(tt.part)

			// Check result
			if result.Result != tt.expectedResult {
				t.Errorf("Result = %v, want %v", result.Result, tt.expectedResult)
			}

			// Check IP
			if tt.expectedIP != nil {
				if result.Ip == nil {
					t.Errorf("IP = nil, want %v", *tt.expectedIP)
				} else if *result.Ip != *tt.expectedIP {
					t.Errorf("IP = %v, want %v", *result.Ip, *tt.expectedIP)
				}
			} else {
				if result.Ip != nil {
					t.Errorf("IP = %v, want nil", *result.Ip)
				}
			}

			// Check hostname
			if tt.expectedHostname != nil {
				if result.Hostname == nil {
					t.Errorf("Hostname = nil, want %v", *tt.expectedHostname)
				} else if *result.Hostname != *tt.expectedHostname {
					t.Errorf("Hostname = %v, want %v", *result.Hostname, *tt.expectedHostname)
				}
			} else {
				if result.Hostname != nil {
					t.Errorf("Hostname = %v, want nil", *result.Hostname)
				}
			}

			// Check details
			if result.Details == nil {
				t.Error("Expected Details to be set, got nil")
			}
		})
	}
}

func TestParseAuthenticationResultsHeader_IPRev(t *testing.T) {
	tests := []struct {
		name                string
		header              string
		expectedIPRevResult *api.IPRevResultResult
		expectedIP          *string
		expectedHostname    *string
	}{
		{
			name:                "IPRev pass in Authentication-Results",
			header:              "mx.google.com; iprev=pass smtp.remote-ip=195.110.101.58 (authsmtp74.register.it)",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("195.110.101.58"),
			expectedHostname:    api.PtrTo("authsmtp74.register.it"),
		},
		{
			name:                "IPRev with other authentication methods",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com; iprev=pass smtp.remote-ip=192.0.2.1 (mail.example.com); dkim=pass header.d=example.com",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("192.0.2.1"),
			expectedHostname:    api.PtrTo("mail.example.com"),
		},
		{
			name:                "IPRev fail",
			header:              "mx.google.com; iprev=fail smtp.remote-ip=198.51.100.42",
			expectedIPRevResult: api.PtrTo(api.Fail),
			expectedIP:          api.PtrTo("198.51.100.42"),
			expectedHostname:    nil,
		},
		{
			name:                "No IPRev in header",
			header:              "mx.google.com; spf=pass smtp.mailfrom=sender@example.com",
			expectedIPRevResult: nil,
		},
		{
			name:                "Multiple IPRev results - only first is parsed",
			header:              "mx.google.com; iprev=pass smtp.remote-ip=192.0.2.1 (first.com); iprev=fail smtp.remote-ip=192.0.2.2 (second.com)",
			expectedIPRevResult: api.PtrTo(api.Pass),
			expectedIP:          api.PtrTo("192.0.2.1"),
			expectedHostname:    api.PtrTo("first.com"),
		},
	}

	analyzer := NewAuthenticationAnalyzer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &api.AuthenticationResults{}
			analyzer.parseAuthenticationResultsHeader(tt.header, results)

			// Check IPRev
			if tt.expectedIPRevResult != nil {
				if results.Iprev == nil {
					t.Errorf("Expected IPRev result, got nil")
				} else {
					if results.Iprev.Result != *tt.expectedIPRevResult {
						t.Errorf("IPRev Result = %v, want %v", results.Iprev.Result, *tt.expectedIPRevResult)
					}
					if tt.expectedIP != nil {
						if results.Iprev.Ip == nil || *results.Iprev.Ip != *tt.expectedIP {
							var gotIP string
							if results.Iprev.Ip != nil {
								gotIP = *results.Iprev.Ip
							}
							t.Errorf("IPRev IP = %v, want %v", gotIP, *tt.expectedIP)
						}
					}
					if tt.expectedHostname != nil {
						if results.Iprev.Hostname == nil || *results.Iprev.Hostname != *tt.expectedHostname {
							var gotHostname string
							if results.Iprev.Hostname != nil {
								gotHostname = *results.Iprev.Hostname
							}
							t.Errorf("IPRev Hostname = %v, want %v", gotHostname, *tt.expectedHostname)
						}
					}
				}
			} else {
				if results.Iprev != nil {
					t.Errorf("Expected no IPRev result, got %+v", results.Iprev)
				}
			}
		})
	}
}
