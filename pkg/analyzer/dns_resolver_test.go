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
	"testing"
)

func TestIsDNSSECEnabled(t *testing.T) {
	resolver := NewStandardDNSResolver()
	ctx := context.Background()

	tests := []struct {
		name         string
		domain       string
		expectDNSSEC bool
	}{
		{
			name:         "ietf.org has DNSSEC",
			domain:       "ietf.org",
			expectDNSSEC: true,
		},
		{
			name:         "google.com doesn't have DNSSEC",
			domain:       "google.com",
			expectDNSSEC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, err := resolver.IsDNSSECEnabled(ctx, tt.domain)
			if err != nil {
				t.Errorf("IsDNSSECEnabled() error = %v", err)
				return
			}

			if enabled != tt.expectDNSSEC {
				t.Errorf("IsDNSSECEnabled() for %s = %v, want %v", tt.domain, enabled, tt.expectDNSSEC)
			} else {
				// Log the result even if we're not validating
				if enabled {
					t.Logf("%s: DNSSEC is enabled ✅", tt.domain)
				} else {
					t.Logf("%s: DNSSEC is NOT enabled ⚠️", tt.domain)
				}
			}
		})
	}
}

func TestIsDNSSECEnabled_NonExistentDomain(t *testing.T) {
	resolver := NewStandardDNSResolver()
	ctx := context.Background()

	// Test with a domain that doesn't exist
	enabled, err := resolver.IsDNSSECEnabled(ctx, "this-domain-definitely-does-not-exist-12345.com")
	if err != nil {
		// Error is acceptable for non-existent domains
		t.Logf("Non-existent domain returned error (expected): %v", err)
		return
	}

	// If no error, DNSSEC should be disabled
	if enabled {
		t.Error("IsDNSSECEnabled() for non-existent domain should return false")
	}
}

func TestIsDNSSECEnabled_WithTrailingDot(t *testing.T) {
	resolver := NewStandardDNSResolver()
	ctx := context.Background()

	// Test that both formats work
	domain1 := "cloudflare.com"
	domain2 := "cloudflare.com."

	enabled1, err1 := resolver.IsDNSSECEnabled(ctx, domain1)
	if err1 != nil {
		t.Errorf("IsDNSSECEnabled() without trailing dot error = %v", err1)
	}

	enabled2, err2 := resolver.IsDNSSECEnabled(ctx, domain2)
	if err2 != nil {
		t.Errorf("IsDNSSECEnabled() with trailing dot error = %v", err2)
	}

	if enabled1 != enabled2 {
		t.Errorf("IsDNSSECEnabled() results differ: without dot = %v, with dot = %v", enabled1, enabled2)
	}
}
