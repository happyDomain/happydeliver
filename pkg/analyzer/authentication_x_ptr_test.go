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
	"git.happydns.org/happyDeliver/internal/utils"
)

func TestParseXPtrResult(t *testing.T) {
	a := NewAuthenticationAnalyzer("receiver.com")

	tests := []struct {
		name           string
		part           string
		expectedResult model.XPtrResultResult
		expectedHelo   *string
		expectedPtr    *string
	}{
		{
			name:           "x-ptr fail with helo and ptr",
			part:           "x-ptr=fail smtp.helo=relay.example.org policy.ptr=mail.example.com",
			expectedResult: model.XPtrResultResultFail,
			expectedHelo:   utils.PtrTo("relay.example.org"),
			expectedPtr:    utils.PtrTo("mail.example.com"),
		},
		{
			name:           "x-ptr pass",
			part:           "x-ptr=pass smtp.helo=mail.example.com policy.ptr=mail.example.com",
			expectedResult: model.XPtrResultResultPass,
			expectedHelo:   utils.PtrTo("mail.example.com"),
			expectedPtr:    utils.PtrTo("mail.example.com"),
		},
		{
			name:           "x-ptr none without ptr",
			part:           "x-ptr=none smtp.helo=relay.example.org",
			expectedResult: model.XPtrResultResultNone,
			expectedHelo:   utils.PtrTo("relay.example.org"),
			expectedPtr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.parseXPtrResult(tt.part)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Result != tt.expectedResult {
				t.Errorf("Result = %q, want %q", result.Result, tt.expectedResult)
			}
			if !equalStrPtr(result.Helo, tt.expectedHelo) {
				t.Errorf("Helo = %v, want %v", result.Helo, tt.expectedHelo)
			}
			if !equalStrPtr(result.Ptr, tt.expectedPtr) {
				t.Errorf("Ptr = %v, want %v", result.Ptr, tt.expectedPtr)
			}
		})
	}
}
