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

const returnMXHeader = "receiver.example; spf=pass smtp.mailfrom=bounce@rsend.example.com; " +
	"dkim=pass header.d=example.com; dmarc=pass header.from=example.com; " +
	"x-return-mx=pass smtp.domain=rsend.example.com policy.org_domain=example.com policy.is_org=no (MX Records found: feedback-smtp.example.net); " +
	"x-return-mx=warn header.domain=example.com policy.is_org=yes policy.mx_error=NOERROR (A Records found: 192.0.2.1) (AAAA Records found: 2001:db8::1)"

func TestParseXReturnMXResults(t *testing.T) {
	a := NewAuthenticationAnalyzer("receiver.example")
	results := &model.AuthenticationResults{}
	a.parseAuthenticationResultsHeader(returnMXHeader, results)

	if results.XReturnMx == nil || len(*results.XReturnMx) != 2 {
		t.Fatalf("x_return_mx = %v, want two verdicts", results.XReturnMx)
	}
	smtp, header := (*results.XReturnMx)[0], (*results.XReturnMx)[1]

	if smtp.Result != model.XReturnMXResultResultPass || !equalStrPtr(smtp.Domain, utils.PtrTo("rsend.example.com")) ||
		smtp.Identity == nil || *smtp.Identity != model.XReturnMXResultIdentitySmtp ||
		!equalStrPtr(smtp.OrgDomain, utils.PtrTo("example.com")) || smtp.IsOrg == nil || *smtp.IsOrg {
		t.Errorf("envelope verdict = %+v", smtp)
	}
	if header.Result != model.XReturnMXResultResultWarn || !equalStrPtr(header.Domain, utils.PtrTo("example.com")) ||
		header.Identity == nil || *header.Identity != model.XReturnMXResultIdentityHeader ||
		header.OrgDomain != nil || header.IsOrg == nil || !*header.IsOrg {
		t.Errorf("From verdict = %+v", header)
	}
	if header.Details == nil || *header.Details == "" {
		t.Errorf("details = %v, want the method as written", header.Details)
	}

	// The verdicts of a lower header do not mix with those of the topmost one
	a.parseAuthenticationResultsHeader("other.example; x-return-mx=fail header.domain=example.org", results)
	if len(*results.XReturnMx) != 2 {
		t.Errorf("x_return_mx = %v, want the topmost header's only", *results.XReturnMx)
	}
}

// The DNS section scores whether the sender domains can receive mail: the
// receiver's verdict on it is shown, not charged a second time.
func TestXReturnMXIsNotScored(t *testing.T) {
	a := NewAuthenticationAnalyzer("receiver.example")

	with := &model.AuthenticationResults{}
	a.parseAuthenticationResultsHeader(returnMXHeader, with)
	without := &model.AuthenticationResults{Spf: with.Spf, Dkim: with.Dkim, Dmarc: with.Dmarc}

	scoreWith, _ := a.CalculateAuthenticationScore(with, nil)
	scoreWithout, _ := a.CalculateAuthenticationScore(without, nil)
	if scoreWith != scoreWithout {
		t.Errorf("score = %d with x-return-mx, %d without, want the same", scoreWith, scoreWithout)
	}
}
