// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

func TestParseDMARCReportURI(t *testing.T) {
	for uri, want := range map[string]string{
		"mailto:dmarc@example.com":         "example.com",
		"MAILTO:dmarc@Example.COM!10m":     "example.com",
		"mailto:d%2Bx@reports.example.net": "reports.example.net",
		"https://example.com/report":       "",
		"dmarc@example.com":                "",
		"mailto:example.com":               "",
		"mailto:dmarc@localhost":           "",
		"mailto:dmarc@exa mple.com":        "",
	} {
		got, err := parseDMARCReportURI(uri)
		if want == "" && err == nil {
			t.Errorf("%q: accepted as %q, want an error", uri, got)
		}
		if want != "" && got != want {
			t.Errorf("%q: domain = %q (%v), want %q", uri, got, err, want)
		}
	}
}

func TestDMARCReportDestinations(t *testing.T) {
	f := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com":                        {"v=DMARC1; p=reject; rua=mailto:agg@example.com,mailto:agg@ok.example.net; ruf=mailto:fail@nope.example.org,bad.example,https://reports.example.org/dmarc"},
		"example.com._report._dmarc.ok.example.net": {"v=DMARC1"},
	}}
	d := newFakeAnalyzer(f)
	rec := d.checkDMARCRecord("example.com")
	if len(deref(rec.Rua)) != 2 || len(deref(rec.Ruf)) != 3 {
		t.Fatalf("rua = %v, ruf = %v", deref(rec.Rua), deref(rec.Ruf))
	}
	byURI := map[string]model.DMARCReportDestination{}
	for _, dest := range deref(rec.ReportAuthorizations) {
		byURI[dest.Uri] = dest
	}
	if dest := byURI["mailto:agg@example.com"]; !dest.Valid || utils.Deref(dest.External) || dest.Authorized != nil {
		t.Errorf("own destination = %+v, want valid, internal, needing no authorization", dest)
	}
	if dest := byURI["mailto:agg@ok.example.net"]; !utils.Deref(dest.External) || !utils.Deref(dest.Authorized) {
		t.Errorf("authorized destination = %+v", dest)
	}
	if dest := byURI["mailto:fail@nope.example.org"]; !utils.Deref(dest.External) || utils.Deref(dest.Authorized) {
		t.Errorf("unauthorized destination = %+v", dest)
	}
	if dest := byURI["bad.example"]; dest.Valid || dest.Error == nil {
		t.Errorf("destination without scheme = %+v, want invalid", dest)
	}
	if dest := byURI["https://reports.example.org/dmarc"]; !dest.Valid || dest.Domain != nil || dest.Authorized != nil {
		t.Errorf("https destination = %+v, want valid, with no consent to check", dest)
	}

	score, issues := d.calculateDMARCScore(&model.DNSResults{FromDomain: "example.com", DmarcRecord: rec})
	if hasIssue(issues, model.IssueTypeDmarcReportUriInvalid) == nil || hasIssue(issues, model.IssueTypeDmarcReportUnauthorized) == nil || hasIssue(issues, model.IssueTypeDmarcNoRua) != nil {
		t.Errorf("issues = %v", issueTypes(issues))
	}
	if score != 105-5 {
		t.Errorf("score = %d, want %d: only the unauthorized destination costs", score, 105-5)
	}
}

func TestDMARCNoRua(t *testing.T) {
	d := newFakeAnalyzer(&fakeResolver{txt: map[string][]string{"_dmarc.example.com": {"v=DMARC1; p=reject"}}})
	rec := d.checkDMARCRecord("example.com")
	_, issues := d.calculateDMARCScore(&model.DNSResults{FromDomain: "example.com", DmarcRecord: rec})
	issue := hasIssue(issues, model.IssueTypeDmarcNoRua)
	if issue == nil || issue.Severity != model.IssueSeverityLow || *issue.Penalty != 0 {
		t.Errorf("issues = %+v, want a free low dmarc_no_rua", issues)
	}
}
