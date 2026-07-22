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

package model

import "testing"

// enumValidCase pairs an enum type name with the full set of its known-valid
// members. Each member is stored via a boolean accessor so the table can hold
// values of many distinct enum types.
type enumValidCase struct {
	name  string
	valid []func() bool
}

// TestEnumValidKnownMembers asserts that every generated enum constant is
// reported as a valid member by its Valid() method. This exercises each case
// arm of the generated switch statements.
func TestEnumValidKnownMembers(t *testing.T) {
	cases := []enumValidCase{
		{"ARCResultResult", []func() bool{
			ARCResultResultFail.Valid, ARCResultResultNone.Valid, ARCResultResultPass.Valid,
		}},
		{"AuthResultResult", []func() bool{
			AuthResultResultDeclined.Valid, AuthResultResultDomainPass.Valid, AuthResultResultFail.Valid,
			AuthResultResultInvalid.Valid, AuthResultResultMissing.Valid, AuthResultResultNeutral.Valid,
			AuthResultResultNone.Valid, AuthResultResultOrgdomainPass.Valid, AuthResultResultPass.Valid,
			AuthResultResultPermerror.Valid, AuthResultResultSkipped.Valid, AuthResultResultSoftfail.Valid,
			AuthResultResultTemperror.Valid,
		}},
		{"BIMICheckStatus", []func() bool{
			BIMICheckStatusFail.Valid, BIMICheckStatusPass.Valid, BIMICheckStatusSkipped.Valid,
			BIMICheckStatusWarning.Valid,
		}},
		{"BlacklistCheckResponseGrade", []func() bool{
			BlacklistCheckResponseGradeA.Valid, BlacklistCheckResponseGradeA1.Valid, BlacklistCheckResponseGradeB.Valid,
			BlacklistCheckResponseGradeC.Valid, BlacklistCheckResponseGradeD.Valid, BlacklistCheckResponseGradeE.Valid,
			BlacklistCheckResponseGradeF.Valid,
		}},
		{"ContentAnalysisUnsubscribeMethods", []func() bool{
			ContentAnalysisUnsubscribeMethodsLink.Valid, ContentAnalysisUnsubscribeMethodsListUnsubscribeHeader.Valid,
			ContentAnalysisUnsubscribeMethodsMailto.Valid, ContentAnalysisUnsubscribeMethodsOneClick.Valid,
		}},
		{"ContentIssueSeverity", []func() bool{
			ContentIssueSeverityCritical.Valid, ContentIssueSeverityHigh.Valid, ContentIssueSeverityInfo.Valid,
			ContentIssueSeverityLow.Valid, ContentIssueSeverityMedium.Valid,
		}},
		{"ContentIssueType", []func() bool{
			ContentIssueTypeBrokenHtml.Valid, ContentIssueTypeDangerousHtml.Valid, ContentIssueTypeExcessiveImages.Valid,
			ContentIssueTypeMissingAlt.Valid, ContentIssueTypeObfuscatedUrl.Valid, ContentIssueTypeSuspiciousLink.Valid,
			ContentIssueTypeUnreplacedTemplate.Valid,
		}},
		{"DKIMCheckStatus", []func() bool{
			DKIMCheckStatusFail.Valid, DKIMCheckStatusPass.Valid, DKIMCheckStatusSkipped.Valid,
			DKIMCheckStatusWarning.Valid,
		}},
		{"DMARCRecordDkimAlignment", []func() bool{
			DMARCRecordDkimAlignmentRelaxed.Valid, DMARCRecordDkimAlignmentStrict.Valid,
		}},
		{"DMARCRecordNonexistentSubdomainPolicy", []func() bool{
			DMARCRecordNonexistentSubdomainPolicyNone.Valid, DMARCRecordNonexistentSubdomainPolicyQuarantine.Valid,
			DMARCRecordNonexistentSubdomainPolicyReject.Valid, DMARCRecordNonexistentSubdomainPolicyUnknown.Valid,
		}},
		{"DMARCRecordPolicy", []func() bool{
			DMARCRecordPolicyNone.Valid, DMARCRecordPolicyQuarantine.Valid, DMARCRecordPolicyReject.Valid,
			DMARCRecordPolicyUnknown.Valid,
		}},
		{"DMARCRecordPsd", []func() bool{
			DMARCRecordPsdN.Valid, DMARCRecordPsdU.Valid, DMARCRecordPsdY.Valid,
		}},
		{"DMARCRecordSpfAlignment", []func() bool{
			DMARCRecordSpfAlignmentRelaxed.Valid, DMARCRecordSpfAlignmentStrict.Valid,
		}},
		{"DMARCRecordSubdomainPolicy", []func() bool{
			DMARCRecordSubdomainPolicyNone.Valid, DMARCRecordSubdomainPolicyQuarantine.Valid,
			DMARCRecordSubdomainPolicyReject.Valid, DMARCRecordSubdomainPolicyUnknown.Valid,
		}},
		{"DomainTestResponseGrade", []func() bool{
			DomainTestResponseGradeA.Valid, DomainTestResponseGradeA1.Valid, DomainTestResponseGradeB.Valid,
			DomainTestResponseGradeC.Valid, DomainTestResponseGradeD.Valid, DomainTestResponseGradeE.Valid,
			DomainTestResponseGradeF.Valid,
		}},
		{"HeaderCheckImportance", []func() bool{
			HeaderCheckImportanceNewsletter.Valid, HeaderCheckImportanceOptional.Valid,
			HeaderCheckImportanceRecommended.Valid, HeaderCheckImportanceRequired.Valid,
		}},
		{"HeaderIssueSeverity", []func() bool{
			HeaderIssueSeverityCritical.Valid, HeaderIssueSeverityHigh.Valid, HeaderIssueSeverityInfo.Valid,
			HeaderIssueSeverityLow.Valid, HeaderIssueSeverityMedium.Valid,
		}},
		{"IPRevResultResult", []func() bool{
			IPRevResultResultFail.Valid, IPRevResultResultPass.Valid, IPRevResultResultPermerror.Valid,
			IPRevResultResultTemperror.Valid,
		}},
		{"LinkCheckStatus", []func() bool{
			LinkCheckStatusBroken.Valid, LinkCheckStatusRedirected.Valid, LinkCheckStatusSuspicious.Valid,
			LinkCheckStatusTimeout.Valid, LinkCheckStatusValid.Valid,
		}},
		{"ReportGrade", []func() bool{
			ReportGradeA.Valid, ReportGradeA1.Valid, ReportGradeB.Valid, ReportGradeC.Valid,
			ReportGradeD.Valid, ReportGradeE.Valid, ReportGradeF.Valid,
		}},
		{"RspamdResultDeliverabilityGrade", []func() bool{
			RspamdResultDeliverabilityGradeA.Valid, RspamdResultDeliverabilityGradeA1.Valid, RspamdResultDeliverabilityGradeB.Valid,
			RspamdResultDeliverabilityGradeC.Valid, RspamdResultDeliverabilityGradeD.Valid, RspamdResultDeliverabilityGradeE.Valid,
			RspamdResultDeliverabilityGradeF.Valid,
		}},
		{"SPFCheckStatus", []func() bool{
			SPFCheckStatusFail.Valid, SPFCheckStatusPass.Valid, SPFCheckStatusSkipped.Valid,
			SPFCheckStatusWarning.Valid,
		}},
		{"SPFRecordAllQualifier", []func() bool{
			SPFRecordAllQualifierEmpty.Valid, SPFRecordAllQualifierMinus.Valid, SPFRecordAllQualifierPlus.Valid,
			SPFRecordAllQualifierTilde.Valid,
		}},
		{"ScoreSummaryAuthenticationGrade", []func() bool{
			ScoreSummaryAuthenticationGradeA.Valid, ScoreSummaryAuthenticationGradeA1.Valid, ScoreSummaryAuthenticationGradeB.Valid,
			ScoreSummaryAuthenticationGradeC.Valid, ScoreSummaryAuthenticationGradeD.Valid, ScoreSummaryAuthenticationGradeE.Valid,
			ScoreSummaryAuthenticationGradeF.Valid,
		}},
		{"ScoreSummaryBlacklistGrade", []func() bool{
			ScoreSummaryBlacklistGradeA.Valid, ScoreSummaryBlacklistGradeA1.Valid, ScoreSummaryBlacklistGradeB.Valid,
			ScoreSummaryBlacklistGradeC.Valid, ScoreSummaryBlacklistGradeD.Valid, ScoreSummaryBlacklistGradeE.Valid,
			ScoreSummaryBlacklistGradeF.Valid,
		}},
		{"ScoreSummaryContentGrade", []func() bool{
			ScoreSummaryContentGradeA.Valid, ScoreSummaryContentGradeA1.Valid, ScoreSummaryContentGradeB.Valid,
			ScoreSummaryContentGradeC.Valid, ScoreSummaryContentGradeD.Valid, ScoreSummaryContentGradeE.Valid,
			ScoreSummaryContentGradeF.Valid,
		}},
		{"ScoreSummaryDnsGrade", []func() bool{
			ScoreSummaryDnsGradeA.Valid, ScoreSummaryDnsGradeA1.Valid, ScoreSummaryDnsGradeB.Valid,
			ScoreSummaryDnsGradeC.Valid, ScoreSummaryDnsGradeD.Valid, ScoreSummaryDnsGradeE.Valid,
			ScoreSummaryDnsGradeF.Valid,
		}},
		{"ScoreSummaryHeaderGrade", []func() bool{
			ScoreSummaryHeaderGradeA.Valid, ScoreSummaryHeaderGradeA1.Valid, ScoreSummaryHeaderGradeB.Valid,
			ScoreSummaryHeaderGradeC.Valid, ScoreSummaryHeaderGradeD.Valid, ScoreSummaryHeaderGradeE.Valid,
			ScoreSummaryHeaderGradeF.Valid,
		}},
		{"ScoreSummarySpamGrade", []func() bool{
			ScoreSummarySpamGradeA.Valid, ScoreSummarySpamGradeA1.Valid, ScoreSummarySpamGradeB.Valid,
			ScoreSummarySpamGradeC.Valid, ScoreSummarySpamGradeD.Valid, ScoreSummarySpamGradeE.Valid,
			ScoreSummarySpamGradeF.Valid,
		}},
		{"SpamAssassinResultDeliverabilityGrade", []func() bool{
			SpamAssassinResultDeliverabilityGradeA.Valid, SpamAssassinResultDeliverabilityGradeA1.Valid, SpamAssassinResultDeliverabilityGradeB.Valid,
			SpamAssassinResultDeliverabilityGradeC.Valid, SpamAssassinResultDeliverabilityGradeD.Valid, SpamAssassinResultDeliverabilityGradeE.Valid,
			SpamAssassinResultDeliverabilityGradeF.Valid,
		}},
		{"StatusComponentsDatabase", []func() bool{
			StatusComponentsDatabaseDown.Valid, StatusComponentsDatabaseUp.Valid,
		}},
		{"StatusComponentsMta", []func() bool{
			StatusComponentsMtaDown.Valid, StatusComponentsMtaUp.Valid,
		}},
		{"StatusStatus", []func() bool{
			StatusStatusDegraded.Valid, StatusStatusHealthy.Valid, StatusStatusUnhealthy.Valid,
		}},
		{"TestStatus", []func() bool{
			TestStatusAnalyzed.Valid, TestStatusPending.Valid,
		}},
		{"TestResponseStatus", []func() bool{
			TestResponseStatusPending.Valid,
		}},
		{"TestSummaryGrade", []func() bool{
			TestSummaryGradeA.Valid, TestSummaryGradeA1.Valid, TestSummaryGradeB.Valid, TestSummaryGradeC.Valid,
			TestSummaryGradeD.Valid, TestSummaryGradeE.Valid, TestSummaryGradeF.Valid,
		}},
		{"XPtrResultResult", []func() bool{
			XPtrResultResultFail.Valid, XPtrResultResultNone.Valid, XPtrResultResultPass.Valid,
			XPtrResultResultPermerror.Valid, XPtrResultResultTemperror.Valid,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, valid := range tc.valid {
				if !valid() {
					t.Errorf("%s member #%d: Valid() = false, want true", tc.name, i)
				}
			}
		})
	}
}

// TestEnumValidRejectsUnknown asserts that the default branch of each generated
// Valid() switch returns false for an out-of-set value.
func TestEnumValidRejectsUnknown(t *testing.T) {
	const bogus = "definitely-not-a-valid-enum-member"
	rejects := []func() bool{
		ARCResultResult(bogus).Valid,
		AuthResultResult(bogus).Valid,
		BIMICheckStatus(bogus).Valid,
		BlacklistCheckResponseGrade(bogus).Valid,
		ContentAnalysisUnsubscribeMethods(bogus).Valid,
		ContentIssueSeverity(bogus).Valid,
		ContentIssueType(bogus).Valid,
		DKIMCheckStatus(bogus).Valid,
		DMARCRecordDkimAlignment(bogus).Valid,
		DMARCRecordNonexistentSubdomainPolicy(bogus).Valid,
		DMARCRecordPolicy(bogus).Valid,
		DMARCRecordPsd(bogus).Valid,
		DMARCRecordSpfAlignment(bogus).Valid,
		DMARCRecordSubdomainPolicy(bogus).Valid,
		DomainTestResponseGrade(bogus).Valid,
		HeaderCheckImportance(bogus).Valid,
		HeaderIssueSeverity(bogus).Valid,
		IPRevResultResult(bogus).Valid,
		LinkCheckStatus(bogus).Valid,
		ReportGrade(bogus).Valid,
		RspamdResultDeliverabilityGrade(bogus).Valid,
		SPFCheckStatus(bogus).Valid,
		SPFRecordAllQualifier(bogus).Valid,
		ScoreSummaryAuthenticationGrade(bogus).Valid,
		ScoreSummaryBlacklistGrade(bogus).Valid,
		ScoreSummaryContentGrade(bogus).Valid,
		ScoreSummaryDnsGrade(bogus).Valid,
		ScoreSummaryHeaderGrade(bogus).Valid,
		ScoreSummarySpamGrade(bogus).Valid,
		SpamAssassinResultDeliverabilityGrade(bogus).Valid,
		StatusComponentsDatabase(bogus).Valid,
		StatusComponentsMta(bogus).Valid,
		StatusStatus(bogus).Valid,
		TestStatus(bogus).Valid,
		TestResponseStatus(bogus).Valid,
		TestSummaryGrade(bogus).Valid,
		XPtrResultResult(bogus).Valid,
	}

	for i, valid := range rejects {
		if valid() {
			t.Errorf("enum #%d: Valid() = true for bogus value, want false", i)
		}
	}
}

// TestGetSpecJSON verifies the embedded spec decodes to non-empty JSON.
func TestGetSpecJSON(t *testing.T) {
	data, err := GetSpecJSON()
	if err != nil {
		t.Fatalf("GetSpecJSON() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("GetSpecJSON() returned empty spec")
	}
	if data[0] != '{' {
		t.Errorf("GetSpecJSON() does not look like a JSON object, starts with %q", data[0])
	}
}

// TestGetSpec verifies the embedded OpenAPI spec loads and parses.
func TestGetSpec(t *testing.T) {
	swagger, err := GetSpec()
	if err != nil {
		t.Fatalf("GetSpec() error = %v", err)
	}
	if swagger == nil {
		t.Fatal("GetSpec() returned nil swagger")
	}
	if swagger.Info == nil || swagger.Info.Title == "" {
		t.Error("GetSpec() returned a spec without Info.Title")
	}
}

// TestGetSwagger verifies the deprecated GetSwagger wrapper still returns the
// parsed spec (it delegates to GetSpec).
func TestGetSwagger(t *testing.T) {
	swagger, err := GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger() error = %v", err)
	}
	if swagger == nil {
		t.Fatal("GetSwagger() returned nil swagger")
	}
}

// TestPathToRawSpec covers both branches of PathToRawSpec: an empty path
// yields an empty map, and a non-empty path yields a single resolver entry.
func TestPathToRawSpec(t *testing.T) {
	if got := PathToRawSpec(""); len(got) != 0 {
		t.Errorf("PathToRawSpec(\"\") returned %d entries, want 0", len(got))
	}

	const p = "spec.json"
	res := PathToRawSpec(p)
	resolver, ok := res[p]
	if !ok {
		t.Fatalf("PathToRawSpec(%q) missing entry for path", p)
	}
	data, err := resolver()
	if err != nil {
		t.Fatalf("resolver() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("resolver() returned empty spec")
	}
}
