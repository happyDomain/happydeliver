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
	"fmt"
	"strconv"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/authresults"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// parseDKIM2Result reads the dkim2 method of an Authentication-Results header:
// one verdict for the whole chain of DKIM2-Signature headers. In
// draft-gondwana-dkim2-authres, header.d is the originator (i=1) and header.i
// the signature a failure is attributed to, not the identity header.i means
// for DKIM1:
//
//	dkim2=fail (i=1 sender.example pass, i=2 fwd.example fail; FAIL: ...)
//	  header.d=sender.example header.i=2
//
// The comment is advisory and written for a human, so it is kept as written
// rather than read. Authentication-Milter (Mail::DKIM2) reports the last
// signature of the chain in both properties instead, whichever one failed, and
// leaves the envelope out of what it checks; reconcileDKIM2Originator tells
// the two apart once the signatures of the message are known.
func (a *AuthenticationAnalyzer) parseDKIM2Result(method authresults.Method) *model.DKIM2Result {
	result := &model.DKIM2Result{
		Result:  model.DKIM2ResultResult(method.Result),
		Details: utils.PtrTo(methodDetails(method)),
	}

	if domain := method.Property("header.d", "d"); domain != "" {
		result.Domain = &domain
	}
	if comment := strings.TrimSpace(method.Comment()); comment != "" {
		result.Comment = &comment
	}
	// Only a failure is attributed to a signature.
	if result.Result != model.DKIM2ResultResultPass && result.Result != model.DKIM2ResultResultNone {
		if i, err := strconv.Atoi(method.Property("header.i", "i")); err == nil && i > 0 {
			result.Instance = &i
		}
	}

	return result
}

// reconcileDKIM2Originator sets the domain of the verdict to the one of the
// i=1 signature of the message, which says who the originator is whatever the
// receiver wrote. A header.d naming another domain shows the receiver does not
// follow the draft, so its header.i attributes nothing either: it is only the
// last signature. A chain signed by one domain throughout cannot tell.
func reconcileDKIM2Originator(result *model.DKIM2Result, email *mailmsg.Message) {
	originator := dkim2Originator(email)
	if originator == "" {
		return
	}
	if result.Domain != nil && !strings.EqualFold(*result.Domain, originator) {
		result.Instance = nil
	}
	result.Domain = &originator
}

// dkim2Originator is the signing domain of the i=1 signature of the message.
func dkim2Originator(email *mailmsg.Message) string {
	for _, sig := range email.DKIM2Signatures() {
		if sig.Instance == 1 {
			return sig.Domain
		}
	}
	return ""
}

// calculateDKIM2Score is what the DKIM2 verdict takes off, out of its own 100
// points: DKIM2 being still a draft, it only ever takes off, and lightly.
func (a *AuthenticationAnalyzer) calculateDKIM2Score(results *model.AuthenticationResults) int {
	if results.Dkim2 == nil {
		return 0
	}
	switch results.Dkim2.Result {
	case model.DKIM2ResultResultFail, model.DKIM2ResultResultPermerror:
		return -100
	case model.DKIM2ResultResultTemperror:
		return -40
	}
	return 0
}

// dkim2Passed says whether the receiver verified the DKIM2 chain of custody.
func dkim2Passed(results *model.AuthenticationResults) bool {
	return results.Dkim2 != nil && results.Dkim2.Result == model.DKIM2ResultResultPass
}

// dkim2VerdictIssues says what the DKIM2 verdict calls for changing. signed
// says whether the message carries DKIM2-Signature headers, which the
// receiver may not have verified: DKIM2 verifiers are not deployed yet.
func dkim2VerdictIssues(dkim2 *model.DKIM2Result, signed bool) []model.Issue {
	if dkim2 == nil {
		if !signed {
			return nil
		}
		return []model.Issue{newIssue(model.IssueTypeDkim2Unevaluated, model.IssueSeverityInfo, "DKIM2",
			"The message carries DKIM2 signatures, but the receiver reported no DKIM2 verdict: DKIM2 is still an IETF draft, and few receivers verify it yet.",
			"Nothing to change; the keys the signatures point to are checked in the DNS section.")}
	}

	where := utils.Deref(dkim2.Domain)
	at := "the DKIM2 chain"
	if dkim2.Instance != nil {
		at = fmt.Sprintf("the DKIM2 signature i=%d", *dkim2.Instance)
		if *dkim2.Instance == 1 {
			at += " (the originator's)"
		}
	}
	diagnostic := ""
	if dkim2.Comment != nil {
		diagnostic = fmt.Sprintf(" The receiver says: %s.", strings.TrimRight(*dkim2.Comment, "."))
	}

	switch dkim2.Result {
	case model.DKIM2ResultResultPass, model.DKIM2ResultResultNone:
		return nil
	case model.DKIM2ResultResultFail:
		return []model.Issue{newIssue(model.IssueTypeDkim2Fail, model.IssueSeverityMedium, where,
			fmt.Sprintf("Verification of %s failed: the message was modified without declaring it, a signature is wrong or out of date, its From is not Authentic, or its signatures do not form a consistent chain.%s", at, diagnostic),
			"Check that the DKIM2 public keys match the private keys, that the signing domain matches the From domain, that the sender each signature records (mf=) belongs to its signing domain and matches a recipient (rt=) of the signature before it, that the clock of the signer is right (a signature lasts 14 days), and that nothing rewrites the message after it was signed.")}
	case model.DKIM2ResultResultTemperror:
		return []model.Issue{newIssue(model.IssueTypeDkim2Temperror, model.IssueSeverityLow, where,
			fmt.Sprintf("A temporary failure, usually a DNS one, prevented the receiver from verifying %s.%s", at, diagnostic),
			"Check that the DNS servers of the signing domain answer reliably, then send another test.")}
	default:
		return []model.Issue{newIssue(model.IssueTypeDkim2Permerror, model.IssueSeverityMedium, where,
			fmt.Sprintf("The receiver could not verify %s: a DKIM2 header or key is missing or malformed.%s", at, diagnostic),
			"Check the DKIM2 header fields your signer writes, and the keys at the selectors they name.")}
	}
}
