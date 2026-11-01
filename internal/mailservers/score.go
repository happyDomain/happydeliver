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

package mailservers

import (
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/analyzer"
	"git.happydns.org/happyDeliver/pkg/grade"
)

// What each part of the conversation with the MX is worth, out of 100.
const (
	weightReach   = 35 // TCP, 220 banner, EHLO
	weightTLS     = 30 // STARTTLS, then a certificate valid for the MX name
	weightBounces = 20 // MAIL FROM:<> and RCPT TO:<postmaster@>
	weightFCrDNS  = 10
	weightIPv6    = 5

	// certExpiringDays is how close to expiry a certificate is worth a
	// warning.
	certExpiringDays = 14

	// penaltyPolicyBroken is what a published but failing MTA-STS or DANE
	// costs: it makes senders refuse to deliver.
	penaltyPolicyBroken = 10

	// capCritical is the highest score an open relay or authentication in
	// clear leaves: an F on the domain scale.
	capCritical = 29
)

// verdict collects the issues of the servers and the points they cost.
type verdict struct {
	issues []model.Issue
	lost   float64
}

func (v *verdict) add(points float64, issueType model.IssueType, severity model.IssueSeverity, location, message, advice string) {
	penalty := int(points + 0.5)
	issue := model.Issue{
		Type:     issueType,
		Category: model.IssueCategoryDeliverability,
		Severity: severity,
		Message:  message,
		Penalty:  &penalty,
	}
	if location != "" {
		issue.Location = &location
	}
	if advice != "" {
		issue.Advice = &advice
	}
	v.lost += points
	v.issues = append(v.issues, issue)
}

// endpointRef names an endpoint in the issues: host and address.
type endpointRef struct {
	host string
	ep   *model.MailServerEndpoint
}

func (e endpointRef) String() string {
	return fmt.Sprintf("%s (%s)", e.host, e.ep.Ip)
}

func joinRefs(refs []endpointRef) string {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.String()
	}
	return strings.Join(names, ", ")
}

// share is what failing n endpoints out of total costs of weight points.
func share(weight float64, n, total int) float64 {
	if total == 0 {
		return 0
	}
	return weight * float64(n) / float64(total)
}

// judge scores the probes of the servers and tells what they call for.
func judge(result *model.MailServersResult, mtaSTS *model.MTASTSResult, relayTested bool) {
	result.OpenRelayTested = utils.PtrTo(relayTested)
	v := &verdict{}
	domain := result.Domain

	switch result.Status {
	case model.MailServersResultStatusNullMx:
		result.Issues = &[]model.Issue{}
		return
	case model.MailServersResultStatusNoMx:
		v.add(0, model.IssueTypeSmtpUnreachable, model.IssueSeverityHigh, domain,
			fmt.Sprintf("%s has neither MX nor address: there is no server to deliver its mail to.", domain),
			fmt.Sprintf("Publish MX records for %s pointing to servers that accept mail.", domain))
		result.Issues = &v.issues
		return
	case model.MailServersResultStatusInconclusive:
		message := "No MX of the domain answered on port 25, and neither did a server known to accept connections: this instance cannot reach port 25, so nothing can be said about the servers."
		advice := "Instance operators: allow outbound connections to port 25, or set -disable-mx-probes."
		if result.Error != nil && !strings.Contains(*result.Error, "port 25") {
			message = *result.Error + ", so nothing can be said about the servers."
			advice = "Test again later if the failure looks temporary."
		}
		v.add(0, model.IssueTypeSmtpProbeInconclusive, model.IssueSeverityInfo, domain, message, advice)
		result.Issues = &v.issues
		return
	}

	var probed, talking []endpointRef
	var skipped []string
	for i := range deref(result.Servers) {
		srv := &(*result.Servers)[i]
		if srv.SkipReason != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %s", srv.Host, *srv.SkipReason))
		}
		for j := range srv.Endpoints {
			ep := &srv.Endpoints[j]
			ref := endpointRef{srv.Host, ep}
			switch {
			case ep.Probed:
				probed = append(probed, ref)
				if utils.Deref(ep.Ehlo) {
					talking = append(talking, ref)
				}
			case ep.SkipReason != nil && !strings.HasPrefix(*ep.SkipReason, "Not probed"):
				skipped = append(skipped, fmt.Sprintf("%s: %s", ref, *ep.SkipReason))
			}
		}
	}

	if len(skipped) > 0 {
		v.add(0, model.IssueTypeSmtpProbeSkipped, model.IssueSeverityMedium, domain,
			fmt.Sprintf("Some MX of %s were not probed, as no sender could deliver to them either: %s", domain, strings.Join(skipped, "; ")),
			"Point every MX record to a hostname resolving only to public addresses.")
	}

	if len(probed) == 0 {
		v.add(100, model.IssueTypeSmtpUnreachable, model.IssueSeverityCritical, domain,
			fmt.Sprintf("No MX of %s can be delivered to.", domain),
			"Point the MX records to servers reachable from the Internet on port 25.")
		finish(result, v, false, false)
		return
	}

	reachIssues(v, probed)
	tlsIssues(v, talking, len(probed))
	bounceIssues(v, talking, len(probed))
	fcrdnsIssues(v, probed)
	ipv6Issues(v, probed, domain)

	mtaSTSEnforced := mtaSTSIssues(v, result, mtaSTS, talking)
	daneValid := daneIssues(v, result)

	// The two defects that make a server a danger to others cap the score
	var critical []string
	var relays, plainAuth []endpointRef
	for _, ref := range talking {
		if utils.Deref(ref.ep.OpenRelay) {
			relays = append(relays, ref)
		}
		if len(deref(ref.ep.AuthBeforeTls)) > 0 {
			plainAuth = append(plainAuth, ref)
		}
	}
	scoreBeforeCap := 100 - v.lost
	if len(relays) > 0 {
		critical = append(critical, "open relay")
		v.add(max(scoreBeforeCap-capCritical, 0), model.IssueTypeSmtpOpenRelay, model.IssueSeverityCritical, joinRefs(relays),
			fmt.Sprintf("%s accept to relay mail to a domain they do not serve: spammers use such servers, which blocklists soon list.", joinRefs(relays)),
			"Restrict relaying to authenticated users and your own networks (Postfix: smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination).")
		scoreBeforeCap = min(scoreBeforeCap, capCritical)
	}
	if len(plainAuth) > 0 {
		critical = append(critical, "authentication in clear")
		v.add(max(scoreBeforeCap-capCritical, 0), model.IssueTypeSmtpAuthPlaintext, model.IssueSeverityCritical, joinRefs(plainAuth),
			fmt.Sprintf("%s offer authentication before STARTTLS, inviting clients to send passwords in clear.", joinRefs(plainAuth)),
			"Offer AUTH only after STARTTLS (Postfix: smtpd_tls_auth_only = yes), and move authenticated submission to port 587 or 465.")
	}

	finish(result, v, len(critical) == 0 && (mtaSTSEnforced || daneValid), len(critical) > 0)
	result.MtaStsEnforced = utils.PtrTo(mtaSTSEnforced)
	result.DaneValid = utils.PtrTo(daneValid)
}

// finish turns what was lost into the score and grade. A+ needs a perfect
// score and MTA-STS or DANE deployed correctly; a critical defect caps the
// grade at F.
func finish(result *model.MailServersResult, v *verdict, plus, critical bool) {
	score := int(100 - v.lost + 0.5)
	score = max(min(score, 100), 0)
	if critical {
		score = min(score, capCritical)
	}
	g := grade.Kind(score)
	if score == 100 && plus {
		g = "A+"
	}
	result.Score = &score
	result.Grade = utils.PtrTo(model.MailServersResultGrade(g))
	if v.issues == nil {
		v.issues = []model.Issue{}
	}
	result.Issues = &v.issues
}

func reachIssues(v *verdict, probed []endpointRef) {
	var down, noBanner, noEHLO, helo []endpointRef
	for _, ref := range probed {
		ep := ref.ep
		switch {
		case !utils.Deref(ep.TcpConnected):
			down = append(down, ref)
		case ep.Banner == nil || (ep.Error != nil && strings.HasPrefix(*ep.Error, "banner")):
			noBanner = append(noBanner, ref)
		case !utils.Deref(ep.Ehlo):
			noEHLO = append(noEHLO, ref)
		case utils.Deref(ep.EhloFallbackHelo):
			helo = append(helo, ref)
		}
	}
	n := len(probed)
	// A server that does not talk cannot do TLS nor take bounces either:
	// it loses those parts too, charged here.
	const silent = weightReach + weightTLS + weightBounces
	if len(down) > 0 {
		severity := model.IssueSeverityMedium
		if len(down) == n {
			severity = model.IssueSeverityCritical
		}
		v.add(share(silent, len(down), n), model.IssueTypeSmtpUnreachable, severity, joinRefs(down),
			fmt.Sprintf("%s cannot be reached on port 25: senders trying them first lose time, and mail is lost if none answers.", joinRefs(down)),
			"Make sure the servers run and that no firewall drops connections to port 25 from the Internet; remove the MX records of servers retired.")
	}
	if len(noBanner) > 0 {
		v.add(share(silent, len(noBanner), n), model.IssueTypeSmtpBannerInvalid, model.IssueSeverityHigh, joinRefs(noBanner),
			fmt.Sprintf("%s accept the connection but do not greet with 220: senders give up.", joinRefs(noBanner)),
			"Check the logs of the SMTP server: it may be overloaded, refuse this client, or not be an SMTP server at all.")
	}
	if len(noEHLO) > 0 {
		v.add(share(silent, len(noEHLO), n), model.IssueTypeSmtpEhloFailed, model.IssueSeverityHigh, joinRefs(noEHLO),
			fmt.Sprintf("%s refuse both EHLO and HELO.", joinRefs(noEHLO)),
			"Check the HELO restrictions of the server: they should accept any well-formed hostname.")
	}
	if len(helo) > 0 {
		v.add(0, model.IssueTypeSmtpEhloFailed, model.IssueSeverityLow, joinRefs(helo),
			fmt.Sprintf("%s only accept HELO, not ESMTP's EHLO: no STARTTLS nor any extension can be offered.", joinRefs(helo)),
			"Enable ESMTP on the server.")
	}
}

// tlsIssues charges the TLS of the servers that talk; n is how many were
// probed in all.
func tlsIssues(v *verdict, talking []endpointRef, n int) {
	var missing, failed, invalid, expiring []endpointRef
	var reasons []string
	for _, ref := range talking {
		ep := ref.ep
		switch {
		case !utils.Deref(ep.StarttlsOffered):
			missing = append(missing, ref)
			continue
		case !utils.Deref(ep.Starttls):
			failed = append(failed, ref)
			continue
		}
		cert := ep.Certificate
		if cert == nil {
			continue
		}
		valid := utils.Deref(cert.ChainValid) && utils.Deref(cert.HostnameMatch) && (cert.DaysLeft == nil || *cert.DaysLeft >= 0)
		if !valid {
			invalid = append(invalid, ref)
			reasons = append(reasons, fmt.Sprintf("%s: %s", ref, certProblem(cert)))
		} else if cert.DaysLeft != nil && *cert.DaysLeft < certExpiringDays {
			expiring = append(expiring, ref)
		}
	}
	if len(missing) > 0 {
		v.add(share(weightTLS, len(missing), n), model.IssueTypeSmtpStarttlsMissing, model.IssueSeverityHigh, joinRefs(missing),
			fmt.Sprintf("%s do not offer STARTTLS: mail to them travels in clear, and Gmail flags it as unencrypted.", joinRefs(missing)),
			"Enable STARTTLS with a certificate for the MX name (Postfix: smtpd_tls_security_level = may, with smtpd_tls_chain_files).")
	}
	if len(failed) > 0 {
		v.add(share(weightTLS, len(failed), n), model.IssueTypeSmtpStarttlsFailed, model.IssueSeverityHigh, joinRefs(failed),
			fmt.Sprintf("%s offer STARTTLS but the handshake fails: senders fall back to clear text, or give up.", joinRefs(failed)),
			"Check the certificate and TLS settings of the server; test with: openssl s_client -starttls smtp -connect <host>:25.")
	}
	if len(invalid) > 0 {
		v.add(share(weightTLS/2, len(invalid), n), model.IssueTypeSmtpCertInvalid, model.IssueSeverityHigh, joinRefs(invalid),
			fmt.Sprintf("Some MX present a certificate senders cannot trust: %s. Opportunistic TLS still works, but MTA-STS and DANE senders refuse to deliver.", strings.Join(reasons, "; ")),
			"Install a certificate from a public CA covering the MX hostname, with its intermediate certificates.")
	}
	if len(expiring) > 0 {
		v.add(share(5, len(expiring), n), model.IssueTypeSmtpCertExpiring, model.IssueSeverityMedium, joinRefs(expiring),
			fmt.Sprintf("The certificate of %s expires in less than %d days.", joinRefs(expiring), certExpiringDays),
			"Renew the certificate, and check that its automatic renewal reloads the SMTP server.")
	}
}

// certProblem says what is wrong with a certificate.
func certProblem(cert *model.MailServerCertificate) string {
	switch {
	case cert.DaysLeft != nil && *cert.DaysLeft < 0:
		return "expired"
	case cert.HostnameMatch != nil && !*cert.HostnameMatch:
		return "not valid for the MX name"
	case cert.ChainError != nil:
		return *cert.ChainError
	default:
		return "chain not trusted"
	}
}

// bounceIssues charges the servers that talk but refuse bounces; n is how
// many were probed in all.
func bounceIssues(v *verdict, talking []endpointRef, n int) {
	var nullRejected, postmasterRejected []endpointRef
	for _, ref := range talking {
		if ref.ep.NullSenderAccepted != nil && !*ref.ep.NullSenderAccepted {
			nullRejected = append(nullRejected, ref)
		}
		if ref.ep.PostmasterAccepted != nil && !*ref.ep.PostmasterAccepted {
			postmasterRejected = append(postmasterRejected, ref)
		}
	}
	if len(nullRejected) > 0 {
		v.add(share(weightBounces/2, len(nullRejected), n), model.IssueTypeSmtpNullSenderRejected, model.IssueSeverityHigh, joinRefs(nullRejected),
			fmt.Sprintf("%s refuse MAIL FROM:<>, the empty sender of bounces and delivery reports (RFC 5321 section 4.5.5): you never learn that your mail did not arrive.", joinRefs(nullRejected)),
			"Accept the null sender; filter bounces you did not cause with other means.")
	}
	if len(postmasterRejected) > 0 {
		v.add(share(weightBounces/2, len(postmasterRejected), n), model.IssueTypeSmtpPostmasterRejected, model.IssueSeverityHigh, joinRefs(postmasterRejected),
			fmt.Sprintf("%s refuse mail to postmaster@, which RFC 5321 section 4.5.1 requires every mail domain to accept: other operators cannot reach you about problems.", joinRefs(postmasterRejected)),
			"Create a postmaster alias delivering to a mailbox someone reads.")
	}
}

func fcrdnsIssues(v *verdict, probed []endpointRef) {
	var noPTR, mismatch []endpointRef
	n := len(probed)
	for _, ref := range probed {
		switch {
		case ref.ep.Ptr == nil:
			noPTR = append(noPTR, ref)
		case !utils.Deref(ref.ep.Fcrdns):
			mismatch = append(mismatch, ref)
		}
	}
	if len(noPTR) > 0 {
		v.add(share(weightFCrDNS, len(noPTR), n), model.IssueTypeSmtpPtrMissing, model.IssueSeverityMedium, joinRefs(noPTR),
			fmt.Sprintf("%s have no reverse DNS. The same servers usually send mail too, and receivers reject senders without one.", joinRefs(noPTR)),
			"Ask the owner of the addresses (your host or provider) for a PTR record naming the MX host.")
	}
	if len(mismatch) > 0 {
		v.add(share(weightFCrDNS, len(mismatch), n), model.IssueTypeSmtpFcrdnsMismatch, model.IssueSeverityMedium, joinRefs(mismatch),
			fmt.Sprintf("The reverse DNS of %s does not resolve back to the address.", joinRefs(mismatch)),
			"Give the name the PTR record points to an A/AAAA record with the address.")
	}
}

func ipv6Issues(v *verdict, probed []endpointRef, domain string) {
	for _, ref := range probed {
		if utils.Deref(ref.ep.Ipv6) && utils.Deref(ref.ep.TcpConnected) {
			return
		}
	}
	v.add(weightIPv6, model.IssueTypeSmtpNoIpv6, model.IssueSeverityInfo, domain,
		fmt.Sprintf("No MX of %s can be reached over IPv6.", domain),
		"Give the MX hosts AAAA records once the servers have IPv6 connectivity.")
}

// mtaSTSIssues holds the servers to the MTA-STS policy of the domain, and
// tells whether it is deployed correctly in enforce mode.
func mtaSTSIssues(v *verdict, result *model.MailServersResult, policy *model.MTASTSResult, talking []endpointRef) bool {
	if policy == nil || policy.Status == model.MTASTSResultStatusAbsent || policy.Mode == nil || policy.PolicyError != nil {
		return false
	}
	var uncovered []string
	for i := range deref(result.Servers) {
		srv := &(*result.Servers)[i]
		covered := analyzer.MTASTSCoversHost(policy, srv.Host)
		srv.MtaStsCovered = utils.PtrTo(covered)
		if !covered {
			uncovered = append(uncovered, srv.Host)
		}
	}
	enforce := *policy.Mode == model.MTASTSResultModeEnforce
	if !enforce {
		return false
	}

	ok := policy.RecordError == nil
	if len(uncovered) > 0 {
		ok = false
		v.add(penaltyPolicyBroken, model.IssueTypeMtaStsMxMismatch, model.IssueSeverityHigh, strings.Join(uncovered, ", "),
			fmt.Sprintf("The enforced MTA-STS policy does not cover %s: senders applying it refuse to deliver there.", strings.Join(uncovered, ", ")),
			"Add an mx line covering these hosts to the policy, and change the id of the _mta-sts record.")
	}
	var untrusted []endpointRef
	for _, ref := range talking {
		cert := ref.ep.Certificate
		if !utils.Deref(ref.ep.Starttls) || cert == nil || !utils.Deref(cert.ChainValid) || !utils.Deref(cert.HostnameMatch) {
			untrusted = append(untrusted, ref)
		}
	}
	if len(untrusted) > 0 {
		ok = false
		v.add(penaltyPolicyBroken, model.IssueTypeSmtpMtaStsCertInvalid, model.IssueSeverityHigh, joinRefs(untrusted),
			fmt.Sprintf("MTA-STS is enforced, but %s present no certificate valid for their name: senders applying the policy refuse to deliver to them.", joinRefs(untrusted)),
			"Install on every MX a certificate from a public CA covering its hostname.")
	}
	return ok && len(talking) > 0
}

// daneIssues tells whether DANE is deployed correctly on every MX, and
// charges the addresses whose certificate does not match.
func daneIssues(v *verdict, result *model.MailServersResult) bool {
	valid := len(deref(result.Servers)) > 0
	var mismatched []string
	for _, srv := range deref(result.Servers) {
		if utils.Deref(srv.TlsaRecords) == 0 || !utils.Deref(srv.TlsaDnssec) {
			valid = false
		}
		matched := 0
		for i := range srv.Endpoints {
			ep := &srv.Endpoints[i]
			if !ep.Probed {
				continue
			}
			switch utils.Deref(ep.Dane) {
			case model.MailServerEndpointDaneMatch:
				matched++
			case model.MailServerEndpointDaneMismatch:
				mismatched = append(mismatched, fmt.Sprintf("%s (%s): %s", srv.Host, ep.Ip, utils.Deref(ep.DaneMessage)))
				valid = false
			default:
				valid = false
			}
		}
		if matched == 0 {
			valid = false
		}
	}
	if len(mismatched) > 0 {
		v.add(penaltyPolicyBroken, model.IssueTypeSmtpDaneMismatch, model.IssueSeverityHigh, result.Domain,
			fmt.Sprintf("The TLSA records do not match the certificate presented: %s. DANE senders refuse to deliver there.", strings.Join(mismatched, "; ")),
			"Publish TLSA records matching the current certificate (or key) before rotating it, and keep the old ones until the new certificate is in place.")
	}
	return valid
}
