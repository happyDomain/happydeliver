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
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
)

// MailPolicyChecker reads the policies a domain publishes about the mail it
// receives: MTA-STS and TLS-RPT. They answer the domain test only:
// the analysis of a received message never builds one, so none of their
// lookups, HTTPS fetches included, ever runs for a report.
type MailPolicyChecker struct {
	// Timeout bounds each DNS lookup.
	Timeout  time.Duration
	resolver DNSResolver
	// httpClient fetches MTA-STS policies: guarded against non-public
	// addresses as the BIMI assets are, and following no redirect, which
	// RFC 8461 section 3.3 forbids.
	httpClient *http.Client
}

// NewMailPolicyChecker builds a checker over resolver, fetching policies
// within httpTimeout.
func NewMailPolicyChecker(timeout, httpTimeout time.Duration, resolver DNSResolver) *MailPolicyChecker {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if resolver == nil {
		resolver = NewStandardDNSResolver()
	}
	client := bimi.NewHTTPClient(httpTimeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &MailPolicyChecker{
		Timeout:    timeout,
		resolver:   resolver,
		httpClient: client,
	}
}

// Check reads every policy of domain at once: none depends on another.
func (m *MailPolicyChecker) Check(ctx context.Context, domain string) *model.MailPolicies {
	policies := &model.MailPolicies{}
	var wg sync.WaitGroup
	wg.Go(func() { policies.MtaSts = m.checkMTASTS(ctx, domain) })
	wg.Go(func() { policies.TlsRpt = m.checkTLSRPT(ctx, domain) })
	wg.Wait()
	return policies
}

// lookupTXT is a TXT lookup of name within the checker's timeout.
func (m *MailPolicyChecker) lookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	return m.resolver.LookupTXT(ctx, name)
}

// mxHosts is the hostnames the MX records lead to, without trailing dot, for
// the checks that compare them with a policy. A null MX leads nowhere.
func mxHosts(records *[]model.MXRecord) []string {
	if isNullMXRecords(records) {
		return nil
	}
	var hosts []string
	seen := map[string]bool{}
	for _, mx := range utils.Deref(records) {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

// EvaluateMailPolicies completes policies with what depends on the MX records
// of domain, and charges what is wrong with them: absent, a policy costs
// nothing and is merely suggested; published but broken, it costs points of
// the domain test score, as broken ones make senders lose mail. The penalty is
// what CalculateDomainOnlyScoreWithPolicies takes off.
func EvaluateMailPolicies(policies *model.MailPolicies, domain string, mxRecords *[]model.MXRecord) {
	if policies == nil {
		return
	}
	hosts := mxHosts(mxRecords)

	issues := &model.MailPoliciesIssues{}
	penalty := 0
	charge := func(list *[]model.Issue, points int, issue model.Issue) {
		issue.Penalty = &points
		penalty += points
		*list = append(*list, issue)
	}

	var mtaSTS, tlsRPT []model.Issue
	mtaSTSIssues(policies.MtaSts, domain, hosts, func(points int, issue model.Issue) { charge(&mtaSTS, points, issue) })
	tlsRPTIssues(policies, domain, func(points int, issue model.Issue) { charge(&tlsRPT, points, issue) })

	if policies.MtaSts != nil {
		issues.MtaSts = issueList(mtaSTS)
	}
	if policies.TlsRpt != nil {
		issues.TlsRpt = issueList(tlsRPT)
	}
	policies.Issues = issues
	policies.Penalty = utils.PtrTo(penalty)
}

// policyCharge charges an issue points of the domain test score.
type policyCharge func(points int, issue model.Issue)
