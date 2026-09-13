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

package content

import (
	"context"
	"fmt"
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
	"git.happydns.org/happyDeliver/pkg/urlprobe"
	"net/http"
	"slices"
	"strings"
	"time"
)

// LinkHTTPFindingKind identifies what a probe observed on the wire. Unlike a
// URLSuspicion, which reads the URL as written in the message, a finding
// reports what the destination actually answered.
type LinkHTTPFindingKind string

const (
	// LinkHTTPNotFound: the destination does not exist (404, 410).
	LinkHTTPNotFound LinkHTTPFindingKind = "not_found"
	// LinkHTTPProtected: the destination refuses unauthenticated access
	// (401, 403), so the recipient cannot open it either.
	LinkHTTPProtected LinkHTTPFindingKind = "protected"
	// LinkHTTPServerFailure: the destination failed or throttled the probe
	// (429, 5xx), which may be transient.
	LinkHTTPServerFailure LinkHTTPFindingKind = "server_failure"
	// LinkHTTPExcessiveRedirects: the destination is reached, but only after
	// more redirections than a URL should need.
	LinkHTTPExcessiveRedirects LinkHTTPFindingKind = "excessive_redirects"
	// LinkHTTPRedirectLoop: the redirections never end, either because they
	// come back to a URL already visited or because they exceed the limit.
	LinkHTTPRedirectLoop LinkHTTPFindingKind = "redirect_loop"
)

// LinkHTTPFinding is one specific problem observed while fetching a URL, with
// the message and the advice shown to the user. It mirrors URLSuspicion so
// that both travel the same way to the report and to the score.
type LinkHTTPFinding struct {
	Kind     LinkHTTPFindingKind
	Severity model.ContentIssueSeverity
	Message  string
	Advice   string
}

// IssueType tells which content issue a finding is filed under. A URL that
// answers but only after a detour is not unreachable: the two read differently
// in a report, and the web UI labels issues by type.
func (f LinkHTTPFinding) IssueType() model.ContentIssueType {
	switch f.Kind {
	case LinkHTTPExcessiveRedirects, LinkHTTPRedirectLoop:
		return model.ContentIssueTypeExcessiveRedirects
	default:
		return model.ContentIssueTypeUnreachableLink
	}
}

// defect says which defect this finding is, and so who pays for it. The role
// decides: a link that does not answer is already graded by the links
// criterion, an image source by the images one, while nothing yet grades the
// address a recipient unsubscribes at.
//
// A chain of redirections that ends somewhere is the one finding no criterion
// counts as broken, the URL being reached after all, so it answers under the
// probe cap whatever its role. A chain that never ends does count as broken,
// both criteria reading it that way, and is filed with the dead URLs.
func (f LinkHTTPFinding) defect(role urlRole) *reading.Defect {
	if f.Kind == LinkHTTPExcessiveRedirects {
		return defectRedirectChain
	}

	switch role {
	case urlRoleImage:
		return defectDeadImage
	case urlRoleUnsubscribe:
		return defectDeadUnsubscribe
	default:
		return defectDeadLink
	}
}

const (
	// probeBudget caps how long the whole fetching pass may take, however many
	// URLs it has left. Without it, a message full of links pointing at servers
	// that never answer holds an analysis for as long as they care to stall it.
	probeBudget = 60 * time.Second

	// excessiveRedirectHops and severeRedirectHops are the number of hops
	// above which a redirection chain is reported. One hop is ordinary
	// (http: to https:, apex to www, a click tracker); three is a detour, five
	// is a chain the sender has lost sight of.
	excessiveRedirectHops = 2
	severeRedirectHops    = 4
)

// probedURL is what a check keeps of fetching its URL. LinkCheck and
// ImageCheck both embed it: a link and an image source are read very
// differently, but they are fetched identically, so what came back off the
// wire is described once and read once.
type probedURL struct {
	// Status is the code of the final response, or 0 when none was received.
	Status int
	// FinalURL is where the URL ends once its redirections are followed.
	FinalURL string
	// RedirectChain lists the URLs the fetch was redirected through, in order,
	// excluding the URL written in the message.
	RedirectChain []string
	// HTTPFindings lists what fetching the URL revealed, as opposed to what
	// reading it did (the Suspicions of the check carrying this).
	HTTPFindings []LinkHTTPFinding
}

// apply records what came back. The subject names what the URL was found as
// ("Link", "Image") and opens each finding's message.
func (p *probedURL) apply(probe urlprobe.Answer, subject string) {
	p.FinalURL = probe.FinalURL
	p.RedirectChain = probe.RedirectChain
	p.HTTPFindings = httpFindings(probe, subject)

	// A request that got no answer has no status to report: leaving it at zero
	// is what tells "never answered" apart from "answered".
	if probe.Err == nil {
		p.Status = probe.Status
	}
}

// destination is where a URL finally leads, given the URL as the message wrote
// it: the end of its redirection chain when it was fetched and redirected, the
// written URL otherwise. Where the chain ends is what the sender actually
// publishes, and it is what a reading of the destinations must be held to: a
// message whose links go through a click tracker leads where the tracker sends
// the recipient, not to the tracker.
//
// A URL nothing followed, because it was never fetched or never answered, is
// its own destination: that is all this knows of it.
func (p probedURL) destination(written string) string {
	if p.FinalURL != "" {
		return p.FinalURL
	}
	return written
}

// hasFinding reports whether the URL carries a finding of the given kind.
func (p probedURL) hasFinding(kind LinkHTTPFindingKind) bool {
	return slices.ContainsFunc(p.HTTPFindings, func(f LinkHTTPFinding) bool {
		return f.Kind == kind
	})
}

// urlRole says what a fetched URL was found as. What a URL that does not
// answer costs depends on it: a body link is graded by the links criterion, an
// image source by the images one, while nothing yet grades the address a
// recipient unsubscribes at.
type urlRole string

const (
	urlRoleLink        urlRole = "link"
	urlRoleImage       urlRole = "image"
	urlRoleUnsubscribe urlRole = "unsubscribe"
)

// probedLocation pairs what a fetch returned with the URL it belongs to, and
// with the role it was first found under.
type probedLocation struct {
	probedURL
	Location string
	Role     urlRole
}

// destination is where this URL finally leads, as probedURL.destination reads
// it off the URL the message wrote.
func (p probedLocation) destination() string {
	return p.probedURL.destination(p.Location)
}

// probedURLs lists every URL that was fetched, once each and in the order they
// were found: the body links, the image sources, then the unsubscribe
// addresses of the List-Unsubscribe header. A URL written twenty times, or
// used both as a link and as an image source, is fetched once and must be
// reported and scored once too, however many checks carry it.
//
// The report and the score both read the fetched URLs through this, so a
// fourth source of URLs only has to be added here.
func (r *Results) probedURLs() []probedLocation {
	probed := make([]probedLocation, 0, len(r.Links)+len(r.Images)+len(r.UnsubscribeChecks))
	seen := make(map[string]bool, cap(probed))

	// The role kept is the first one the URL was found under, as the entry
	// itself is: a URL written both as a link and as an image source is
	// reported once, and the role it is reported under is what decides which
	// defect that one finding is.
	add := func(location string, role urlRole, result probedURL) {
		if location == "" || seen[location] {
			return
		}
		seen[location] = true
		probed = append(probed, probedLocation{probedURL: result, Location: location, Role: role})
	}

	for _, link := range r.Links {
		add(link.URL, urlRoleLink, link.probedURL)
	}
	for _, image := range r.Images {
		add(image.Src, urlRoleImage, image.probedURL)
	}
	for _, check := range r.UnsubscribeChecks {
		add(check.URL, urlRoleUnsubscribe, check.probedURL)
	}

	return probed
}

// findings reports every problem the probe observed. The subject names what
// the URL was found as ("Link", "Image") and opens each message, the way
// insecureSchemeSuspicion does, so that the findings read the same way
// wherever the URL came from.
func httpFindings(p urlprobe.Answer, subject string) []LinkHTTPFinding {
	if p.Err != nil {
		if urlprobe.RedirectExhausted(p.Err) {
			return []LinkHTTPFinding{{
				Kind:     LinkHTTPRedirectLoop,
				Severity: model.ContentIssueSeverityHigh,
				Message:  fmt.Sprintf("%s never arrives: its redirections come back to a URL already visited, or exceed %d hops", subject, urlprobe.MaxRedirects),
				Advice:   "Follow the link yourself and remove the loop; a destination that never resolves is unreachable for the recipient and for the filters that check it",
			}}
		}

		// Any other error is ours as much as the sender's: a DNS failure, a
		// timeout or a refused connection seen from here is not evidence
		// against the message.
		return nil
	}

	var findings []LinkHTTPFinding

	if finding, ok := redirectChainFinding(subject, p.RedirectChain, p.FinalURL); ok {
		findings = append(findings, finding)
	}

	if finding, ok := httpStatusFinding(subject, p.Status); ok {
		findings = append(findings, finding)
	}

	return findings
}

// httpStatusFinding turns a response code into a finding. The three classes
// worth telling apart are a destination that does not exist, one the recipient
// is not allowed to see, and one that failed on its own side.
func httpStatusFinding(subject string, status int) (LinkHTTPFinding, bool) {
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		return LinkHTTPFinding{
			Kind:     LinkHTTPNotFound,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("%s leads nowhere (HTTP %d): the recipient who clicks it lands on an error page", subject, status),
			Advice:   "Point it at a live page, or drop it; filters score dead links as a negative signal",
		}, true

	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return LinkHTTPFinding{
			Kind:     LinkHTTPProtected,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("%s is not reachable by the recipient (HTTP %d): it sits behind an authentication or an access restriction", subject, status),
			Advice:   "Serve the destination without a login, or restrict it only after the click; a filter following the link sees the same refusal it would see for a dead page",
		}, true

	case status == http.StatusTooManyRequests || status >= 500:
		return LinkHTTPFinding{
			Kind:     LinkHTTPServerFailure,
			Severity: model.ContentIssueSeverityMedium,
			Message:  fmt.Sprintf("%s answered with a server-side failure (HTTP %d); this may be temporary, or a limit the destination applies to automated clients", subject, status),
			Advice:   "Check that the destination stays up for the whole campaign, and that it does not rate-limit the clients mail filters use to follow links",
		}, true
	}

	return LinkHTTPFinding{}, false
}

// redirectChainFinding reports a chain longer than a destination should need.
// One or two hops are ordinary; beyond that the sender no longer controls
// where the click ends up, and each hop adds latency and one more domain whose
// reputation the link carries.
func redirectChainFinding(subject string, chain []string, finalURL string) (LinkHTTPFinding, bool) {
	if len(chain) <= excessiveRedirectHops {
		return LinkHTTPFinding{}, false
	}

	severity := model.ContentIssueSeverityMedium
	if len(chain) > severeRedirectHops {
		severity = model.ContentIssueSeverityHigh
	}

	return LinkHTTPFinding{
		Kind:     LinkHTTPExcessiveRedirects,
		Severity: severity,
		Message:  fmt.Sprintf("%s goes through %d redirections before reaching %q", subject, len(chain), finalURL),
		Advice:   "Point the URL at its destination directly; every hop adds latency and one more domain whose reputation the link carries",
	}, true
}

// redirectDowngradeSuspicion reports an https: URL whose redirections hand the
// recipient over to http:. insecureSchemeSuspicion only reads the URL as
// written in the message, so the downgrade is invisible to it, while the
// browser that follows the chain carries out the whole exchange in clear text
// all the same.
//
// A URL already written in http: raises nothing here: the static suspicion
// says it, and saying it twice would charge the sender twice for one mistake.
func redirectDowngradeSuspicion(rawURL string, chain []string) *URLSuspicion {
	if scheme, _ := splitScheme(strings.TrimSpace(rawURL)); scheme != "https" {
		return nil
	}

	for _, hop := range chain {
		if suspicion := insecureSchemeSuspicion("Redirect target", hop); suspicion != nil {
			return suspicion
		}
	}

	return nil
}

// probeContentURLs fetches every distinct URL the message points at, and
// records what came back on each check that carries it. Reading the message is
// done by then: a URL written twenty times, or used both as a link and as an
// image source, is fetched once.
func (c *Analyzer) probeContentURLs(results *Results) {
	if c.SkipProbes {
		return
	}

	// An unsubscribe endpoint is probed under stricter rules, and a URL that is
	// both a body link and an unsubscribe endpoint gets the stricter ones: the
	// risk of unsubscribing a recipient for real outweighs the accuracy a GET
	// fallback would buy. An endpoint offered only in the body carries that
	// same risk, so the header and the body are both read here.
	unsubscribe := make(map[string]bool, len(results.ListUnsubscribeURLs)+len(results.UnsubscribeLinks))
	for _, rawURL := range slices.Concat(results.ListUnsubscribeURLs, results.UnsubscribeLinks) {
		if urlprobe.Probeable(rawURL) {
			unsubscribe[rawURL] = true
		}
	}

	var requests []urlprobe.Request
	seen := make(map[string]bool)
	add := func(rawURL string) {
		if !urlprobe.Probeable(rawURL) || seen[rawURL] {
			return
		}
		seen[rawURL] = true
		requests = append(requests, urlprobe.Request{
			URL:  rawURL,
			Opts: urlprobe.Options{NoGETFallback: unsubscribe[rawURL]},
		})
	}

	for _, link := range results.Links {
		// A URL that does not parse, or that still carries a merge field, has
		// no destination to fetch.
		if link.Valid {
			add(link.URL)
		}
	}
	for _, image := range results.Images {
		add(image.Src)
	}
	for _, rawURL := range results.ListUnsubscribeURLs {
		add(rawURL)
	}

	if len(requests) == 0 {
		return
	}

	// What the cap leaves out is counted, not dropped in silence: a report that
	// stopped short must say so rather than let the URLs it never fetched read
	// as URLs that answered.
	if len(requests) > urlprobe.MaxURLs {
		results.UnprobedURLs = len(requests) - urlprobe.MaxURLs
		requests = requests[:urlprobe.MaxURLs]
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeBudget)
	defer cancel()

	probes := c.prober.Probe(ctx, requests)

	for i := range results.Links {
		if probe, ok := probes[results.Links[i].URL]; ok {
			results.Links[i].applyProbe(probe, "Link")
		}
	}

	for i := range results.Images {
		if probe, ok := probes[results.Images[i].Src]; ok {
			results.Images[i].applyProbe(probe)
		}
	}

	for _, rawURL := range results.ListUnsubscribeURLs {
		probe, ok := probes[rawURL]
		if !ok {
			continue
		}

		check := LinkCheck{URL: rawURL, Valid: true, IsSafe: true}
		check.applyProbe(probe, "The unsubscribe address advertised in the List-Unsubscribe header")

		// An unsubscribe endpoint answering anything but "gone" is left alone:
		// RFC 8058 has it accept a POST, so a refusal of the HEAD this probe
		// sends says nothing about whether a recipient can unsubscribe.
		check.HTTPFindings = slices.DeleteFunc(check.HTTPFindings, func(f LinkHTTPFinding) bool {
			return f.Kind != LinkHTTPNotFound
		})
		// The suspicions a redirection may have raised belong to the body's
		// links; the header's URL is reported on its reachability alone.
		check.Suspicions = nil
		check.IsSafe = true

		results.UnsubscribeChecks = append(results.UnsubscribeChecks, check)
	}
}

// applyProbe records what fetching the link returned, plus the one suspicion
// only a fetch can raise.
func (l *LinkCheck) applyProbe(probe urlprobe.Answer, subject string) {
	l.apply(probe, subject)

	// A chain the sender no longer controls may hand the recipient over to a
	// plain http: hop, which the URL written in the message does not show.
	if suspicion := redirectDowngradeSuspicion(l.URL, probe.RedirectChain); suspicion != nil {
		l.Suspicions = append(l.Suspicions, *suspicion)
		l.IsSafe = false
	}

	// Redirections that never end are the link's own doing, and the finding
	// says so. Everything else is a failure seen from here, which says nothing
	// about the message: it stays a warning, and Warning being empty is what
	// tells the two apart when the status is mapped.
	if probe.Err != nil && !urlprobe.RedirectExhausted(probe.Err) {
		l.Warning = fmt.Sprintf("Could not verify link: %v", probe.Err)
	}
}

// applyProbe records what fetching the image source returned. An image is
// fetched when the message is opened, with no click involved, so a source that
// does not answer leaves a hole the recipient sees straight away, whether the
// server said so or the redirections never got there.
func (i *ImageCheck) applyProbe(probe urlprobe.Answer) {
	i.apply(probe, "Image")

	if suspicion := redirectDowngradeSuspicion(i.Src, probe.RedirectChain); suspicion != nil {
		i.Suspicions = append(i.Suspicions, *suspicion)
	}

	i.IsBroken = i.Status >= 400 || i.hasFinding(LinkHTTPRedirectLoop)
}

// httpFindingIssue turns what fetching a URL revealed into the issue the
// report shows, the way a suspicion of a URL becomes an issue of its own.
func httpFindingIssue(location string, finding LinkHTTPFinding) model.ContentIssue {
	return model.ContentIssue{
		Type:     finding.IssueType(),
		Severity: finding.Severity,
		Message:  finding.Message,
		Location: utils.PtrTo(location),
		Advice:   utils.PtrTo(finding.Advice),
	}
}
