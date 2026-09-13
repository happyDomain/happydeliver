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
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// contentCheck is a check of the content analysis: one written over the facts
// gathered about a message. The machinery it is run by is reading.Run's, and
// is the same for every reading happyDeliver makes.
type contentCheck = reading.Check[*contentInput]

// contentInput carries what every check reads. It is assembled once per
// message, so that a check costs a pass over facts already gathered rather
// than a second look at the message.
type contentInput struct {
	// Results holds the facts read off the message: its parts, the links and
	// images it carries, and what fetching them returned.
	Results *Results

	// Message is the message itself, headers and MIME parts included. A check
	// needing a fact nobody else needs reads it here rather than having it
	// added to Results: what an attachment weighs, what the From domain is,
	// what a part declares itself to be.
	Message *mailmsg.Message

	// HTML is the tree the HTML part parsed into, nil when the message carries
	// no HTML or none that parses. It is parsed once for every check, so that
	// looking at the markup (an alt attribute, a colour, a stylesheet, a tag
	// no client supports) costs a walk rather than a second parse.
	HTML *html.Node
}

var (
	// familyURLSuspicion answers for what the shape of a URL says, for links
	// and image sources alike.
	familyURLSuspicion = &reading.Family{Name: "url_suspicion", Cap: 10}

	// familyHTTPProbe answers for what fetching the URLs revealed, under a cap
	// of its own so that a deceptive link and a dead one are charged apart.
	familyHTTPProbe = &reading.Family{Name: "http_probe", Cap: 10}

	// familyHarmfulHTML answers for markup an email client blocks outright.
	// Each tag costs a flat twenty points: they are all equally fatal to the
	// rendering, so weighing them by severity would say nothing.
	familyHarmfulHTML = &reading.Family{Name: "harmful_html", Cap: 40, PerItem: 20}

	// familyRspamd answers for what the spam filter of the receiving MTA
	// observed about the content. It is capped like the others: a filter with
	// a lot to say informs the reader, it does not decide the grade.
	familyRspamd = &reading.Family{Name: "rspamd", Cap: 10}
)

// Reading is what the checks made of what was observed: the findings a report
// shows, and what they cost its score.
type Reading = reading.Evaluation

// Read runs the registry over what was observed about a message.
//
// It is called once and its answer handed to both Analysis and Score, which
// is why it is the caller's to hold rather than something either of them does
// on its own: a check may fetch a URL or hand a file to a scanner, and no
// message is to be read twice for one report.
//
// Everything a check reads must therefore be observed first, the filter's
// verdict included.
func (c *Analyzer) Read(observed *Results) Reading {
	// The analysis owns the deadline it gives its checks, as it owns the one it
	// gives its HTTP client. The day a request context is threaded down to
	// here, this is the one line that changes.
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	issues, penalty := reading.Run(ctx, contentChecks, observed.checkInput())

	return Reading{Issues: issues, Penalty: penalty}
}

// concernForURL keys a defect that is about one URL. Both the check that reads
// the message and the one that reads the spam filter's symbols go through it,
// so that they agree on the key whenever they agree on the URL.
//
// The URL is normalised only as far as is safe: scheme and host lowercased,
// surrounding space removed. Anything more (dropping a trailing slash,
// sorting a query) risks calling two URLs the same when a server does not, and
// a wrong merge costs a finding while a missed one costs only tidiness. A URL
// that does not parse gets no key, so it is never merged.
func concernForURL(defect string, rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)

	return defect + ":" + parsed.String()
}

// checkInput is what the checks are handed: the facts gathered about the
// message, the message itself, and its parsed markup.
func (r *Results) checkInput() *contentInput {
	return &contentInput{
		Results: r,
		Message: r.email,
		HTML:    r.htmlDocument,
	}
}
