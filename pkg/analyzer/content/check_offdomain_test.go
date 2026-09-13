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
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/reading"
	"net/mail"
	"strings"
	"testing"
)

// offDomainFindings runs the check alone over a message sent from
// example.com, carrying the given links.
func offDomainFindings(t *testing.T, links ...LinkCheck) []reading.Finding {
	t.Helper()

	results := &Results{
		email: &mailmsg.Message{From: &mail.Address{Address: "news@example.com"}},
		Links: links,
	}

	findings, err := offDomainLinksCheck.Run(context.Background(), results.checkInput())
	if err != nil {
		t.Fatalf("the check could not answer: %v", err)
	}

	return findings
}

// TestOffDomainLinksReportsAMessageLeadingNowhereHome is the case the check
// exists for: several links, not one of them back to the domain the message is
// sent from.
func TestOffDomainLinksReportsAMessageLeadingNowhereHome(t *testing.T) {
	findings := offDomainFindings(t,
		LinkCheck{URL: "https://www.example.net/offer"},
		LinkCheck{URL: "https://shop.example.org/spring"},
		LinkCheck{URL: "https://blog.example.org/why"},
	)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want the one this is a finding about: %v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Defect != defectOffDomainLinks {
		t.Errorf("reported as %v, want the off-domain defect", finding.Defect)
	}

	// The sender's domain and the destinations are both named: the finding is
	// a comparison, and one that names neither side cannot be acted on.
	for _, want := range []string{"example.com", "example.net", "example.org"} {
		if !strings.Contains(finding.Message, want) {
			t.Errorf("the finding does not name %q: %s", want, finding.Message)
		}
	}
}

// TestOffDomainLinksKeepsQuiet covers what must not be reported. Each of these
// is a message the check has nothing to say about, and saying something would
// put a sender in front of a finding they cannot act on.
func TestOffDomainLinksKeepsQuiet(t *testing.T) {
	for _, tt := range []struct {
		name  string
		links []LinkCheck
	}{
		{
			name: "one link leads home",
			links: []LinkCheck{
				{URL: "https://www.example.net/offer"},
				{URL: "https://example.org/spring"},
				{URL: "https://shop.example.com/cart"},
			},
		},
		{
			name: "a subdomain of the sender's domain is the sender's domain",
			links: []LinkCheck{
				{URL: "https://www.example.net/offer"},
				{URL: "https://example.org/spring"},
				{URL: "https://news.eu.example.com/read"},
			},
		},
		{
			// What the whole reading is worth: the links are all written to a
			// tracker, and they all land back home.
			name: "a click tracker that forwards home",
			links: []LinkCheck{
				{URL: "https://click.example.net/a", probedURL: probedURL{FinalURL: "https://example.com/offer"}},
				{URL: "https://click.example.net/b", probedURL: probedURL{FinalURL: "https://example.com/spring"}},
				{URL: "https://click.example.net/c", probedURL: probedURL{FinalURL: "https://example.com/shop"}},
			},
		},
		{
			// Two links elsewhere are what an ordinary message is made of.
			name: "too few links to say anything",
			links: []LinkCheck{
				{URL: "https://www.example.net/offer"},
				{URL: "https://example.org/spring"},
			},
		},
		{
			name: "links that designate no domain at all",
			links: []LinkCheck{
				{URL: "mailto:contact@example.net"},
				{URL: "tel:+15550100"},
				{URL: "https://example.com/{{UNSUB}}", IsTemplate: true},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if findings := offDomainFindings(t, tt.links...); len(findings) != 0 {
				t.Errorf("reported %d findings on a message it has nothing to say about: %v", len(findings), findings)
			}
		})
	}
}

// TestOffDomainLinksNeedsASender: a message naming no domain of its own has no
// identity to compare its destinations against, and the check says nothing
// rather than comparing them to nothing.
func TestOffDomainLinksNeedsASender(t *testing.T) {
	results := &Results{
		email: &mailmsg.Message{},
		Links: []LinkCheck{
			{URL: "https://www.example.net/offer"},
			{URL: "https://shop.example.org/spring"},
			{URL: "https://blog.example.org/why"},
		},
	}

	findings, err := offDomainLinksCheck.Run(context.Background(), results.checkInput())
	if err != nil {
		t.Fatalf("the check could not answer: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("reported %d findings about a message that names no sender: %v", len(findings), findings)
	}
}

// TestOffDomainLinksNamesWhatItCanAndCountsTheRest keeps the finding readable
// on a message linking to a dozen places: the first few destinations are
// named, the others counted.
func TestOffDomainLinksNamesWhatItCanAndCountsTheRest(t *testing.T) {
	links := []LinkCheck{
		{URL: "https://example.net/a"},
		{URL: "https://example.org/b"},
		{URL: "https://example.io/c"},
		{URL: "https://example.coop/d"},
		{URL: "https://example.museum/e"},
		{URL: "https://example.info/f"},
		{URL: "https://example.biz/g"},
	}

	findings := offDomainFindings(t, links...)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one: %v", len(findings), findings)
	}

	message := findings[0].Message
	if !strings.Contains(message, "and 2 others") {
		t.Errorf("the finding does not count the destinations it leaves unnamed: %s", message)
	}
	if strings.Contains(message, "example.biz") {
		t.Errorf("the finding names more destinations than a sentence holds: %s", message)
	}
}
