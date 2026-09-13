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
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"net/mail"
	"slices"
	"testing"
)

// TestSenderDomains reads the identities a message is sent under off its
// headers. What matters is that each of the three sources is read, that they
// are folded onto the registrable domain, and that a domain named twice is
// listed once: the list is compared against the destinations, and a duplicate
// there would say nothing more.
func TestSenderDomains(t *testing.T) {
	for _, tt := range []struct {
		name  string
		email *mailmsg.Message
		want  []string
	}{
		{
			name:  "no message at all",
			email: nil,
		},
		{
			name:  "a message naming nobody",
			email: &mailmsg.Message{},
		},
		{
			name:  "the From header alone",
			email: &mailmsg.Message{From: &mail.Address{Address: "news@mail.example.com"}},
			want:  []string{"example.com"},
		},
		{
			name: "a From header the parser could not turn into an address",
			email: &mailmsg.Message{Header: mail.Header{
				"From": []string{"Example Corp <news@example.com>"},
			}},
			want: []string{"example.com"},
		},
		{
			name: "the three sources, the From first",
			email: &mailmsg.Message{
				From:       &mail.Address{Address: "news@example.com"},
				ReturnPath: "<bounces+42@bounce.example.net>",
				Header: mail.Header{"Dkim-Signature": []string{
					"v=1; a=rsa-sha256; d=example.org; s=selector1; h=from",
					"v=1; a=ed25519-sha256; d=mail.example.com; s=selector2; h=from",
				}},
			},
			// example.com is named by both the From and the second signature,
			// and appears once.
			want: []string{"example.com", "example.net", "example.org"},
		},
		{
			name: "a signature with no selector, which is no signature",
			email: &mailmsg.Message{
				From:   &mail.Address{Address: "news@example.com"},
				Header: mail.Header{"Dkim-Signature": []string{"v=1; d=example.org"}},
			},
			want: []string{"example.com"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := senderDomains(tt.email)
			if !slices.Equal(got, tt.want) {
				t.Errorf("senderDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDestinationDomains reads where the body leads. The point of the helper
// is that it answers on the destinations rather than on what the message
// wrote: a link redirected elsewhere counts for where it lands.
func TestDestinationDomains(t *testing.T) {
	results := &Results{
		Links: []LinkCheck{
			// Two subdomains of one registrable domain, which is one
			// destination.
			{URL: "https://shop.example.com/spring"},
			{URL: "https://blog.example.com/spring"},
			// A tracker whose redirection was followed: what it forwards to is
			// the destination, not the tracker.
			{
				URL:       "https://click.tracker.example.org/abc123",
				probedURL: probedURL{FinalURL: "https://www.example.net/offer"},
			},
			// A tracker nothing followed, which is all we know of it.
			{URL: "https://click.tracker.example.org/def456"},
			// Neither of these designates a registrable domain.
			{URL: "mailto:contact@example.coop"},
			{URL: "https://198.51.100.7/login"},
			{URL: "https://example.com/{{UNSUB}}", IsTemplate: true},
		},
		// An image source and an unsubscribe address are destinations of
		// another kind, and are not read here.
		Images:            []ImageCheck{{Src: "https://cdn.example.io/banner.png"}},
		UnsubscribeChecks: []LinkCheck{{URL: "https://unsub.example.systems/42"}},
	}

	// The tracker nothing followed stands for itself, folded onto its
	// registrable domain like any other host.
	want := []string{"example.com", "example.net", "example.org"}
	if got := results.destinationDomains(); !slices.Equal(got, want) {
		t.Errorf("destinationDomains() = %v, want %v", got, want)
	}
}
