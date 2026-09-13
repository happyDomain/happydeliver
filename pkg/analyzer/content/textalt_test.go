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
	"slices"
	"strings"
	"testing"
)

// The body of a newsletter, and the text part a converter would produce from
// it. They are written out here rather than generated so that the wording of
// each is deliberate: what separates the levels is what the two say, and a
// generated pair would only ever agree.
const (
	newsletterHTML = `Spring collection is here
	Our spring collection arrives today, with forty new pieces in linen and
	cotton, cut in the workshop we opened last year outside Lyon. Every order
	over fifty euros ships free until the end of the month, and returns stay
	free for thirty days whatever the reason.
	Members get early access from Thursday morning, a second pair at half
	price, and the alterations we normally charge for done at no cost. If you
	are not a member yet, joining takes a minute and costs nothing.
	The linen comes from a mill in Normandy that has been weaving for four
	generations, and the cotton is grown without irrigation in Andalusia. We
	visit both every spring, and we publish what we pay for the cloth.
	Visit the shop to see the whole collection, or come to the Paris store,
	which stays open late on Thursdays through the season.
	You are receiving this because you subscribed. Unsubscribe at any time.
	Example Corp, 1 Rue de la Paix, Paris.`

	newsletterText = `Spring collection is here

	Our spring collection arrives today, with forty new pieces in linen and
	cotton, cut in the workshop we opened last year outside Lyon. Every order
	over fifty euros ships free until the end of the month, and returns stay
	free for thirty days whatever the reason.

	Members get early access from Thursday morning, a second pair at half
	price, and the alterations we normally charge for done at no cost. If you
	are not a member yet, joining takes a minute and costs nothing.

	The linen comes from a mill in Normandy that has been weaving for four
	generations, and the cotton is grown without irrigation in Andalusia. We
	visit both every spring, and we publish what we pay for the cloth.

	Visit the shop to see the whole collection, or come to the Paris store,
	which stays open late on Thursdays through the season:
	https://example.com/shop

	You are receiving this because you subscribed. Unsubscribe at any time:
	https://example.com/unsubscribe
	Example Corp, 1 Rue de la Paix, Paris.`

	// The previous campaign's text, left in place while the HTML was
	// rewritten. It shares its footer and much of its vocabulary with the HTML
	// above, and says something else entirely, which is the whole difficulty.
	previousCampaignText = `Winter sale ends tonight

	The winter sale ends tonight at midnight. Every coat and every scarf is
	half price, the last sizes are going fast, and what is left of the
	collection will not be restocked before autumn.

	Order before eight to get your parcel this week. Deliveries pause for the
	holidays from the twenty-fourth, and resume on the second of January.

	Our Paris store keeps its winter hours until Sunday, and the alterations
	counter closes an hour earlier than the shop floor for the rest of the
	week.

	You are receiving this because you subscribed. Unsubscribe at any time:
	https://example.com/unsubscribe
	Example Corp, 1 Rue de la Paix, Paris.`

	// What a sender writes instead of a text part, and what the recipient
	// reading their mail in a terminal is left with.
	stubText = `This email requires an HTML-capable email client. If you cannot
	read it, please view it in your browser.`
)

// TestTextAlternativeLevel reads the levels off the messages they are meant to
// name. The stale case is the one to watch: it is the most common defect of
// all, and the word-counting measure this replaced scored it as consistent.
func TestTextAlternativeLevel(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		html      string
		truncated bool
		want      textAltLevel
	}{
		{
			name: "a text part generated from the HTML",
			text: newsletterText,
			html: newsletterHTML,
			want: textAltOK,
		},
		{
			name: "last campaign's text left in place",
			text: previousCampaignText,
			html: newsletterHTML,
			want: textAltStale,
		},
		{
			name: "a text part standing in for the message",
			text: stubText,
			html: newsletterHTML,
			want: textAltStub,
		},
		{
			// A text part that says less than the HTML and nothing else is no
			// defect: what is asked of it is to be true, not exhaustive.
			name: "a faithful but shorter text part",
			text: newsletterText[:len(newsletterText)/2],
			html: newsletterHTML,
			want: textAltOK,
		},
		{
			name: "no text part at all",
			text: "",
			html: newsletterHTML,
			want: textAltAbsent,
		},
		{
			name: "a plain text message, with no HTML to contradict it",
			text: newsletterText,
			html: "",
			want: textAltOK,
		},
		{
			name:      "a body that stopped short",
			text:      previousCampaignText,
			html:      newsletterHTML,
			truncated: true,
			want:      textAltUnknown,
		},
		{
			name: "a message carrying neither part",
			want: textAltUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := textAlternativeLevel(tt.text, tt.html, tt.truncated); got != tt.want {
				t.Errorf("textAlternativeLevel() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestTextAlternativeSimilarityIgnoresSharedBoilerplate is the reason the
// measure counts sequences of words rather than words.
//
// The two texts here have nothing in common but the footer every campaign
// carries and the function words every sentence is made of. Counted word by
// word they overlap enough to pass for related, which is how a stale text
// alternative used to go unreported; counted three words at a time they do
// not.
func TestTextAlternativeSimilarityIgnoresSharedBoilerplate(t *testing.T) {
	stale := normalizeForComparison(previousCampaignText)
	fresh := normalizeForComparison(newsletterHTML)

	similarity := textAlternativeSimilarity(stale, fresh)
	if similarity >= textAltStaleSimilarity {
		t.Errorf("two unrelated campaigns scored %.2f, want below %.2f: shared boilerplate must not read as a shared message",
			similarity, textAltStaleSimilarity)
	}

	// The same text against itself is the other end of the scale, and pins
	// that the measure is not simply always low.
	if same := textAlternativeSimilarity(fresh, fresh); same != 1 {
		t.Errorf("a text compared to itself scored %.2f, want 1", same)
	}
}

func TestNormalizeForComparison(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "case and spacing",
			input: "  Hello   WORLD\t\nagain  ",
			want:  "hello world again",
		},
		{
			name:  "a destination the text part writes out",
			input: "Visit the shop: https://example.com/shop?id=4 today",
			want:  "visit the shop today",
		},
		{
			name:  "an address the HTML hides behind a word",
			input: "Write to us at mailto:hello@example.com now",
			want:  "write to us at now",
		},
		{
			name:  "the rules a converter underlines a heading with",
			input: "Spring collection\n=================\nis here",
			want:  "spring collection is here",
		},
		{
			name:  "the bullets a converter opens a list item with",
			input: "* first item\n- second item\n3. third item",
			want:  "first item second item third item",
		},
		{
			name:  "the marker a converter leaves where an image was",
			input: "[image: Spring banner] Spring is here",
			want:  "spring is here",
		},
		{
			name:  "words the punctuation belongs to",
			input: "Don't miss our well-known sale!",
			want:  "don't miss our well-known sale",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeForComparison(tt.input); got != tt.want {
				t.Errorf("normalizeForComparison(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestTextLinksMissingFromHTML pins which way the comparison is read and how
// tolerant it is: a destination is missing only when the HTML offers nothing
// leading to the same place, and the scheme is not part of that judgement.
func TestTextLinksMissingFromHTML(t *testing.T) {
	tests := []struct {
		name  string
		links []LinkCheck
		want  []string
	}{
		{
			name: "a destination only the text offers",
			links: []LinkCheck{
				{URL: "https://example.com/shop", InHTML: true, InText: true},
				{URL: "https://example.com/se-desabonner", InText: true},
			},
			want: []string{"https://example.com/se-desabonner"},
		},
		{
			name: "the same destination, written with two schemes",
			links: []LinkCheck{
				{URL: "https://example.com/shop", InHTML: true},
				{URL: "http://example.com/shop", InText: true},
			},
		},
		{
			name: "a bare www. address, whose scheme we synthesised",
			links: []LinkCheck{
				{URL: "https://www.example.com/shop", InHTML: true},
				{URL: "http://www.example.com/shop", InText: true},
			},
		},
		{
			name: "a host written in two cases",
			links: []LinkCheck{
				{URL: "https://Example.COM/shop", InHTML: true},
				{URL: "https://example.com/shop", InText: true},
			},
		},
		{
			name: "a destination only the HTML offers, which says nothing",
			links: []LinkCheck{
				{URL: "https://example.com/shop", InHTML: true, InText: true},
				{URL: "https://example.com/tracking/42", InHTML: true},
			},
		},
		{
			name: "two paths of one host are two destinations",
			links: []LinkCheck{
				{URL: "https://example.com/manage?lang=fr", InHTML: true},
				{URL: "https://example.com/se-desabonner", InText: true},
			},
			want: []string{"https://example.com/se-desabonner"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := textLinksMissingFromHTML(tt.links)
			if !slices.Equal(got, tt.want) {
				t.Errorf("textLinksMissingFromHTML() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTextAlternativeCheckSaysWhichDefect holds the report to naming what it
// found: the three levels a sender can act on say different things, because
// what they are to do about them differs.
func TestTextAlternativeCheckSaysWhichDefect(t *testing.T) {
	tests := []struct {
		level textAltLevel
		says  string
	}{
		{level: textAltStub, says: "fraction"},
		{level: textAltStale, says: "do not say the same thing"},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			in := (&Results{TextAlternative: tt.level}).checkInput()

			findings, err := textAlternativeCheck.Run(t.Context(), in)
			if err != nil {
				t.Fatalf("the check could not answer: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("the check reported %d findings, want one statement about the message", len(findings))
			}
			if !strings.Contains(findings[0].Message, tt.says) {
				t.Errorf("a %s text part is reported as %q, which does not say %q", tt.level, findings[0].Message, tt.says)
			}
			if findings[0].Concern == "" {
				t.Error("the finding carries no concern, so the spam filter saying the same would be reported twice")
			}
		})
	}

	// The levels that hold nothing against the sender say nothing.
	for _, level := range []textAltLevel{textAltOK, textAltAbsent, textAltUnknown} {
		t.Run("silent on "+level.String(), func(t *testing.T) {
			in := (&Results{TextAlternative: level}).checkInput()

			findings, err := textAlternativeCheck.Run(t.Context(), in)
			if err != nil {
				t.Fatalf("the check could not answer: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("the check reported %d findings on a %s text part, want none", len(findings), level)
			}
		})
	}
}
