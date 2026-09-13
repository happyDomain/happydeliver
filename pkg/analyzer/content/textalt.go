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
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// textAltLevel says how the plain text part stands to the HTML part.
//
// It is what the score and the report both read, rather than the raw
// similarity: a number invites each reader to set its own threshold, and two
// readers with two thresholds are two answers to one question.
type textAltLevel int

const (
	// textAltUnknown is the zero value on purpose: a message nobody measured
	// must not read as a verdict. The consistency criterion leaves the scale
	// on it, as it already does for a body that stopped short.
	textAltUnknown textAltLevel = iota

	// textAltOK: the text part says what the HTML says, or there is no HTML
	// for it to contradict.
	//
	// It covers a text part that says less than the HTML and nothing else: a
	// terse but faithful summary is a choice, not a defect, and a text part
	// that carries so little of the message that it stands in for it rather
	// than states it is caught by its length instead.
	textAltOK

	// textAltStale: both parts are substantial and they say different things.
	// The usual cause is the text of the previous campaign, left in place
	// while the HTML was rewritten.
	textAltStale

	// textAltStub: the text part is a fraction of the HTML, carrying none of
	// the message. Most often it announces that the reader's client cannot
	// display HTML, which is a statement the reader's client rarely agrees
	// with.
	textAltStub

	// textAltAbsent: no text part at all.
	textAltAbsent
)

// String names the level for the tests and the logs. It is never shown to a
// reader of the report, who gets a sentence instead.
func (l textAltLevel) String() string {
	switch l {
	case textAltOK:
		return "ok"
	case textAltStale:
		return "stale"
	case textAltStub:
		return "stub"
	case textAltAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// The thresholds the level is read off. They are deliberately lenient: a text
// part generated from the HTML still differs from it in ways nothing can
// normalise away (a footer the converter writes out, an image caption it drops),
// and a message wrongly told its parts disagree is worse than one whose mild
// drift goes unmentioned.
const (
	// textAltStubLengthRatio: below this share of the HTML's text, the text
	// part is not an alternative but a placeholder. Three lines against a
	// full newsletter sit far under it; a terse but honest text part does not.
	textAltStubLengthRatio = 0.15

	// textAltStaleSimilarity: below this, the two parts have almost nothing in
	// common but their boilerplate.
	//
	// It is placed on evidence rather than on taste. Over the fixtures, a text
	// part generated from its HTML scores between 0.50 and 0.91, and one left
	// from another campaign scores 0.00; the line sits in that gap, closer to
	// the second, so that a sender is told their parts disagree only when they
	// plainly do.
	//
	// What it lets through is a short message whose footer is a large share of
	// its text: boilerplate two campaigns share weighs more the less there is
	// beside it, and such a pair can score above the line. Missing one is the
	// side to err on, a sender wrongly told their parts disagree having no way
	// to prove otherwise.
	textAltStaleSimilarity = 0.35
)

// textAlternativeLevel grades the text part against the HTML part.
//
// It is computed once, when the message is read, and carried on the results:
// the criterion of the score and the check of the report read that one answer
// rather than each measuring again.
func textAlternativeLevel(textContent, htmlText string, bodyTruncated bool) textAltLevel {
	// A body that stopped short may be missing the very part being compared,
	// so nothing is said about it: the criterion leaves the scale instead of
	// failing a message for bytes that never arrived.
	if bodyTruncated {
		return textAltUnknown
	}

	text := normalizeForComparison(textContent)
	html := normalizeForComparison(htmlText)

	if text == "" {
		// A message made of HTML alone. Nothing here says whether that is a
		// good idea: the plaintext_alternative criterion answers for it.
		if html == "" {
			return textAltUnknown
		}
		return textAltAbsent
	}

	// No HTML to contradict the text: a plain text message is coherent with
	// itself. This is where the old code wrote a similarity of 1.0, which read
	// as "the two parts agree perfectly" for a message that had only one.
	if html == "" {
		return textAltOK
	}

	// A text part that is a fraction of the HTML carries none of the message,
	// however many words it happens to share with it. The length is read
	// before the similarity for that reason: a three-line stub quoting the
	// subject line can score deceptively well.
	if float64(len(text))/float64(len(html)) < textAltStubLengthRatio {
		return textAltStub
	}

	if textAlternativeSimilarity(text, html) < textAltStaleSimilarity {
		return textAltStale
	}

	return textAltOK
}

// textAlternativeSimilarity measures how much two normalised texts say the
// same thing, between 0 and 1.
//
// It compares sequences of three words rather than words taken one by one,
// and that is the whole point. Function words ("the", "your", "de", "vous")
// make up a third of any text and are the same from one mailing to the next;
// so is the footer every campaign carries, its legal notice, its postal
// address, its unsubscribe line. Counting words alone, two texts with nothing
// in common land around a third of a match, which is where a threshold would
// have to sit, and the most common defect of all, last campaign's text left
// in place, passes unnoticed.
//
// Three consecutive words have to match for a trigram to, which no amount of
// shared vocabulary achieves by accident. It needs no word list and no
// language detection, which matters for a service that reads mail in any
// language.
func textAlternativeSimilarity(text, html string) float64 {
	textGrams := trigrams(text)
	htmlGrams := trigrams(html)

	if len(textGrams) == 0 || len(htmlGrams) == 0 {
		// Too short to have any trigram: fall back to the words themselves,
		// where a handful of them is all there is to compare.
		textGrams = wordSet(text)
		htmlGrams = wordSet(html)

		if len(textGrams) == 0 || len(htmlGrams) == 0 {
			return 0
		}
	}

	common := 0
	for gram := range textGrams {
		if _, shared := htmlGrams[gram]; shared {
			common++
		}
	}

	// Measured against the smaller of the two, which is the text part in any
	// ordinary message: what is asked is how much of what the text says the
	// HTML says too. A text part that is faithful but short scores full marks,
	// and rightly: it says nothing the message does not. Dividing by the HTML
	// instead would grade every message on how much of it the text repeats,
	// which is a different question, and one whose honest answer is usually
	// "less than all of it".
	smaller := min(len(textGrams), len(htmlGrams))

	return float64(common) / float64(smaller)
}

// trigrams cuts a normalised text into the set of its three-word sequences.
func trigrams(text string) map[string]struct{} {
	words := strings.Fields(text)
	if len(words) < 3 {
		return nil
	}

	grams := make(map[string]struct{}, len(words)-2)
	for i := 0; i+3 <= len(words); i++ {
		grams[strings.Join(words[i:i+3], " ")] = struct{}{}
	}

	return grams
}

// wordSet is what a text too short for trigrams is compared on instead.
func wordSet(text string) map[string]struct{} {
	words := strings.Fields(text)

	set := make(map[string]struct{}, len(words))
	for _, word := range words {
		set[word] = struct{}{}
	}

	return set
}

var (
	// bareURLRegex matches the destinations a text part writes out in full.
	// The HTML part hides them behind the text of an anchor, so leaving them
	// in would count as a difference what is only a difference of medium.
	bareURLRegex = regexp.MustCompile(`(?i)\b(?:https?://|mailto:|www\.)\S+`)

	// converterDecorationRegex matches what a HTML-to-text converter draws to
	// stand in for markup: the rules it underlines headings with, the bullets
	// it opens list items with, the pipes it rules tables with, the markers it
	// leaves where an image was.
	converterDecorationRegex = regexp.MustCompile(`(?im)^[ \t]*(?:[=\-*_~#+|>]{2,}|[*\-+•·]|\d+[.)])[ \t]*|\[(?:image|cid|img)[^\]]*\]|[|>]`)
)

// normalizeForComparison reduces a text to what it says, so that two texts
// saying the same thing in two media compare equal.
//
// It is applied to both sides, so anything it removes is removed from both:
// what it costs is never a difference it invents, only one it declines to see.
func normalizeForComparison(text string) string {
	text = strings.ToLower(text)

	// The destinations first: a URL carries punctuation and separators of its
	// own, and taking it out before the rest keeps its remains from being read
	// as words.
	text = bareURLRegex.ReplaceAllString(text, " ")
	text = converterDecorationRegex.ReplaceAllString(text, " ")

	// Punctuation apart, letters and digits are what carries the meaning.
	// Apostrophes and hyphens are kept inside words, where they belong to the
	// word rather than separating two.
	text = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsNumber(r):
			return r
		case r == '\'' || r == '’' || r == '-':
			return r
		default:
			return ' '
		}
	}, text)

	return strings.Join(strings.Fields(text), " ")
}

// textLinksMissingFromHTML lists the destinations the text part writes and the
// HTML part does not, in the order the text writes them.
//
// Only this direction is read. The text part is the poorer of the two in
// links, so a destination it carries and the HTML does not is a sign the two
// were not generated together; the reverse, a newsletter whose HTML links far
// more than its text spells out, is the normal shape of a mailing and says
// nothing about the sender.
func textLinksMissingFromHTML(links []LinkCheck) []string {
	inHTML := make(map[string]struct{}, len(links))
	for _, link := range links {
		if link.InHTML {
			inHTML[comparableURL(link.URL)] = struct{}{}
		}
	}

	var missing []string
	for _, link := range links {
		if !link.InText || link.InHTML {
			continue
		}
		if _, found := inHTML[comparableURL(link.URL)]; !found {
			missing = append(missing, link.URL)
		}
	}

	return missing
}

// comparableURL is the form two URLs are held to be the same destination
// under.
//
// The scheme is dropped and the host lowercased. A text part writes an address
// bare where the HTML writes it with a scheme, and analyzeTextLinks puts an
// "http://" in front of a "www." the sender never typed: comparing schemes
// would report those as divergences the sender cannot act on.
//
// Nothing more is normalised. Dropping a trailing slash or sorting a query
// would call two URLs the same where a server does not, and here that would
// silence a real finding rather than merely untidy the report.
func comparableURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(rawURL))
	}

	parsed.Scheme = ""
	parsed.Host = strings.ToLower(parsed.Host)

	return strings.TrimPrefix(parsed.String(), "//")
}
