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

package authresults

import "strings"

// segment is one piece of the field between two semicolons: the words it is
// written with, the comments written among them, and the text itself.
type segment struct {
	words    []string
	comments []string
	raw      string
}

// glueChars are the characters that bind two words into one element of the
// grammar: a method to its version, a ptype to its property, and either of
// them to the value that follows.
const glueChars = "=./"

// scan walks the field once and cuts it into its segments.
//
// It is where the two liberties the grammar takes are answered. A comment may
// appear between any two elements and may hold anything at all, semicolons and
// parentheses of its own included, so it is read to its matching parenthesis
// and set aside rather than read as content. A value may be a quoted string,
// so it is read to its closing quote and kept as one word, spaces and all.
func scan(value string) []segment {
	var (
		segments []segment
		current  segment
		word     strings.Builder
		comment  strings.Builder
		depth    int
		start    int
	)

	// endWord ends the word being read, if one is.
	endWord := func() {
		if word.Len() > 0 {
			current.words = append(current.words, word.String())
			word.Reset()
		}
	}

	for i := 0; i < len(value); i++ {
		c := value[i]

		switch {
		case depth > 0:
			switch c {
			case '(':
				depth++
				comment.WriteByte(c)
			case ')':
				if depth--; depth == 0 {
					current.comments = append(current.comments, comment.String())
					comment.Reset()
				} else {
					comment.WriteByte(c)
				}
			case '\\':
				// A quoted pair carries whatever follows it, a
				// parenthesis included, which would otherwise close
				// the comment early.
				if i++; i < len(value) {
					comment.WriteByte(value[i])
				}
			default:
				comment.WriteByte(c)
			}

		case c == '(':
			depth = 1
			endWord()

		case c == '"':
			i = readQuoted(value, i, &word)

		case c == ';':
			endWord()
			current.raw = strings.TrimSpace(value[start:i])
			segments = append(segments, current)

			current, start = segment{}, i+1

		case c == ' ', c == '\t', c == '\r', c == '\n':
			endWord()

		default:
			word.WriteByte(c)
		}
	}

	// A comment nobody closed takes the rest of the field with it, which is
	// what a reader of the message sees too.
	endWord()
	current.raw = strings.TrimSpace(value[start:])

	return append(segments, current)
}

// readQuoted reads a quoted string into the word being read, without its
// quotes, and answers the index of its closing quote.
//
// A string nobody closed ends where the segment it was written in ends: the
// receiver wrote a quote it did not mean, and that must not cost the reader
// every method written after the next semicolon. A semicolon inside a string
// that is closed is part of the value, so the whole string is read before
// either answer is given.
func readQuoted(value string, open int, word *strings.Builder) int {
	var (
		content strings.Builder
		cut     = -1
		end     int
	)

	for i := open + 1; i < len(value); i++ {
		switch c := value[i]; c {
		case '"':
			word.WriteString(content.String())
			return i
		case '\\':
			if i++; i < len(value) {
				content.WriteByte(value[i])
			}
		default:
			if c == ';' && cut < 0 {
				cut, end = content.Len(), i
			}
			content.WriteByte(c)
		}
	}

	if cut < 0 {
		word.WriteString(content.String())
		return len(value)
	}

	// The semicolon itself is left to the caller to read as the separator
	// it is.
	word.WriteString(content.String()[:cut])

	return end - 1
}

// glue joins the words that the grammar allows a comment or a fold to have
// separated: "dkim (a) / (b) 1 (c) = (d) fail" is written as five words and is
// one methodspec.
//
// A word binds to the next one only while it is still waiting for something
// the grammar owes it: "header." waits for the property it names, "dkim=" for
// its result. A word that already carries its value waits for nothing, so
// "header.b=Zm9v==" and "header.d=example.com." are properties that are
// finished, whatever character they end on.
func glue(words []string) []string {
	var items []string

	bindNext := false
	for i, word := range words {
		switch {
		case (bindNext || bindsToPrevious(word)) && len(items) > 0:
			items[len(items)-1] += word
		default:
			items = append(items, word)
		}

		var next string
		if i+1 < len(words) {
			next = words[i+1]
		}

		bindNext = bindsToNext(word, next)
	}

	return items
}

// bindsToPrevious says whether a word opens with a character that binds it to
// the word before it.
func bindsToPrevious(word string) bool {
	return word != "" && strings.IndexByte(glueChars, word[0]) >= 0
}

// bindsToNext says whether a word ends waiting for the word after it.
func bindsToNext(word string, next string) bool {
	if word == "" {
		return false
	}

	switch last := word[len(word)-1]; last {
	case '.', '/':
		// A dot and a slash join a ptype to its property and a method to
		// its version, both of which are written before the equals sign.
		// After it they are part of a value: a domain written down to its
		// root, or a URL.
		return strings.IndexByte(word, '=') < 0
	case '=':
		if strings.IndexByte(word, '=') != len(word)-1 {
			return false
		}

		// A value the receiver left empty is written the same way as one
		// the next word carries, so the next word answers for both: a
		// word naming a ptype and a property of its own is never the
		// value of the property before it.
		return !startsProperty(next)
	default:
		return false
	}
}

// startsProperty says whether a word opens a propspec of its own, written with
// the ptype the grammar asks for: "header.d=example.com".
func startsProperty(word string) bool {
	equals := strings.IndexByte(word, '=')
	if equals < 0 {
		return false
	}

	return strings.IndexByte(word[:equals], '.') >= 0
}
