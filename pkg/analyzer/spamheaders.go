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

package analyzer

import (
	"regexp"
	"strconv"
	"strings"
)

// parseFloat32 parses a header field as a float32, reporting whether it held a
// number.
func parseFloat32(s string) (float32, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return float32(v), true
}

// extractFloatField parses re's first capture group in header as a float32.
func extractFloatField(header string, re *regexp.Regexp) (float32, bool) {
	matches := re.FindStringSubmatch(header)
	if len(matches) < 2 {
		return 0, false
	}
	return parseFloat32(matches[1])
}

// The threshold both scanners report the same way in their X-Spam-Status, e.g.
// "required=5.0". The leading boundary keeps another scanner's prefixed field
// from being read as this one.
var spamStatusRequiredRe = regexp.MustCompile(`(?i)(?:^|[^\w-])required=(-?\d+\.?\d*)`)

// rspamdOnlySpamHeaders lists the headers only rspamd ever writes: their name
// alone identifies their author. rspamd's milter_headers writes a bare X-Spam
// when it acts on a message, and stamps the X-Rspamd-* ones on every message it
// touches; SpamAssassin has no header of its own, which is why this list has no
// counterpart.
var rspamdOnlySpamHeaders = []string{
	"X-Spam",
	"X-Spamd-Result",
	"X-Rspamd-Score",
	"X-Rspamd-Action",
	"X-Rspamd-Server",
	"X-Rspamd-Queue-Id",
}

// ambiguousSpamHeaders lists the headers SpamAssassin and rspamd both write:
// rspamd's milter_headers module reproduces SpamAssassin's naming so existing
// filters keep working. Only their value or the company they keep tells.
var ambiguousSpamHeaders = []string{
	"X-Spam-Status",
	"X-Spam-Score",
	"X-Spam-Flag",
	"X-Spam-Level",
	"X-Spam-Report",
	"X-Spam-Checker-Version",
}

// rspamdVerdictHeaders both name rspamd as their author and show it reported on
// the message. A mere server stamp (X-Rspamd-Server and the like) is left out:
// it says rspamd passed by, not that it wrote the SpamAssassin-named headers.
var rspamdVerdictHeaders = []string{"X-Spam", "X-Spamd-Result", "X-Rspamd-Score"}

// hasAnySpamHeader reports whether an attributed bucket holds at least one of
// the named headers.
func hasAnySpamHeader(headers map[string]string, names ...string) bool {
	for _, name := range names {
		if _, ok := headers[name]; ok {
			return true
		}
	}
	return false
}

// spamShapedVerdict is what the SpamAssassin-shaped headers say about a
// message: the score of X-Spam-Score and the Yes/No of X-Spam-Flag. Both
// scanners write these names, so they are read out of the bucket
// SpamScannerHeaders already attributed, and only for what that scanner's own
// authoritative header left unsaid.
type spamShapedVerdict struct {
	score      float32
	hasScore   bool
	isSpam     bool
	hasVerdict bool
}

func readSpamShapedVerdict(headers map[string]string) spamShapedVerdict {
	var verdict spamShapedVerdict

	if scoreHeader, ok := headers["X-Spam-Score"]; ok {
		verdict.score, verdict.hasScore = parseFloat32(scoreHeader)
	}

	if flagHeader, ok := headers["X-Spam-Flag"]; ok {
		verdict.isSpam = strings.EqualFold(strings.TrimSpace(flagHeader), "YES")
		verdict.hasVerdict = true
	}

	return verdict
}

// SpamHeaderSet groups a message's spam-scanner headers by the scanner that
// wrote them.
type SpamHeaderSet struct {
	SpamAssassin map[string]string
	Rspamd       map[string]string
}

// SpamScannerHeaders routes every spam-related header of the message to its
// author:
//
//  1. a header only rspamd ever writes goes to rspamd;
//  2. an X-Spam-Status goes to whoever its value names;
//  3. any other ambiguous header goes to rspamd when rspamd reported a verdict
//     of its own, and to SpamAssassin otherwise, its naming convention being the
//     one rspamd merely borrows.
func (e *EmailMessage) SpamScannerHeaders() SpamHeaderSet {
	set := SpamHeaderSet{
		SpamAssassin: map[string]string{},
		Rspamd:       map[string]string{},
	}

	for _, name := range rspamdOnlySpamHeaders {
		if value := e.firstSpamHeader(name); value != "" {
			set.Rspamd[name] = value
		}
	}

	// Who an ambiguous header belongs to when its own value names nobody. An
	// X-Spam-Status carrying "rspamdscore=" counts as a verdict of rspamd's own,
	// just like the headers it names itself in.
	rspamdOwnsMuteHeaders := hasAnySpamHeader(set.Rspamd, rspamdVerdictHeaders...) ||
		strings.Contains(strings.ToLower(e.firstSpamHeader("X-Spam-Status")), "rspamdscore=")

	for _, name := range ambiguousSpamHeaders {
		// The names above are in canonical MIME form, which is how the header
		// map is keyed, so indexing it directly finds every occurrence.
		for _, value := range e.Header[name] {
			if strings.TrimSpace(value) == "" {
				continue
			}

			target := set.SpamAssassin
			if writtenByRspamd(name, value, rspamdOwnsMuteHeaders) {
				target = set.Rspamd
			}

			// A scanner writes a given header once; should a relay have added
			// its own, keep the topmost occurrence, the one the last hop wrote.
			if _, seen := target[name]; !seen {
				target[name] = value
			}
		}
	}

	return set
}

// firstSpamHeader returns the topmost non-blank occurrence of a header, the one
// the last hop wrote.
func (e *EmailMessage) firstSpamHeader(name string) string {
	for _, value := range e.Header[name] {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// writtenByRspamd reports whether rspamd wrote this occurrence of a header both
// scanners write. Only X-Spam-Status ever gives its author away in its own
// value: rspamd's variant carries its score as "rspamdscore=", SpamAssassin's
// lists the rules it ran. A header saying nothing of its author, this one
// included, follows the fallback the caller worked out for the whole message.
func writtenByRspamd(name, value string, fallback bool) bool {
	if name != "X-Spam-Status" {
		return fallback
	}

	lower := strings.ToLower(value)

	switch {
	case strings.Contains(lower, "rspamdscore="):
		return true
	case spamAssassinStatusScoreRe.MatchString(value),
		strings.Contains(lower, "tests="),
		strings.Contains(lower, "autolearn="):
		return false
	default:
		return fallback
	}
}
