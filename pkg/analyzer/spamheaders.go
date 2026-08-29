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
	"strings"
)

// SpamScanner names a spam filter able to leave a verdict in a message's
// headers.
type SpamScanner string

const (
	ScannerSpamAssassin SpamScanner = "spamassassin"
	ScannerRspamd       SpamScanner = "rspamd"
)

// The threshold every scanner reports the same way in its X-Spam-Status, e.g.
// "required=5.0". The leading boundary keeps another scanner's prefixed field
// from being read as this one.
var spamStatusRequiredRe = regexp.MustCompile(`(?i)(?:^|[^\w-])required=(-?\d+\.?\d*)`)

// sharedSpamHeaders lists the headers no scanner has to itself: SpamAssassin
// established these names, and the others reproduce them so that existing
// filters keep working — rspamd's milter_headers module does, and any filter
// added later most likely will too. Only their value or the company they keep
// tells who wrote them.
var sharedSpamHeaders = []string{
	"X-Spam-Status",
	"X-Spam-Score",
	"X-Spam-Flag",
	"X-Spam-Level",
	"X-Spam-Report",
	"X-Spam-Checker-Version",
}

// sharedSpamHeadersOwner is who a shared header belongs to when nothing in the
// message says otherwise: the naming convention is SpamAssassin's, the others
// merely borrow it.
const sharedSpamHeadersOwner = ScannerSpamAssassin

// spamScannerProfile describes how a scanner shows itself in a message's
// headers. Teaching happyDeliver a new filter is adding a profile here, then an
// analyzer reading the bucket SpamScannerHeaders fills for it.
type spamScannerProfile struct {
	scanner SpamScanner

	// ownHeaders are the names only this scanner ever writes: the name alone
	// identifies the author. A scanner writing nothing but the shared names,
	// SpamAssassin being the first of them, has none.
	ownHeaders []string

	// verdictHeaders are those of ownHeaders whose presence proves the scanner
	// reported on this very message, as opposed to merely stamping the hosts it
	// went through.
	verdictHeaders []string

	// signatures are the patterns giving the scanner away in the value of a
	// shared header, keyed by that header's name. Such a value both attributes
	// its own header and counts as a verdict of the scanner's own.
	signatures map[string]*regexp.Regexp

	// borrowsSharedNames tells whether the scanner writes the shared names on
	// top of its own, and may therefore be credited the ones that name nobody.
	borrowsSharedNames bool
}

// spamScannerProfiles is consulted in order: the first profile whose signature
// a value bears is credited with it, so a more specific pattern belongs before
// a looser one.
var spamScannerProfiles = []spamScannerProfile{
	{
		scanner: ScannerRspamd,
		// milter_headers writes a bare X-Spam when it acts on a message, and
		// stamps the X-Rspamd-* ones on every message it touches.
		ownHeaders: []string{
			"X-Spam",
			"X-Spamd-Result",
			"X-Rspamd-Score",
			"X-Rspamd-Action",
			"X-Rspamd-Server",
			"X-Rspamd-Queue-Id",
		},
		// A mere server stamp (X-Rspamd-Server and the like) is left out: it
		// says rspamd passed by, not that it wrote the shared headers.
		verdictHeaders: []string{"X-Spam", "X-Spamd-Result", "X-Rspamd-Score"},
		signatures:     map[string]*regexp.Regexp{"X-Spam-Status": rspamdStatusScoreRe},

		borrowsSharedNames: true,
	},
	{
		scanner:    ScannerSpamAssassin,
		signatures: map[string]*regexp.Regexp{"X-Spam-Status": spamAssassinStatusSignatureRe},
	},
}

// ScannerHeaders holds the headers one scanner wrote, keyed by header name in
// canonical MIME form.
type ScannerHeaders map[string]string

// Has reports whether at least one of the named headers is present.
func (h ScannerHeaders) Has(names ...string) bool {
	for _, name := range names {
		if _, ok := h[name]; ok {
			return true
		}
	}

	return false
}

// SpamHeaderSet groups a message's spam-scanner headers by the scanner that
// wrote them.
type SpamHeaderSet map[SpamScanner]ScannerHeaders

// For returns the headers attributed to a scanner, empty when it left none.
func (s SpamHeaderSet) For(scanner SpamScanner) ScannerHeaders {
	return s[scanner]
}

// SpamScannerHeaders routes every spam-related header of the message to its
// author:
//
//  1. a header only one scanner ever writes goes to that scanner;
//  2. a shared header goes to whoever its value names;
//  3. any other shared header goes to the scanner that borrows these names when
//     it reported a verdict of its own, and to the convention's owner
//     otherwise.
func (e *EmailMessage) SpamScannerHeaders() SpamHeaderSet {
	set := SpamHeaderSet{}

	for _, profile := range spamScannerProfiles {
		headers := ScannerHeaders{}
		set[profile.scanner] = headers

		for _, name := range profile.ownHeaders {
			if value := e.firstSpamHeader(name); value != "" {
				headers[name] = value
			}
		}
	}

	// Who a shared header belongs to when its own value names nobody. A borrower
	// actively stamping verdicts is the one that duplicates the naming, so the
	// duplicates are its; crediting them to neither would be safer still, but it
	// would throw away the only score some messages carry.
	claimant := sharedSpamHeadersOwner
	for _, profile := range spamScannerProfiles {
		if profile.borrowsSharedNames && profile.reportedVerdict(e, set[profile.scanner]) {
			claimant = profile.scanner
			break
		}
	}

	for _, name := range sharedSpamHeaders {
		// The names above are in canonical MIME form, which is how the header
		// map is keyed, so indexing it directly finds every occurrence.
		for _, value := range e.Header[name] {
			if strings.TrimSpace(value) == "" {
				continue
			}

			owner := claimant
			if signer, ok := spamHeaderSigner(name, value); ok {
				owner = signer
			}

			// A scanner writes a given header once; should a relay have added
			// its own, keep the topmost occurrence, the one the last hop wrote.
			if !set[owner].Has(name) {
				set[owner][name] = value
			}
		}
	}

	return set
}

// reportedVerdict reports whether the scanner did more than pass by: a header
// of its own carrying a verdict, or its signature in a shared one.
func (p spamScannerProfile) reportedVerdict(e *EmailMessage, own ScannerHeaders) bool {
	if own.Has(p.verdictHeaders...) {
		return true
	}

	for name, signature := range p.signatures {
		if signature.MatchString(e.firstSpamHeader(name)) {
			return true
		}
	}

	return false
}

// spamHeaderSigner names the scanner whose signature this occurrence of a shared
// header bears. Only X-Spam-Status ever gives its author away in its own value:
// rspamd's variant carries its score as "rspamdscore=", SpamAssassin's lists the
// rules it ran. A header saying nothing of its author, this one included,
// follows the fallback the caller worked out for the whole message.
func spamHeaderSigner(name, value string) (SpamScanner, bool) {
	for _, profile := range spamScannerProfiles {
		if signature, ok := profile.signatures[name]; ok && signature.MatchString(value) {
			return profile.scanner, true
		}
	}

	return "", false
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

// sharedSpamVerdict is what the shared headers say about a message: the score of
// X-Spam-Score and the Yes/No of X-Spam-Flag. Every scanner writes these names,
// so they are read out of the bucket SpamScannerHeaders already attributed, and
// only for what that scanner's own authoritative header left unsaid.
type sharedSpamVerdict struct {
	score      float32
	hasScore   bool
	isSpam     bool
	hasVerdict bool
}

func readSharedSpamVerdict(headers ScannerHeaders) sharedSpamVerdict {
	var verdict sharedSpamVerdict

	if scoreHeader, ok := headers["X-Spam-Score"]; ok {
		verdict.score, verdict.hasScore = parseFloat32(scoreHeader)
	}

	if flagHeader, ok := headers["X-Spam-Flag"]; ok {
		verdict.isSpam = strings.EqualFold(strings.TrimSpace(flagHeader), "YES")
		verdict.hasVerdict = true
	}

	return verdict
}
