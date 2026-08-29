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
	_ "embed"
	"strings"
	"sync"
)

// shortenersList is the url-shorteners list by PeterDave Hello and
// contributors (https://github.com/PeterDaveHello/url-shorteners), embedded
// verbatim and licensed CC-BY-SA-4.0. See THIRD-PARTY-NOTICES.md, and
// data/url-shorteners.LICENSE for the license text.
//
//go:embed data/url-shorteners.list
var shortenersList string

// shortenersLicense is the CC-BY-SA-4.0 license text shipped alongside the
// list, so that binary-only recipients of happyDeliver (a release artifact, a
// container image) get the notices the license requires along with the data.
//
//go:embed data/url-shorteners.LICENSE
var shortenersLicense string

// shortenersAttribution is the credit CC-BY-SA-4.0 section 3(a)(1) asks for.
const shortenersAttribution = `URL shortener domain list
-------------------------

Copyright (c) PeterDave Hello and contributors
Source:  https://github.com/PeterDaveHello/url-shorteners
License: Creative Commons Attribution-ShareAlike 4.0 International
         (CC-BY-SA-4.0), https://creativecommons.org/licenses/by-sa/4.0/
Changes: none, the list is embedded exactly as published upstream. The
         services happyDeliver adds to it, and the branded short links it
         leaves out, live in its own source code, not in this list.

This material is provided as-is, without warranties, as stated in sections 5
and 6 of the license reproduced below.`

// ThirdPartyNotices returns the attribution and license notices for the
// third-party data embedded in this package.
func ThirdPartyNotices() string {
	return shortenersAttribution + "\n\n" + shortenersLicense
}

// extraShorteners are shortening services missing from the embedded list.
var extraShorteners = []string{
	"gg.gg",     // shortening service, widely reported as abused for phishing
	"shrtco.de", // shrtcode, shortening service and API
	"spoo.me",   // open-source link shortener, self-hostable
}

// brandedShortHosts are hosts the embedded list counts as shorteners but which
// only ever lead to one company's own content. The shortener finding says the
// recipient cannot see where the link leads; for these hosts that is untrue —
// "youtu.be/..." is the canonical way to link a YouTube video, not a way to
// hide a destination — so an ordinary email linking to a video, a track or a
// chat must not be flagged.
//
// A general-purpose shortener stays in the list even when a well-known company
// runs it: "goo.gl", "t.co", "buff.ly" and their kind wrap arbitrary URLs.
var brandedShortHosts = []string{
	"youtu.be", // YouTube video
	"amzn.to",  // Amazon
	"apple.co", // Apple
	"spoti.fi", // Spotify
	"fb.me",    // Facebook
	"m.me",     // Facebook Messenger
	"wa.me",    // WhatsApp click-to-chat
	"lnkd.in",  // LinkedIn
	"g.co",     // Google (registry-restricted to Google properties)
	"msft.it",  // Microsoft
	"pin.it",   // Pinterest
	"flic.kr",  // Flickr
	"redd.it",  // Reddit
	"t.me",     // Telegram
}

// urlShorteners is the set of public URL shortening services recognised by
// analyzeURLSuspicions. A link going through one of them hides its real
// destination from the recipient, which is both a phishing pattern and a
// deliverability penalty.
//
// Matching is done by isShortenerHost on the whole host (optionally prefixed
// with "www.").
var urlShorteners = sync.OnceValue(loadURLShorteners)

// loadURLShorteners parses the embedded list, applies the local overlays and
// normalises every entry the way isShortenerHost looks them up.
func loadURLShorteners() map[string]struct{} {
	shorteners := make(map[string]struct{}, strings.Count(shortenersList, "\n"))

	for line := range strings.Lines(shortenersList) {
		host := normalizeShortenerHost(line)
		// Skip blank lines and the license/attribution comment header
		if host == "" || strings.HasPrefix(host, "#") {
			continue
		}
		shorteners[host] = struct{}{}
	}

	for _, host := range extraShorteners {
		shorteners[normalizeShortenerHost(host)] = struct{}{}
	}

	for _, host := range brandedShortHosts {
		delete(shorteners, normalizeShortenerHost(host))
	}

	return shorteners
}

func normalizeShortenerHost(host string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "www.")
}
