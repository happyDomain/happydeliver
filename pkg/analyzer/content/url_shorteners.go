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
	"sync"

	"git.happydns.org/happyDeliver/pkg/emaildata/shorteners"
)

// extraShorteners are shortening services missing from the embedded list.
var extraShorteners = []string{
	"gg.gg",     // shortening service, widely reported as abused for phishing
	"shrtco.de", // shrtcode, shortening service and API
	"spoo.me",   // open-source link shortener, self-hostable
}

// brandedShortHosts are hosts the embedded list counts as shorteners but which
// only ever lead to one company's own content. The shortener finding says the
// recipient cannot see where the link leads; for these hosts that is untrue:
// "youtu.be/..." is the canonical way to link a YouTube video, not a way to
// hide a destination, so an ordinary email linking to a video, a track or a
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
// It is the embedded list read through what this analysis makes of it: the
// services it knows about and upstream has not listed, and the branded short
// links it refuses to count as hiding anything.
//
// Matching is done by isShortenerHost on the whole host (optionally prefixed
// with "www.").
var urlShorteners = sync.OnceValue(loadURLShorteners)

// loadURLShorteners takes the embedded list and applies the local overlays.
func loadURLShorteners() map[string]struct{} {
	upstream := shorteners.Hosts()

	known := make(map[string]struct{}, len(upstream)+len(extraShorteners))
	for host := range upstream {
		known[host] = struct{}{}
	}

	for _, host := range extraShorteners {
		known[shorteners.NormalizeHost(host)] = struct{}{}
	}

	for _, host := range brandedShortHosts {
		delete(known, shorteners.NormalizeHost(host))
	}

	return known
}
