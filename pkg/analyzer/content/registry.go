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

// contentChecks is every check the content analysis runs, in the order their
// findings are read.
//
// This is the one place to touch to add a check: write its file, declare a
// contentCheck in it, and name it here. Where it sits in the list is where its
// findings sit in the report, so the order is not arbitrary: what qualifies
// the whole analysis comes first, what merely informs comes last.
var contentChecks = []contentCheck{
	// A body that stops short qualifies everything said below it, which only
	// ever saw the parts that arrived. It is read first for that reason.
	truncatedBodyCheck,

	brokenHTMLCheck,

	// What the message says, before what it is made of: a text alternative
	// that contradicts the HTML, or offers destinations the HTML does not,
	// qualifies everything a reader who prefers text ever sees.
	textAlternativeCheck,
	textLinkParityCheck,

	missingAltCheck,
	excessiveImagesCheck,

	// Whether the text can be made out at all, which is of a piece with the
	// images a reader is told nothing about: both answer for the recipients a
	// message leaves out.
	lowContrastCheck,

	templatePlaceholderCheck,
	linkSuspicionCheck,
	imageSuspicionCheck,
	probeFindingCheck,
	unprobedURLsCheck,

	harmfulHTMLCheck,
	htmlRemarkCheck,

	// What a client will not render as it was sent. It reads the markup, so it
	// sits with the other readings of the markup, and last among them: it
	// qualifies nothing above it, and a message whose HTML does not parse has
	// been told so before it is told which clients drop its flexbox.
	clientCompatCheck,

	// What the spam filter observed comes last: it complements the checks
	// above rather than replacing them, and the reader has met our own
	// findings by the time they reach it.
	rspamdFindingsCheck,
}
