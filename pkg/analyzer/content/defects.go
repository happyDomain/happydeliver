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

import "git.happydns.org/happyDeliver/pkg/reading"

// contentDefects is the whole vocabulary. A defect missing from it is priced
// by nobody, and the tests say so.
var contentDefects = []*reading.Defect{
	defectTruncatedBody,
	defectBrokenHTML,
	defectHTMLRemark,
	defectDangerousHTML,
	defectMissingAlt,
	defectExcessiveImages,
	defectTextHTMLMismatch,
	defectTextLinkMissing,
	defectUnreplacedTemplate,
	defectSuspiciousURL,
	defectDeadLink,
	defectDeadImage,
	defectDeadUnsubscribe,
	defectRedirectChain,
	defectUnprobedURLs,
	defectClientCompat,
	defectEventHandler,
	defectRspamdObservation,
}

var (
	// defectTruncatedBody: the body stopped before its end.
	//
	// The criteria such a body cannot answer are withdrawn from the scale
	// rather than failed, which is a heavier and fairer answer than a penalty.
	// Charging for it on top would bill the sender for an incident of
	// transport.
	defectTruncatedBody = &reading.Defect{
		Name:      "truncated_body",
		Uncharged: "the criteria the missing parts would have decided leave the scale instead, which already answers for it",
	}

	// defectBrokenHTML: markup the parser could not read through.
	defectBrokenHTML = &reading.Defect{Name: "broken_html"}

	// defectHTMLRemark: a lesser remark the HTML pass gathered along the way,
	// an external stylesheet being the one it raises today.
	defectHTMLRemark = &reading.Defect{
		Name:      "html_remark",
		Uncharged: "none of these keeps the message from being read: they inform the sender rather than grade the message",
	}

	// defectDangerousHTML: markup an email client blocks outright.
	defectDangerousHTML = &reading.Defect{Name: "dangerous_html", Family: familyHarmfulHTML}

	// defectMissingAlt: an image a recipient who cannot see it is told nothing
	// about.
	defectMissingAlt = &reading.Defect{Name: "missing_alt"}

	// defectExcessiveImages: a message that is mostly image, with little text
	// a reader or a filter can read.
	defectExcessiveImages = &reading.Defect{Name: "excessive_images"}

	// defectTextHTMLMismatch: a plain text alternative that no longer says
	// what the HTML says: the previous campaign's text, or a line telling a
	// reader their client cannot do HTML when it plainly can.
	defectTextHTMLMismatch = &reading.Defect{Name: "text_html_mismatch"}

	// defectTextLinkMissing: a destination the text part offers and the HTML
	// part does not, which suggests the two were not generated together.
	//
	// It is reported and not charged, and the reason is worth writing down:
	// many senders rewrite their links through a click tracker that mints a
	// distinct token per part, so a text link "missing" from the HTML may be
	// the very same link wearing another token. Nothing here can tell that
	// apart from a text part left behind, and a sender is not to lose a grade
	// over an ambiguity we hold rather than they do. So it is put in front of
	// them to judge.
	defectTextLinkMissing = &reading.Defect{
		Name:      "text_link_missing",
		Uncharged: "a click tracker minting one token per part makes the same link look like two, and nothing here tells that apart from a text part left behind: the reader judges it, we only point at it",
	}

	// defectUnreplacedTemplate: a link whose URL still carries a merge field,
	// so it designates no destination at all.
	defectUnreplacedTemplate = &reading.Defect{Name: "unreplaced_template"}

	// defectSuspiciousURL: what the shape of a URL says, before anything is
	// fetched. It covers links and image sources alike: the defect is of one
	// nature whether it is written in an href or in a src.
	defectSuspiciousURL = &reading.Defect{Name: "suspicious_url", Family: familyURLSuspicion}

	// defectDeadLink: a body link that does not answer, or whose redirections
	// never end.
	defectDeadLink = &reading.Defect{Name: "dead_link"}

	// defectDeadImage: an image source that does not answer, which leaves a
	// hole the recipient sees the moment the message opens.
	defectDeadImage = &reading.Defect{Name: "dead_image"}

	// defectDeadUnsubscribe: the address advertised in List-Unsubscribe
	// answering that it is gone.
	//
	// No criterion measures it: the score says nothing yet about how a
	// recipient gets out, so it answers under the HTTP-probe cap, beside the
	// redirect chains.
	defectDeadUnsubscribe = &reading.Defect{Name: "dead_unsubscribe", Family: familyHTTPProbe}

	// defectRedirectChain: a URL that is reached, but only after a detour.
	// Being reachable, no criterion counts it as broken, so it answers here.
	defectRedirectChain = &reading.Defect{Name: "redirect_chain", Family: familyHTTPProbe}

	// defectUnprobedURLs: the URLs one analysis left unfetched.
	defectUnprobedURLs = &reading.Defect{
		Name:      "unprobed_urls",
		Uncharged: "it describes a limit of the analysis, not a defect of the message",
	}

	// defectRspamdObservation: something the spam filter of the receiving MTA
	// saw and no criterion of ours measures.
	//
	// A symbol observing something a criterion already grades takes that
	// criterion's defect instead, and so costs nothing: the filter agreeing
	// with a measurement we made ourselves is worth reading, not worth
	// charging for twice.
	defectRspamdObservation = &reading.Defect{Name: "rspamd_observation", Family: familyRspamd}

	// defectClientCompat: CSS or markup a client drops, so that the message
	// reaches the recipient rendered otherwise than it was sent.
	//
	// Which clients drop what is not our judgement but Can I email's, embedded
	// and refreshable. What it costs is nobody's: knowing that a client ignores
	// a property is not knowing that the reader sees anything different for it,
	// and a sender is not to lose a grade over a distinction we cannot make.
	defectClientCompat = &reading.Defect{
		Name:      "client_compat",
		Uncharged: "nothing here says whether the unsupported property changes what the reader sees: it is put in front of the sender rather than billed to them",
	}

	// defectEventHandler: an on* attribute, which no email client runs and
	// every sanitiser strips.
	//
	// It costs nothing for a reason of its own, not by extension of the above:
	// a stripped handler deprives the message of a behaviour it never had
	// anywhere, so there is no rendering lost to charge for. That is what parts
	// it from the <script> tag familyHarmfulHTML charges twenty points for,
	// which a filter scores the sender on.
	defectEventHandler = &reading.Defect{
		Name:      "event_handler",
		Uncharged: "a handler no client was ever going to run costs the message nothing it had: the sender is told, not charged",
	}
)
