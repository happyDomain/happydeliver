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
	"cmp"
	"context"
	"slices"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// rspamdFinding is what one rspamd symbol means for the sender.
//
// The catalogue below exists because rspamd's own symbol descriptions are
// identifiers, not advice: "Has text part encoded in base64" names what fired
// without saying why it matters or what to change. Several of the symbols
// worth reporting carry no description at all, and some of the most telling
// ones (WP_COMPROMISED at zero, PDF_JAVASCRIPT at a tenth of a point) are
// weighted as next to nothing, because rspamd's scale measures spamminess
// while this report measures what a sender can act on. Severity is therefore
// curated here and never derived from the symbol's weight.
type rspamdFinding struct {
	// Issue files the finding under one of the report's content families.
	Issue model.ContentIssueType

	// Defect says what the symbol saw, at the grain at which it is paid for.
	//
	// It is left empty for everything no criterion of ours grades, which is
	// most of the catalogue: those answer under the filter's own cap, as
	// defectRspamdObservation. A symbol observing something a criterion
	// already grades names that criterion's defect instead, and so costs
	// nothing extra: the filter agreeing with a measurement we made
	// ourselves is worth reading, not worth charging for twice.
	Defect *reading.Defect

	// Severity is how much this costs the sender, on this report's scale
	// rather than on rspamd's.
	Severity model.ContentIssueSeverity

	// Message states what was observed. A trailing "%s" is filled with the
	// symbol's options, which several symbols need to be readable at all:
	// MIME_BAD_ATTACHMENT without its file name says nothing.
	Message string

	// Advice says what to change, and the fact that says why.
	Advice string

	// Concern is the key under which this finding may be recognised as the
	// same defect one of happyDeliver's own checks reported. Empty means it is
	// always reported on its own, which is the case for everything no check of
	// ours observes.
	//
	// A recipe ending in ":@url" is keyed on the URL the symbol's options
	// name, through the same concernForURL our checks use, so the two agree
	// whenever they agree on the URL. Anything else is used as written, which
	// suits a statement about the whole message.
	Concern string
}

// concernURLRecipe marks a catalogue concern to be keyed on the URL found in
// the symbol's options rather than used as written.
const concernURLRecipe = ":@url"

// rspamdFindingCatalog maps a symbol to what it means.
//
// The rule for being in here is narrow, and it is what keeps this table from
// growing into a second copy of the spam filter's report: a symbol earns an
// entry only if it observes something happyDeliver is meant to report on,
// one of the checks the sections below group by. Everything else rspamd
// raises about a message, and it raises a great deal, belongs to the spam
// filter's own verdict and is already shown in the raw symbol table.
//
// So no MIME encoding remarks, no subject hygiene, nothing about the host
// that sent the message: those are real observations, and they are none of
// this report's business. A symbol absent from the catalogue is ignored
// rather than repeated with its bare description.
var rspamdFindingCatalog = map[string]rspamdFinding{
	// --- Hidden text, from a contrast failure to the oldest trick there is
	"R_WHITE_ON_WHITE": {
		Issue:    model.ContentIssueTypeHiddenText,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "The message contains text whose colour makes it unreadable against its background.",
		Advice:   "Give every text a colour that contrasts with what is behind it; filters score text invisible against its background as hidden content",
	},
	"ZERO_FONT": {
		Issue:    model.ContentIssueTypeHiddenText,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "The message sets a font size of zero somewhere.",
		Advice:   "Remove the zero-sized text; filters score a \"font-size:0\" as hidden content, including one a template left behind",
	},
	"MANY_INVISIBLE_PARTS": {
		Issue:    model.ContentIssueTypeHiddenText,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "Several parts of the message are hidden from view.",
		Advice:   "Remove the hidden blocks the template left in place; filters count how many a message carries, and a preheader is normally the only one",
	},
	"DATA_URI_OBFU": {
		Issue:    model.ContentIssueTypeHiddenText,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "Part of the content is carried as a base64 data: URI rather than as markup.",
		Advice:   "Write the content as HTML and link images normally; filters score text or markup inside a data: URI as obfuscation, since only the rendering client decodes it",
	},

	// --- One-big-image newsletters
	"HTML_SHORT_LINK_IMG_1": {
		Defect:   defectExcessiveImages,
		Issue:    model.ContentIssueTypeImageOnlyContent,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "The HTML part is very short and consists of a linked image.",
		Advice:   "Put the message in text as well as in the image; a client that blocks images shows nothing, and filters cannot read the image",
	},
	"HTML_SHORT_LINK_IMG_2": {
		Defect:   defectExcessiveImages,
		Issue:    model.ContentIssueTypeImageOnlyContent,
		Severity: model.ContentIssueSeverityLow,
		Message:  "The HTML part is short and largely made of a linked image.",
		Advice:   "Add real text alongside the image, for clients that block images and for filters that cannot read it",
	},
	"HTML_SHORT_LINK_IMG_3": {
		Defect:   defectExcessiveImages,
		Issue:    model.ContentIssueTypeImageOnlyContent,
		Severity: model.ContentIssueSeverityInfo,
		Message:  "The HTML part leans on a linked image for much of its content.",
		Advice:   "Keep enough text that the message still reads with images off",
	},
	"R_EMPTY_IMAGE": {
		Defect:   defectExcessiveImages,
		Issue:    model.ContentIssueTypeImageOnlyContent,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "The message pairs empty parts with an image.",
		Advice:   "Fill the empty parts or drop them; an image carrying the whole message with blank text beside it is scored as an image-only mailing",
	},

	// --- Text and HTML out of sync
	"R_PARTS_DIFFER": {
		Defect:   defectTextHTMLMismatch,
		Issue:    model.ContentIssueTypeTextHtmlMismatch,
		Severity: model.ContentIssueSeverityLow,
		Message:  "The text and HTML parts do not say the same thing: %s",
		Advice:   "Generate the text part from the HTML rather than maintaining it by hand; a stale text alternative is what clients that prefer text display",
		Concern:  "text_html_mismatch",
	},

	// --- Destination reputation
	"DBL_PHISH": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is listed in the Spamhaus DBL as phishing: %s",
		Advice:   "Remove the link; if the domain is yours, it is compromised and needs cleaning before it is linked again",
	},
	"DBL_BOTNET": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is listed in the Spamhaus DBL as botnet command-and-control: %s",
		Advice:   "Remove the link, and check the machine that composed this message for compromise",
	},
	"DBL_SPAM": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is listed in the Spamhaus DBL as spam: %s",
		Advice:   "Remove the link, or get the domain delisted if it is yours; one listed destination is enough for the whole message to be rejected",
	},
	"DBL_ABUSE_PHISH": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is a legitimate one currently abused for phishing: %s",
		Advice:   "Remove the link; while the destination is abused, every message pointing at it is scored as phishing",
	},
	"URIBL_BLACK": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is on the URIBL blacklist: %s",
		Advice:   "Remove the link, or get the domain delisted if it is yours",
	},
	"PH_SURBL_MULTI": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A domain the message links to is listed in SURBL as phishing: %s",
		Advice:   "Remove the link; if the domain is yours, it is compromised",
	},
	"PHISHED_OPENPHISH": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A URL of the message is a known phishing address, listed by OpenPhish: %s",
		Advice:   "Remove the link",
	},
	"PHISHED_PHISHTANK": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A URL of the message is a known phishing address, listed by PhishTank: %s",
		Advice:   "Remove the link",
	},
	"HACKED_WP_PHISHING": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "The message looks sent from a compromised WordPress installation, for phishing.",
		Advice:   "If the site is yours, take it off line and audit it before sending anything else from it",
	},
	"WP_COMPROMISED": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A link points into a WordPress installation known to be compromised: %s",
		Advice:   "Remove the link; if the site is yours, it is serving someone else's content and needs cleaning before it is linked again",
	},
	"SEM_URIBL": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A domain the message links to is listed in the Spam Eating Monkey URIBL: %s",
		Advice:   "Check the destination, and remove the link if you do not control it",
	},
	"SEM_URIBL_FRESH15": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "A domain the message links to was registered in the last fifteen days: %s",
		Advice:   "Keep the links on an established domain; a newly registered domain carries no reputation and is heavily penalised, so warm it up before putting it in a campaign",
	},
	"URL_SUSPICIOUS_TLD": {
		Issue:    model.ContentIssueTypeLinkReputation,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "A link uses a top-level domain filters treat with suspicion: %s",
		Advice:   "Host the destination on an established TLD; filters penalise some extensions whatever sits behind them",
	},

	// --- Deceiving URLs, homographs included
	"URL_HOMOGRAPH_ATTACK": {
		Issue:    model.ContentIssueTypeHomographUrl,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A URL mixes scripts so that its host reads as a name it is not: %s",
		Advice:   "Write the host in one script; a label mixing Latin and Cyrillic look-alikes is a homograph attack",
	},
	"URL_RTL_OVERRIDE": {
		Issue:    model.ContentIssueTypeHomographUrl,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A URL contains a right-to-left override character, which reverses how part of it is displayed: %s",
		Advice:   "Remove the override; it makes the URL display as something other than where it goes",
	},
	"URL_ZERO_WIDTH_SPACES": {
		Issue:    model.ContentIssueTypeHomographUrl,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "A URL contains zero-width spaces, invisible to the reader: %s",
		Advice:   "Remove them; invisible characters break the match between what the URL shows and where it leads",
	},
	"OMOGRAPH_URL": {
		Issue:    model.ContentIssueTypeHomographUrl,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A URL holds both Latin and non-Latin characters: %s",
		Advice:   "Check the host character by character; if the domain really is internationalised, write it in punycode to remove the ambiguity",
	},
	"URL_BAD_UNICODE": {
		Issue:    model.ContentIssueTypeHomographUrl,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A URL contains invalid Unicode: %s",
		Advice:   "Rewrite the URL with a valid encoding; clients differ in what they make of an invalid sequence",
	},
	"URL_OBFUSCATED_TEXT": {
		Issue:    model.ContentIssueTypeObfuscatedUrl,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A URL in the text is written so as to hide where it goes: %s",
		Advice:   "Write URLs plainly; filters decode the encodings that hide a destination from a reader, and score the obfuscation",
	},
	"URL_MULTIPLE_AT_SIGNS": {
		Issue:    model.ContentIssueTypeObfuscatedUrl,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A URL carries several @ signs, so what precedes the last one is not the host: %s",
		Advice:   "Remove everything before the host; it shows one domain while the link reaches another",
	},
	"HTTP_TO_IP": {
		Issue:    model.ContentIssueTypeObfuscatedUrl,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "A link points at a bare IP address rather than a name: %s",
		Advice:   "Link to a hostname; an IP address cannot be checked against a domain reputation or a TLS certificate",
		Concern:  "ip_host" + concernURLRecipe,
	},
	"URL_NO_TLD": {
		Issue:    model.ContentIssueTypeObfuscatedUrl,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "A URL has a host with no top-level domain: %s",
		Advice:   "Write the full domain; a host without a TLD resolves only inside the network it was written in",
	},

	// --- Attachments
	"BOGUS_ENCRYPTED_AND_TEXT": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "The message mixes an encrypted payload with plain text or HTML in a way that does not add up.",
		Advice:   "Send either a properly signed and encrypted message or a plain one; this combination is used to put a payload past a scanner while keeping a readable part",
	},
	"MIME_DOUBLE_BAD_EXTENSION": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "An attachment hides its real extension behind a harmless-looking one: %s",
		Advice:   "Name files with a single, true extension; a double extension makes an executable display as a document",
	},
	"MIME_BAD_UNICODE": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityCritical,
		Message:  "An attachment's file name contains Unicode characters known for disguising it: %s",
		Advice:   "Rename the file in plain characters; the ones flagged here reverse or hide part of the name as it is displayed",
	},
	"MIME_ARCHIVE_IN_ARCHIVE": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached archive contains another archive: %s",
		Advice:   "Attach the files themselves, or link to them; an antivirus cannot see inside a nested archive, and scores it as evasion",
	},
	"MIME_OBFUSCATED_ARCHIVE": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached archive holds files showing clear signs of obfuscation: %s",
		Advice:   "Repackage the archive with plain names and extensions, or link to the files instead",
	},
	"MIME_ENCRYPTED_ARCHIVE": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached archive is password-protected: %s",
		Advice:   "Share the file through a link the recipient authenticates against; a password-protected archive cannot be scanned, and many gateways reject it outright",
	},
	"MIME_BAD_ATTACHMENT": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attachment has a MIME type that does not belong in a message: %s",
		Advice:   "Send documents in formats a recipient can open safely, and link to anything executable rather than attaching it",
	},
	"MIME_BAD_EXTENSION": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attachment carries an extension gateways refuse: %s",
		Advice:   "Link to the file instead; an attachment with this extension is usually stripped before delivery",
	},
	"EXE_IN_ARCHIVE": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached archive contains an executable: %s",
		Advice:   "Distribute software through a download the recipient initiates; most gateways block an executable arriving by mail",
	},
	"PDF_SUSPICIOUS": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached PDF has properties associated with malicious documents: %s",
		Advice:   "Regenerate the PDF from its source with a current tool, and check what the original was made with",
	},
	"PDF_JAVASCRIPT": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "An attached PDF contains JavaScript.",
		Advice:   "Export the PDF without scripting; embedded scripts are where PDF exploits run",
	},
	"PDF_ENCRYPTED": {
		Issue:    model.ContentIssueTypeAttachmentRisk,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "An attached PDF is encrypted.",
		Advice:   "Send the document unencrypted over a channel that protects it, or link to it; an encrypted PDF cannot be scanned",
	},

	// --- What a check of our own also observes: merged, not dropped
	// These overlap a check of happyDeliver's own on purpose. Both run, and the
	// pipeline reports whichever saw the defect, or one of them with the
	// other's agreement noted, when both did. Leaving them out of the catalogue
	// would mean losing the cases our own check misses.
	"R_SUSPICIOUS_IMAGES": {
		Defect:   defectExcessiveImages,
		Issue:    model.ContentIssueTypeExcessiveImages,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "The message carries far more image than text.",
		Advice:   "Put the message in text and let images illustrate it; a mostly-image mailing reads as empty to a filter, and to clients that block remote content",
		Concern:  "excessive_images",
	},
	"REDIRECTOR_URL": {
		Defect:   defectSuspiciousURL,
		Issue:    model.ContentIssueTypeSuspiciousLink,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "A link goes through a public redirector rather than straight to its destination: %s",
		Advice:   "Link to your own domain, a branded click-tracker included; a filter weighs the reputation of a public redirector rather than yours",
		Concern:  "shortener" + concernURLRecipe,
	},
	"URL_USER_PASSWORD": {
		Defect:   defectSuspiciousURL,
		Issue:    model.ContentIssueTypeSuspiciousLink,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "A URL carries a user field before its host: %s",
		Advice:   "Remove the \"user@\" part; it shows one domain while the link reaches another, and filters score it as such",
		Concern:  "userinfo" + concernURLRecipe,
	},

	// --- Client compatibility
	"HTML_META_REFRESH_URL": {
		Issue:    model.ContentIssueTypeClientCompat,
		Severity: model.ContentIssueSeverityHigh,
		Message:  "The HTML carries a meta refresh redirection: %s",
		Advice:   "Remove it and link to the destination; no email client honours a meta refresh, and filters score a redirection hidden in markup as cloaking",
	},
	"EXT_CSS": {
		Defect:   defectHTMLRemark,
		Issue:    model.ContentIssueTypeClientCompat,
		Severity: model.ContentIssueSeverityMedium,
		Message:  "The HTML references an external stylesheet: %s",
		Advice:   "Inline the styles; most clients never fetch an external stylesheet and render the message unstyled",
		Concern:  "external_css" + concernURLRecipe,
	},
}

// rspamdFindingsCheck turns the symbols the spam filter raised into findings a
// sender can act on.
//
// It reports whatever rspamd result the report holds, which on a message
// received over SMTP is the one its own milter wrote into the headers. It
// therefore costs no network call and applies to every report.
//
// Findings are filed under familyRspamd, capped like the others so that a
// filter having a lot to say cannot decide the content grade by itself.
var rspamdFindingsCheck = contentCheck{
	Name:     "rspamd_finding",
	Category: reading.CategoryDeliverability,
	Reports: []*reading.Defect{
		defectRspamdObservation,
		defectExcessiveImages,
		defectTextHTMLMismatch,
		defectSuspiciousURL,
		defectHTMLRemark,
	},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.Results.Rspamd == nil {
			return nil, nil
		}

		type found struct {
			symbol  string
			finding rspamdFinding
			params  string
		}

		var matched []found
		for symbol, detail := range in.Results.Rspamd.Symbols {
			finding, ok := rspamdFindingCatalog[symbol]
			if !ok {
				continue
			}

			params := ""
			if detail.Params != nil {
				params = strings.TrimSpace(*detail.Params)
			}

			matched = append(matched, found{symbol: symbol, finding: finding, params: params})
		}

		// Symbols come out of a map, so they are sorted before being reported:
		// a report that reshuffles itself between two runs of the same message
		// cannot be compared with itself. Gravest first, then by name.
		slices.SortFunc(matched, func(a, b found) int {
			if c := cmp.Compare(severityRank(b.finding.Severity), severityRank(a.finding.Severity)); c != 0 {
				return c
			}
			return cmp.Compare(a.symbol, b.symbol)
		})

		issues := make([]reading.Finding, 0, len(matched))
		for _, m := range matched {
			message := m.finding.Message
			if strings.Contains(message, "%s") {
				// A symbol whose message needs its options, raised without
				// any, still has to read as a sentence.
				replacement := m.params
				if replacement == "" {
					replacement = "the message does not say which"
				}
				message = strings.Replace(message, "%s", replacement, 1)
			}

			issue := model.ContentIssue{
				Type:     m.finding.Issue,
				Severity: m.finding.Severity,
				Message:  message,
				Advice:   utils.PtrTo(m.finding.Advice),
				Source:   utils.PtrTo(model.ContentIssueSourceRspamd),
				Symbol:   utils.PtrTo(m.symbol),
			}
			if m.params != "" {
				issue.Location = utils.PtrTo(m.params)
			}

			// A symbol the catalogue does not tie to one of our own
			// measurements answers under the filter's cap.
			defect := m.finding.Defect
			if defect == nil {
				defect = defectRspamdObservation
			}

			issues = append(issues, reading.Finding{
				Defect:       defect,
				ContentIssue: issue,
				Concern:      rspamdConcern(m.finding.Concern, m.params),
			})
		}

		return issues, nil
	},
}

// rspamdConcern turns a catalogue recipe into the key this finding is merged
// under. A recipe asking for a URL yields nothing when the options hold none,
// so the finding is reported on its own rather than merged on a guess.
func rspamdConcern(recipe, params string) string {
	defect, keyedOnURL := strings.CutSuffix(recipe, concernURLRecipe)
	if !keyedOnURL {
		return recipe
	}

	// The options of a URL symbol name the URL, sometimes among other fields.
	for field := range strings.FieldsSeq(strings.ReplaceAll(params, ",", " ")) {
		if concern := concernForURL(defect, field); concern != "" {
			return concern
		}
	}

	return ""
}
