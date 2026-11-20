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

package attachment

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// rspamdFinding is what one rspamd symbol about the files a message carries
// means for the sender.
//
// Severity is curated here rather than derived from the symbol's weight, for
// the reason the content catalogue gives: rspamd's scale measures spamminess,
// and this report measures what a sender can act on.
type rspamdFinding struct {
	// Issue is the type the finding is filed under: the one a check of ours
	// would have used for the same defect, when there is one.
	Issue model.IssueType

	Severity model.IssueSeverity

	// Category says which reading of the message the finding answers. Empty
	// means the check's own, security, which is what most of these symbols
	// speak of.
	Category reading.Category

	// Message states what was observed. A "%s" is filled with the option the
	// symbol named, without which several of them say nothing: a bad MIME
	// type is only worth reading next to the file it was found on.
	Message string

	// Advice says what to change, and the fact that says why.
	Advice string

	// Counterpart is the defect one of our own checks reports for the same
	// thing. When that check reported it on the same file, the filter's
	// finding is noted on ours as agreeing rather than shown and charged a
	// second time. Nil means nothing of ours observes it.
	Counterpart *reading.Defect

	// Refine, when set, says what the symbol means given the option it named,
	// for a symbol whose gravity depends on what it was raised about. It
	// answers with the finding to report, its message already written.
	Refine func(finding rspamdFinding, option string) rspamdFinding
}

// rspamdFindingCatalog maps every rspamd symbol that speaks of the files a
// message carries to what it means. A symbol absent from it is none of the
// attachment reading's business; the content catalogue answers for those
// about the body.
var rspamdFindingCatalog = map[string]rspamdFinding{
	"BOGUS_ENCRYPTED_AND_TEXT": {
		Issue:    model.IssueTypeAttachmentRisk,
		Severity: model.IssueSeverityCritical,
		Message:  "The message mixes an encrypted payload with plain text or HTML in a way that does not add up.",
		Advice:   "Send either a properly signed and encrypted message or a plain one; this combination is used to put a payload past a scanner while keeping a readable part",
	},
	"MIME_DOUBLE_BAD_EXTENSION": {
		Issue:       model.IssueTypeDoubleExtension,
		Severity:    model.IssueSeverityCritical,
		Message:     "An attachment hides its real extension behind a harmless-looking one: %s",
		Advice:      "Name files with a single, true extension; a double extension makes an executable display as a document",
		Counterpart: defectDoubleExtension,
	},
	"MIME_BAD_UNICODE": {
		Issue:       model.IssueTypeDangerousExtension,
		Severity:    model.IssueSeverityCritical,
		Message:     "An attachment's file name contains Unicode characters known for disguising it: %s",
		Advice:      "Rename the file in plain characters; the ones flagged here reverse or hide part of the name as it is displayed",
		Counterpart: defectDangerousExtension,
	},
	"MIME_ARCHIVE_IN_ARCHIVE": {
		Issue:       model.IssueTypeNestedArchive,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attached archive contains another archive: %s",
		Advice:      "Attach the files themselves, or link to them; an antivirus cannot see inside a nested archive, and scores it as evasion",
		Counterpart: defectNestedArchive,
	},
	"MIME_OBFUSCATED_ARCHIVE": {
		Issue:    model.IssueTypeAttachmentRisk,
		Severity: model.IssueSeverityHigh,
		Message:  "An attached archive holds files showing clear signs of obfuscation: %s",
		Advice:   "Repackage the archive with plain names and extensions, or link to the files instead",
	},
	"MIME_ENCRYPTED_ARCHIVE": {
		Issue:       model.IssueTypePasswordProtected,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attached archive is password-protected: %s",
		Advice:      "Share the file through a link the recipient authenticates against; a password-protected archive cannot be scanned, and many gateways reject it outright",
		Counterpart: defectPasswordProtected,
	},
	// rspamd raises this one when the extension of a file does not match the
	// type of its content, and names both: "png:image/webp".
	"MIME_BAD_ATTACHMENT": {
		Issue:       model.IssueTypeTypeMismatch,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attachment's name does not match its content: %s",
		Advice:      "Give the file the extension of what it actually is; a name hiding a file's real type is how a payload passes for a document, and filters score it as such",
		Counterpart: defectTypeMismatch,
		Refine:      refineBadAttachment,
	},
	"MIME_BAD_EXTENSION": {
		Issue:       model.IssueTypeDangerousExtension,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attachment carries an extension gateways refuse: %s",
		Advice:      "Link to the file instead; an attachment with this extension is usually stripped before delivery",
		Counterpart: defectDangerousExtension,
	},
	"EXE_IN_ARCHIVE": {
		Issue:       model.IssueTypeExecutableContent,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attached archive contains an executable: %s",
		Advice:      "Distribute software through a download the recipient initiates; most gateways block an executable arriving by mail",
		Counterpart: defectExecutableContent,
	},
	"PDF_SUSPICIOUS": {
		Issue:    model.IssueTypePdfActiveContent,
		Severity: model.IssueSeverityHigh,
		Message:  "An attached PDF has properties associated with malicious documents: %s",
		Advice:   "Regenerate the PDF from its source with a current tool, and check what the original was made with",
	},
	"PDF_JAVASCRIPT": {
		Issue:       model.IssueTypePdfActiveContent,
		Severity:    model.IssueSeverityHigh,
		Message:     "An attached PDF contains JavaScript.",
		Advice:      "Export the PDF without scripting; embedded scripts are where PDF exploits run",
		Counterpart: defectPDFActiveContent,
	},
	"PDF_ENCRYPTED": {
		Issue:    model.IssueTypePasswordProtected,
		Severity: model.IssueSeverityMedium,
		Message:  "An attached PDF is encrypted.",
		Advice:   "Send the document unencrypted over a channel that protects it, or link to it; an encrypted PDF cannot be scanned",
	},
}

// rasterImageExtensions are the extensions of the image formats nothing runs
// in. SVG is left out on purpose: it is markup, and may carry a script.
var rasterImageExtensions = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "jpe": true, "gif": true, "webp": true,
	"bmp": true, "tif": true, "tiff": true, "avif": true, "heic": true, "heif": true,
	"ico": true,
}

// isRasterImageType answers whether a media type names an image format
// nothing runs in.
func isRasterImageType(mediaType string) bool {
	mediaType = strings.ToLower(mediaType)
	return strings.HasPrefix(mediaType, "image/") && !strings.HasPrefix(mediaType, "image/svg")
}

// refineBadAttachment says what a file whose name does not match its content
// is worth, from the extension and the type rspamd named.
//
// One image format passing for another hides nothing: no payload sits behind
// a WebP named .png, and our own type check rightly says nothing of it. The
// filter still scores it, though, which a sender is to be told, at the
// gravity of a few points of spam score rather than of a disguised program.
// Anything else keeps the gravity of a file lying about what it is.
func refineBadAttachment(finding rspamdFinding, option string) rspamdFinding {
	ext, mediaType, ok := strings.Cut(option, ":")
	ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	mediaType = strings.TrimSpace(mediaType)
	if !ok || ext == "" || mediaType == "" {
		return finding
	}

	finding.Message = fmt.Sprintf("An attachment is named .%s but its content is %s.", ext, mediaType)

	if rasterImageExtensions[ext] && isRasterImageType(mediaType) {
		finding.Severity = model.IssueSeverityLow
		finding.Category = reading.CategoryDeliverability
		finding.Message = fmt.Sprintf("An image is named .%s but its content is %s.", ext, mediaType)
		finding.Advice = "Rename the image after its real format, or save it in the format its name says; nothing is hidden here, but spam filters score a name that does not match the content, even between two image formats"
		// What our type check passes over on purpose is not the defect it
		// reports: nothing of ours is there to agree with.
		finding.Counterpart = nil
	}

	return finding
}

// rspamdSymbol is one thing the filter said, about one file when it could be
// told which: a symbol naming several files is split into one entry per file.
type rspamdSymbol struct {
	Symbol  string
	Finding rspamdFinding

	// Params is the part of the symbol's options this entry is about.
	Params string
}

// rspamdFindingsCheck reports what the spam filter said about a file, or
// about the files of the message when it could not be told which. It reads
// only what Read handed it in attachmentInput.Rspamd, which is why it is not
// in attachmentChecks: Read runs it after our own checks, on whatever they did
// not already report.
var rspamdFindingsCheck = attachmentCheck{
	Name:     "rspamd_finding",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectRspamdObservation},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		findings := make([]reading.Finding, 0, len(in.Rspamd))
		for _, s := range in.Rspamd {
			message := s.Finding.Message
			if strings.Contains(message, "%s") {
				// A symbol whose message needs its options, raised without
				// any, still has to read as a sentence.
				replacement := s.Params
				if replacement == "" {
					replacement = "the message does not say which"
				}
				message = strings.Replace(message, "%s", replacement, 1)
			}

			issue := model.Issue{
				Type:     s.Finding.Issue,
				Category: s.Finding.Category,
				Severity: s.Finding.Severity,
				Message:  message,
				Advice:   utils.PtrTo(s.Finding.Advice),
				Source:   utils.PtrTo(reading.SourceRspamd),
				Symbol:   utils.PtrTo(s.Symbol),
			}

			// A finding about a file is located at that file, as every other
			// finding about it is; one about no file in particular at what
			// the filter named.
			switch {
			case in.Attachment != nil && in.Attachment.Location != "":
				issue.Location = utils.PtrTo(in.Attachment.Location)
			case s.Params != "":
				issue.Location = utils.PtrTo(s.Params)
			}

			findings = append(findings, reading.Finding{Defect: defectRspamdObservation, Issue: issue})
		}

		return findings, nil
	},
}

// rspamdChecks is what the filter's leftovers are read by, on a file or on
// the message.
var rspamdChecks = []attachmentCheck{rspamdFindingsCheck}

// attributeRspamd sorts what the filter said about attachments by the file it
// is about: one list per attachment, index-aligned with them, and one for what
// no single file answers to.
//
// An option is tied to a file only when exactly one answers to it. A verdict
// pinned on a file picked among several would be a guess presented as a
// finding; left at the message, it is still shown, and still costs what it
// costs.
func attributeRspamd(attachments []Attachment, filter *model.RspamdResult) (perFile [][]rspamdSymbol, message []rspamdSymbol) {
	perFile = make([][]rspamdSymbol, len(attachments))
	if filter == nil {
		return perFile, nil
	}

	var matched []rspamdSymbol
	for symbol, detail := range filter.Symbols {
		finding, ok := rspamdFindingCatalog[symbol]
		if !ok {
			continue
		}

		params := ""
		if detail.Params != nil {
			params = strings.TrimSpace(*detail.Params)
		}

		options := splitOptions(params)
		if len(options) == 0 {
			matched = append(matched, rspamdSymbol{Symbol: symbol, Finding: finding})
			continue
		}
		for _, option := range options {
			refined := finding
			if finding.Refine != nil {
				refined = finding.Refine(finding, option)
			}
			matched = append(matched, rspamdSymbol{Symbol: symbol, Finding: refined, Params: option})
		}
	}

	// Symbols come out of a map, so they are sorted before being reported: a
	// report that reshuffles itself between two runs of the same message
	// cannot be compared with itself. Gravest first, then by name.
	slices.SortFunc(matched, func(a, b rspamdSymbol) int {
		if c := cmp.Compare(severityRank(b.Finding.Severity), severityRank(a.Finding.Severity)); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Symbol, b.Symbol); c != 0 {
			return c
		}
		return cmp.Compare(a.Params, b.Params)
	})

	for _, s := range matched {
		if at := attachmentNamedBy(attachments, s.Params); at >= 0 {
			perFile[at] = append(perFile[at], s)
		} else {
			message = append(message, s)
		}
	}

	return perFile, message
}

// splitOptions cuts a symbol's options into the values it named, which rspamd
// separates with commas.
func splitOptions(params string) (options []string) {
	for option := range strings.SplitSeq(params, ",") {
		if option = strings.TrimSpace(option); option != "" {
			options = append(options, option)
		}
	}

	return options
}

// attachmentNamedBy is the index of the one attachment an option of the
// filter names, or -1 when none or several do.
//
// The filter names a file in one of three ways: by its whole name, by its
// extension and the type its content turned out to be ("png:image/webp", for
// MIME_BAD_ATTACHMENT), or by its extension alone, possibly a double one
// (".pdf.exe"). They are tried in that order, the first that any file
// answers to deciding.
func attachmentNamedBy(attachments []Attachment, option string) int {
	if option == "" {
		return -1
	}

	ways := []func(*Attachment) bool{
		func(a *Attachment) bool {
			return a.Filename != "" && strings.EqualFold(a.Filename, option)
		},
		func(a *Attachment) bool {
			ext, mediaType, ok := strings.Cut(option, ":")
			if !ok || a.Filename == "" {
				return false
			}
			if !strings.EqualFold(strings.TrimPrefix(path.Ext(a.Filename), "."), ext) {
				return false
			}
			return strings.EqualFold(a.DetectedType, mediaType) || strings.EqualFold(a.DeclaredMediaType, mediaType)
		},
		func(a *Attachment) bool {
			suffix := "." + strings.TrimPrefix(option, ".")
			return a.Filename != "" && len(a.Filename) > len(suffix) && strings.HasSuffix(strings.ToLower(a.Filename), strings.ToLower(suffix))
		},
	}

	for _, names := range ways {
		found := -1
		for i := range attachments {
			if !names(&attachments[i]) {
				continue
			}
			if found >= 0 {
				return -1
			}
			found = i
		}
		if found >= 0 {
			return found
		}
	}

	return -1
}

// corroborate notes, on what our own checks found about a file, the symbols
// of the filter that say the same thing, and answers with those that do not.
//
// The finding of ours is the one kept, since it carries a location and advice
// of its own; the filter's agreement is worth reading on it, not worth a
// second line or a second charge.
func corroborate(evaluation *reading.Evaluation, symbols []rspamdSymbol) (leftover []rspamdSymbol) {
	for _, s := range symbols {
		at := -1
		if s.Finding.Counterpart != nil {
			at = slices.IndexFunc(evaluation.Findings, func(f reading.Finding) bool {
				return f.Defect == s.Finding.Counterpart
			})
		}
		if at < 0 {
			leftover = append(leftover, s)
			continue
		}

		issue := &evaluation.Findings[at].Issue
		corroborated := []string{}
		if issue.CorroboratedBy != nil {
			corroborated = *issue.CorroboratedBy
		}
		if !slices.Contains(corroborated, s.Symbol) {
			corroborated = append(corroborated, s.Symbol)
		}
		issue.CorroboratedBy = &corroborated
		evaluation.Issues[at].CorroboratedBy = &corroborated
	}

	return leftover
}

// severityRank orders severities from the mildest to the gravest.
func severityRank(severity model.IssueSeverity) int {
	switch severity {
	case model.IssueSeverityCritical:
		return 4
	case model.IssueSeverityHigh:
		return 3
	case model.IssueSeverityMedium:
		return 2
	default:
		return 1
	}
}
