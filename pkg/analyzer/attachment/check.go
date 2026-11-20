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
	"context"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// attachmentCheck is a check of the attachment analysis, written over a single
// file the message carries and run by reading.Run.
type attachmentCheck = reading.Check[*attachmentInput]

// attachmentInput is what every check is handed: one attachment, as it was
// observed, and what the analysis was willing to read of it. The reading is
// per attachment rather than per message, so that the merge never folds a
// finding about one file into a finding about another.
type attachmentInput struct {
	Attachment *Attachment

	// MaxSize is the ceiling the analysis reads up to, so that the check
	// reporting an attachment left unread can say what it was measured
	// against. Zero means there was no ceiling.
	MaxSize int64

	// Rspamd is what the spam filter said about this file and our own checks
	// did not, for rspamdFindingsCheck to report. On the reading of the
	// message as a whole, Attachment is nil and this is all there is.
	Rspamd []rspamdSymbol
}

// Reading is what the checks made of one attachment, or of the files of the
// message taken together: the findings a report shows, and what they cost
// its score.
type Reading = reading.Evaluation

// Readings is what the checks made of the files a message carries.
type Readings struct {
	// Files holds one Reading per attachment, in the order Results holds
	// them.
	Files []Reading

	// Message is what the spam filter said about the files of the message
	// that no single one of them answers to.
	Message Reading
}

// concernMalware keys the verdict that a file is malicious, whoever reached
// it, so that a sample two engines recognise is reported once with the second
// named as agreeing.
const concernMalware = "malware"

// Read runs the registry over every attachment of a message, then adds what
// the spam filter said about them, when one did. It is called once and its
// answer handed to both Analysis and Score.
//
// The filter's symbols are tied to the file they name where exactly one does,
// and noted on our own finding where one of our checks saw the same thing in
// that file. What is left is reported on the file, or on the message when no
// single file could be told.
func (a *Analyzer) Read(observed *Results, filter *model.RspamdResult) Readings {
	if observed == nil {
		return Readings{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.scanTimeout)
	defer cancel()

	perFile, message := attributeRspamd(observed.Attachments, filter)

	var readings Readings
	if len(observed.Attachments) > 0 {
		readings.Files = make([]Reading, len(observed.Attachments))
	}
	for i := range observed.Attachments {
		attachment := &observed.Attachments[i]

		evaluation := reading.Evaluate(ctx, attachmentChecks, &attachmentInput{Attachment: attachment, MaxSize: a.maxSize})

		if leftover := corroborate(&evaluation, perFile[i]); len(leftover) > 0 {
			extra := reading.Evaluate(ctx, rspamdChecks, &attachmentInput{Attachment: attachment, MaxSize: a.maxSize, Rspamd: leftover})
			evaluation.Issues = append(evaluation.Issues, extra.Issues...)
			evaluation.Findings = append(evaluation.Findings, extra.Findings...)
			evaluation.Penalty += extra.Penalty
		}

		readings.Files[i] = evaluation
	}

	if len(message) > 0 {
		readings.Message = reading.Evaluate(ctx, rspamdChecks, &attachmentInput{Rspamd: message})
	}

	return readings
}
