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
}

// Reading is what the checks made of one attachment: the findings a report
// shows, and what they cost its score.
type Reading = reading.Evaluation

// concernMalware keys the verdict that a file is malicious, whoever reached
// it, so that a sample two engines recognise is reported once with the second
// named as agreeing.
const concernMalware = "malware"

// Read runs the registry over every attachment of a message, and answers one
// Reading per attachment, in the order Results holds them. It is called once
// and its answer handed to both Analysis and Score.
func (a *Analyzer) Read(observed *Results) []Reading {
	if observed == nil || len(observed.Attachments) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.scanTimeout)
	defer cancel()

	readings := make([]Reading, len(observed.Attachments))
	for i := range observed.Attachments {
		in := &attachmentInput{Attachment: &observed.Attachments[i], MaxSize: a.maxSize}

		issues, penalty := reading.Run(ctx, attachmentChecks, in)
		readings[i] = Reading{Issues: issues, Penalty: penalty}
	}

	return readings
}
