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

// attachmentCheck is a check of the attachment analysis: one written over a
// single file the message carries. The machinery it is run by is reading.Run's,
// and is the same for every reading happyDeliver makes.
type attachmentCheck = reading.Check[*attachmentInput]

// attachmentInput is what every check is handed: one attachment, as it was
// observed, and what the analysis was willing to read of it.
//
// The reading is per attachment rather than per message, which is what makes
// the merge say something: two engines agreeing about one file agree about
// that file, and a finding about the second attachment can never be folded
// into a finding about the first.
type attachmentInput struct {
	// Attachment is the file, as it was observed: its name, its bytes, and
	// what the scanners said about it.
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
// it. Both scanners report under it, so that a sample two engines recognise is
// reported once and the second engine is named as agreeing rather than
// repeating the alarm.
//
// It needs nothing to distinguish it: one reading covers one attachment, so
// the file is already implied.
const concernMalware = "malware"

// Read runs the registry over every attachment of a message.
//
// It answers one Reading per attachment, in the order they appear in the
// message, which is the order Results holds them in: a caller pairs the two by
// index, and Analysis and Score both do.
//
// It is called once and its answer handed to both, which is why it is the
// caller's to hold: a check may hand a file to a scanner, and no attachment is
// to be read twice for one report.
func (a *Analyzer) Read(observed *Results) []Reading {
	if observed == nil || len(observed.Attachments) == 0 {
		return nil
	}

	// The analysis owns the deadline it gives its checks, as it owns the one it
	// gives its scanners. The day a request context is threaded down to here,
	// this is the one line that changes.
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

// finding builds a finding about one attachment, at the place the check was
// looking. Every check goes through it so that the vocabulary of an issue (its
// type, its severity, where it was found) is assembled the same way each time.
func finding(defect *reading.Defect, issueType model.IssueType, severity model.IssueSeverity, location, message, advice string) reading.Finding {
	issue := model.Issue{
		Type:     issueType,
		Severity: severity,
		Message:  message,
	}
	if location != "" {
		issue.Location = &location
	}
	if advice != "" {
		issue.Advice = &advice
	}

	return reading.Finding{Issue: issue, Defect: defect}
}
