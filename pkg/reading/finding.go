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

package reading

import (
	"git.happydns.org/happyDeliver/internal/model"
)

// The observers a finding may be attributed to, beyond happyDeliver itself.
//
// They are declared here rather than in the schema because the vocabulary is
// open: a report names whoever saw the defect, and which third parties an
// instance asks is the instance's business rather than something every reader
// has to have been told in advance.
const (
	// SourceSelf is happyDeliver, which is also what leaving the source out
	// says.
	SourceSelf model.ContentIssueSource = "self"

	// SourceRspamd is the spam filter, which reports what it raised on the
	// message under the symbol that raised it.
	SourceRspamd model.ContentIssueSource = "rspamd"
)

// NewFinding builds a finding at the place the check was looking. Every check
// goes through it, so that the vocabulary of an issue (its type, its severity,
// where it was found, what to do about it) is assembled the same way each
// time.
//
// Location and advice are taken as plain strings and made into pointers here,
// because that is the whole of the ceremony a check used to repeat: the
// schema tells apart a field left out from one set to nothing, and empty means
// left out.
//
// What a finding carries beyond this is set on the answer: a Concern, when the
// check knows the key another check would recognise the same defect under, and
// a Category, when a check's findings do not all answer the same reading.
func NewFinding(defect *Defect, issueType model.ContentIssueType, severity model.ContentIssueSeverity, location, message, advice string) Finding {
	issue := model.ContentIssue{
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

	return Finding{ContentIssue: issue, Defect: defect}
}
