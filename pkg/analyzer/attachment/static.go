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

	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// staticCheck is a check read off the facts of a file alone, without opening
// anything else: what its name says, what its declared type says against its
// content, and what its content turns out to be. Written over the facts rather
// than the attachment, it reads a file inside a zip exactly as it reads a file
// attached to the message.
//
// Nothing is detected here. The facts are read off fileinspect, which knows
// the formats and nothing of what any of them costs; what is done here is
// putting a defect, a gravity and a sentence on each of them, which is this
// package's whole business.
type staticCheck struct {
	// Name and Reports are those of the attachmentCheck it is run as.
	Name    string
	Reports []*reading.Defect

	// Findings says what the facts of a file at that location are worth.
	Findings func(facts fileinspect.Facts, location string) []reading.Finding
}

// staticChecks is every static check, in the order their findings are read.
// It is the one list every reading of a file's facts is made of, so that a
// fact is judged the same wherever the file was found.
var staticChecks = []staticCheck{
	// What the file says it is.
	filenameCheck,
	typeMismatchCheck,
}

// check is the static check as the registry runs it, over the attachment.
func (c staticCheck) check() attachmentCheck {
	return attachmentCheck{
		Name:     c.Name,
		Category: reading.CategorySecurity,
		Reports:  c.Reports,
		Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
			return c.Findings(in.Attachment.facts, in.Attachment.Location), nil
		},
	}
}

// staticFindings is what every static check makes of the facts of one file,
// as the registry reports them about the attachment itself.
func staticFindings(facts fileinspect.Facts, location string) (findings []reading.Finding) {
	for _, c := range staticChecks {
		findings = append(findings, c.Findings(facts, location)...)
	}

	return findings
}
