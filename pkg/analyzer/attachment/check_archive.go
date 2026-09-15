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
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// archiveLimits is how far into an archive the analysis reads.
var archiveLimits = fileinspect.DefaultLimits()

// archiveCheck looks inside an archive, and reports what it finds there as it
// would report an attachment, plus what is particular to archives: one that is
// locked, one nested inside another, one that expands out of proportion, and
// what the extraction budget kept it from reaching.
var archiveCheck = attachmentCheck{
	Name:     "attachment_archive",
	Category: reading.CategorySecurity,
	Reports: append(staticReports(),
		defectPasswordProtected,
		defectNestedArchive,
		defectArchiveBomb,
		defectScanSkipped,
	),
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		entries := fileinspect.Walk(in.Attachment.Data, archiveLimits)

		return archiveFindings(entries, in.Attachment.Location), nil
	},
}

// archiveFindings says what looking inside an archive turned up: every member
// read as an attachment is read, and every place the reading stopped.
func archiveFindings(entries []fileinspect.Entry, location string) (findings []reading.Finding) {
	for _, entry := range entries {
		at := locate(location, entry.At)

		switch entry.Kind {
		case fileinspect.KindMember:
			findings = append(findings, staticFindings(entry.Facts, at)...)

		case fileinspect.KindNested:
			// The member is both a file and an archive, and reported as both.
			findings = append(findings, staticFindings(entry.Facts, at)...)
			findings = append(findings, reading.NewFinding(
				defectNestedArchive,
				model.IssueTypeNestedArchive,
				model.IssueSeverityMedium,
				at,
				fmt.Sprintf("Archive contains a nested archive %q", entry.Name),
				"Flatten the archive so every file is within reach of a scanner",
			))

		case fileinspect.KindTooDeep:
			findings = append(findings, staticFindings(entry.Facts, at)...)
			findings = append(findings, reading.NewFinding(
				defectNestedArchive,
				model.IssueTypeNestedArchive,
				model.IssueSeverityMedium,
				at,
				fmt.Sprintf("Archive nesting exceeds %d levels; deeper content was not inspected", archiveLimits.MaxDepth),
				"Flatten the archive so every file is within reach of a scanner",
			))

		case fileinspect.KindEncrypted:
			findings = append(findings, reading.NewFinding(
				defectPasswordProtected,
				model.IssueTypePasswordProtected,
				model.IssueSeverityMedium,
				at,
				"Archive is password-protected and cannot be scanned",
				"Send the archive unencrypted, or host it and share the link and the password separately",
			))

		case fileinspect.KindBomb:
			findings = append(findings, reading.NewFinding(
				defectArchiveBomb,
				model.IssueTypeArchiveBomb,
				model.IssueSeverityHigh,
				at,
				bombMessage(entry.Name),
				"Repack the archive without that member; a file expanding that much gets the whole message dropped",
			))

		case fileinspect.KindTruncated:
			findings = append(findings, reading.NewFinding(
				defectScanSkipped,
				model.IssueTypeScanSkipped,
				model.IssueSeverityMedium,
				at,
				truncatedMessage(entry.Name),
				"Split the archive into smaller ones, or host it and link to it",
			))

		case fileinspect.KindBudgetExhausted:
			findings = append(findings, reading.NewFinding(
				defectScanSkipped,
				model.IssueTypeScanSkipped,
				model.IssueSeverityMedium,
				at,
				"Archive extraction budget exhausted; remaining members were not scanned",
				"Split large archives or resend the file directly so every member can be scanned",
			))
		}
	}

	return findings
}

// locate names, in a finding, a file found inside an archive: the attachment
// the recipient sees, then the members leading down to it.
func locate(location string, within []string) string {
	if len(within) == 0 {
		return location
	}

	return location + " → " + strings.Join(within, " → ")
}

// bombMessage names the member that expands out of proportion, or the file
// itself when the format holds a single stream and there is no member to name.
func bombMessage(name string) string {
	if name == "" {
		return "Compressed data has an extreme compression ratio (possible archive bomb)"
	}

	return fmt.Sprintf("Archive member %q has an extreme compression ratio (possible archive bomb)", name)
}

// truncatedMessage names the member that was read only as far as the budget
// went.
func truncatedMessage(name string) string {
	if name == "" {
		return "Compressed content exceeds the scan budget and was only partially scanned"
	}

	return fmt.Sprintf("Archive member %q exceeds the scan budget and was only partially scanned", name)
}
