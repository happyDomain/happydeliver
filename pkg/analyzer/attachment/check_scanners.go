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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// clamavCheck reads the verdict the local scanner reached about this file.
//
// It reads an observation rather than making one: the scan happened when the
// message was, so that a file is handed over once however many checks care
// about the answer.
var clamavCheck = attachmentCheck{
	Name:     "clamav",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectMalware, defectScanError},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		scan := in.Attachment.ClamAV
		if scan == nil {
			return nil, nil
		}

		switch scan.Status {
		case "infected":
			found := finding(
				defectMalware,
				model.IssueTypeMalwareDetected,
				model.IssueSeverityCritical,
				in.Attachment.Location,
				fmt.Sprintf("ClamAV detected malware: %s", scan.Signature),
				"This attachment is malicious and must not be distributed",
			)
			found.Concern = concernMalware
			found.Issue.Source = source(model.IssueSourceClamav)

			return []reading.Finding{found}, nil

		case "error", "too_large":
			return []reading.Finding{scanCaveat("ClamAV", scan.Error, in.Attachment.Location)}, nil
		}

		return nil, nil
	},
}

// virustotalCheck reads what VirusTotal knows about this file.
var virustotalCheck = attachmentCheck{
	Name:     "virustotal",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectMalware, defectScanError},
	Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
		scan := in.Attachment.VirusTotal
		if scan == nil {
			return nil, nil
		}

		var found reading.Finding
		switch scan.Status {
		case "malicious":
			found = finding(
				defectMalware,
				model.IssueTypeMalwareDetected,
				model.IssueSeverityCritical,
				in.Attachment.Location,
				fmt.Sprintf("VirusTotal flags this file as malicious (%d/%d engines)", scan.Positives, scan.Total),
				"This attachment is known to be malicious and must not be distributed",
			)

		case "suspicious":
			found = finding(
				defectMalware,
				model.IssueTypeMalwareDetected,
				model.IssueSeverityHigh,
				in.Attachment.Location,
				fmt.Sprintf("VirusTotal flags this file as suspicious (%d/%d engines)", scan.Positives, scan.Total),
				"Several engines consider this attachment suspicious; verify its origin before opening it",
			)

		case "error":
			return []reading.Finding{scanCaveat("VirusTotal", scan.Error, in.Attachment.Location)}, nil

		default:
			return nil, nil
		}

		found.Concern = concernMalware
		found.Issue.Source = source(model.IssueSourceVirustotal)

		return []reading.Finding{found}, nil
	},
}

// scanCaveat says that a scanner was asked and did not answer, so that a
// reader does not take our silence about a file for a clean bill.
//
// It is a finding rather than an error of the check: the check reached a
// verdict, and the verdict is that this file stands unverified. That is
// something the reader must see, and nothing the sender pays for.
func scanCaveat(scanner, detail, location string) reading.Finding {
	message := fmt.Sprintf("%s could not scan this attachment", scanner)
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	return finding(
		defectScanError,
		model.IssueTypeScanError,
		model.IssueSeverityInfo,
		location,
		message,
		"This attachment was not verified by that scanner; the rest of the report stands",
	)
}

// source is the observer of a finding, as the report carries it.
func source(observer model.IssueSource) *model.IssueSource {
	return &observer
}
