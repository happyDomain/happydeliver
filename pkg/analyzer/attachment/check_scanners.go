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
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// scannerChecks is one check per engine the analysis knows of, read off
// knownScanners. One per engine rather than one over all of them, because the
// merge is written in terms of observers: two engines recognising one sample
// are two observers agreeing.
func scannerChecks() []attachmentCheck {
	checks := make([]attachmentCheck, 0, len(knownScanners))
	for _, def := range knownScanners {
		checks = append(checks, scannerCheck(def.scannerInfo))
	}

	return checks
}

// scannerCheck reads the verdict one engine reached about this file, in
// Analyze.
func scannerCheck(info scannerInfo) attachmentCheck {
	return attachmentCheck{
		Name:     info.Name,
		Category: reading.CategorySecurity,
		Reports:  []*reading.Defect{defectMalware, defectScanError, defectScanSkipped},
		Run: func(_ context.Context, in *attachmentInput) ([]reading.Finding, error) {
			scan := in.Attachment.ScanBy(info.Name)
			if scan == nil {
				return nil, nil
			}

			var found reading.Finding
			switch scan.Status {
			case model.ScanResultStatusMalicious:
				found = reading.NewFinding(
					defectMalware,
					model.IssueTypeMalwareDetected,
					model.IssueSeverityCritical,
					in.Attachment.Location,
					fmt.Sprintf("%s flags this file as malicious%s", info.Label, scanEvidence(scan)),
					"This attachment is known to be malicious and must not be distributed",
				)

			case model.ScanResultStatusSuspicious:
				found = reading.NewFinding(
					defectMalware,
					model.IssueTypeMalwareDetected,
					model.IssueSeverityHigh,
					in.Attachment.Location,
					fmt.Sprintf("%s finds this file suspicious%s", info.Label, scanEvidence(scan)),
					"This attachment is flagged by too few engines to call it malicious, and by too many to ignore; verify its origin before opening it",
				)

			case model.ScanResultStatusError:
				return []reading.Finding{scanCaveat(info.Label, scan.Detail, in.Attachment.Location)}, nil

			case model.ScanResultStatusSkipped:
				// A file the analysis never read is already reported by
				// sizeCheck.
				if in.Attachment.Data == nil {
					return nil, nil
				}

				return []reading.Finding{reading.NewFinding(
					defectScanSkipped,
					model.IssueTypeScanSkipped,
					model.IssueSeverityInfo,
					in.Attachment.Location,
					fmt.Sprintf("%s did not scan this attachment%s", info.Label, scanReason(scan)),
					"This attachment was not verified by that scanner; the rest of the report stands",
				)}, nil

			default:
				// Clean, unknown, pending, disabled: none of them is a finding.
				return nil, nil
			}

			found.Concern = concernMalware
			found.Issue.Source = utils.PtrTo(model.IssueSource(info.Name))

			return []reading.Finding{found}, nil
		},
	}
}

// scanEvidence is what the engine offers in support of its verdict: the name
// it gave the sample, or how many of the engines it speaks for flagged it.
func scanEvidence(scan *Scan) string {
	switch {
	case scan.Verdict != "":
		return fmt.Sprintf(": %s", scan.Verdict)
	case scan.EnginesTotal > 0:
		return fmt.Sprintf(" (%d/%d engines)", scan.EnginesFlagged, scan.EnginesTotal)
	default:
		return ""
	}
}

// scanReason is why a scanner said nothing about a file, when it said.
func scanReason(scan *Scan) string {
	if scan.Detail == "" {
		return ""
	}

	return fmt.Sprintf(": %s", scan.Detail)
}

// scanCaveat says that a scanner was asked and did not answer. It is a finding
// rather than an error of the check: the reader must see it, and the sender
// pays nothing for it.
func scanCaveat(scanner, detail, location string) reading.Finding {
	message := fmt.Sprintf("%s could not scan this attachment", scanner)
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	return reading.NewFinding(
		defectScanError,
		model.IssueTypeScanError,
		model.IssueSeverityInfo,
		location,
		message,
		"This attachment was not verified by that scanner; the rest of the report stands",
	)
}
