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
	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/clamav"
	"git.happydns.org/happyDeliver/pkg/virustotal"
)

// Analysis is what the report shows of the attachments: each file, what the
// scanners said about it, and what the checks found in it.
//
// It takes the readings rather than producing them, because the same readings
// answer for the score: a file is handed to a scanner once per report.
func (a *Analyzer) Analysis(results *Results, readings []Reading) *model.AttachmentAnalysis {
	if results == nil {
		return nil
	}

	analysis := &model.AttachmentAnalysis{
		HasAttachments:    len(results.Attachments) > 0,
		ClamavEnabled:     utils.PtrTo(results.ClamAVEnabled),
		VirustotalEnabled: utils.PtrTo(results.VirusTotalEnabled),
	}

	if len(results.Attachments) == 0 {
		return analysis
	}

	checks := make([]model.AttachmentCheck, 0, len(results.Attachments))
	for i, attachment := range results.Attachments {
		check := model.AttachmentCheck{
			Sha256: attachment.SHA256,
			Size:   attachment.Size,
		}
		if attachment.Filename != "" {
			check.Filename = utils.PtrTo(attachment.Filename)
		}
		if attachment.DeclaredType != "" {
			check.DeclaredContentType = utils.PtrTo(attachment.DeclaredType)
		}
		if attachment.DetectedType != "" {
			check.DetectedContentType = utils.PtrTo(attachment.DetectedType)
		}
		if attachment.Inline {
			check.Inline = utils.PtrTo(true)
		}

		check.Clamav = clamavToModel(attachment.ClamAV, results.ClamAVEnabled)
		check.Virustotal = virustotalToModel(attachment.VirusTotal, results.VirusTotalEnabled)

		// The readings are index-aligned with the attachments, and a caller
		// that did not read at all leaves the findings out rather than
		// inventing an empty verdict.
		if i < len(readings) && len(readings[i].Issues) > 0 {
			issues := readings[i].Issues
			check.Issues = &issues
		}

		checks = append(checks, check)
	}
	analysis.Attachments = &checks

	return analysis
}

// clamavToModel converts a ClamAV scan to the API model, mapping a missing
// scan to the skipped status
func clamavToModel(scan *clamav.Scan, enabled bool) *model.ClamAVResult {
	if scan == nil {
		if !enabled {
			return &model.ClamAVResult{Status: model.ClamAVResultStatusSkipped}
		}
		return nil
	}

	result := &model.ClamAVResult{Status: model.ClamAVResultStatus(scan.Status)}
	if scan.Signature != "" {
		result.Signature = utils.PtrTo(scan.Signature)
	}
	return result
}

// virustotalToModel converts a VirusTotal scan to the API model, mapping a
// missing scan to the skipped status
func virustotalToModel(scan *virustotal.Scan, enabled bool) *model.VirusTotalResult {
	if scan == nil {
		if !enabled {
			return &model.VirusTotalResult{Status: model.VirusTotalResultStatusSkipped}
		}
		return nil
	}

	result := &model.VirusTotalResult{Status: model.VirusTotalResultStatus(scan.Status)}
	if scan.Total > 0 {
		result.Positives = utils.PtrTo(scan.Positives)
		result.Total = utils.PtrTo(scan.Total)
	}
	if scan.Permalink != "" {
		result.Permalink = utils.PtrTo(scan.Permalink)
	}
	return result
}
