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

package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// AttachmentFinding is an issue detected in an attachment (analyzer-internal,
// converted to model.AttachmentIssue in GenerateAttachmentAnalysis)
type AttachmentFinding struct {
	Type     model.AttachmentIssueType
	Severity model.AttachmentIssueSeverity
	Message  string
	Location string
	Advice   string
}

// AttachmentAnalyzer extracts email attachments and analyzes their harmfulness
type AttachmentAnalyzer struct {
	scanTimeout time.Duration
	maxSize     int64 // per-attachment size cap for content analysis
}

// NewAttachmentAnalyzer creates a new attachment analyzer. Scanners with empty
// credentials/addresses are disabled and reported as skipped.
func NewAttachmentAnalyzer(clamavAddress, virustotalAPIKey string, virustotalUpload bool, scanTimeout time.Duration, maxSize int64) *AttachmentAnalyzer {
	return &AttachmentAnalyzer{
		scanTimeout: scanTimeout,
		maxSize:     maxSize,
	}
}

// AttachmentResults contains the intermediate analysis of all attachments
type AttachmentResults struct {
	Attachments       []AttachmentResult
	ClamAVEnabled     bool
	VirusTotalEnabled bool
}

// AttachmentResult is the analysis of a single attachment
type AttachmentResult struct {
	Filename     string
	DeclaredType string
	DetectedType string
	SHA256       string
	Size         int64
	Inline       bool
	Findings     []AttachmentFinding
}

// AnalyzeAttachments extracts and analyzes every attachment of the email
func (a *AttachmentAnalyzer) AnalyzeAttachments(email *EmailMessage) *AttachmentResults {
	results := &AttachmentResults{}

	attachments := email.GetAttachments()
	if len(attachments) == 0 {
		return results
	}

	results.Attachments = make([]AttachmentResult, len(attachments))

	for i := range attachments {
		part := &attachments[i]
		result := &results.Attachments[i]

		result.Filename = part.Filename
		result.DeclaredType = part.ContentType
		result.Inline = part.IsInline()

		location := part.Filename
		if location == "" {
			location = fmt.Sprintf("attachment #%d (%s)", i+1, part.ContentType)
		}

		data, err := part.DecodedBytes()
		if err != nil {
			result.Findings = append(result.Findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeScanError,
				Severity: model.AttachmentIssueSeverityInfo,
				Message:  fmt.Sprintf("Failed to decode attachment content: %v", err),
				Location: location,
				Advice:   "The attachment transfer encoding is corrupted; recipients may be unable to open it",
			})
			continue
		}

		checksum := sha256.Sum256(data)
		result.SHA256 = hex.EncodeToString(checksum[:])
		result.Size = int64(len(data))
		result.DetectedType = detectContentType(data)

		if a.maxSize > 0 && result.Size > a.maxSize {
			result.Findings = append(result.Findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeScanSkipped,
				Severity: model.AttachmentIssueSeverityInfo,
				Message:  fmt.Sprintf("Attachment is too large to analyze (%d bytes)", result.Size),
				Location: location,
				Advice:   "Large attachments hurt deliverability; consider linking to a download instead",
			})
			continue
		}
	}

	return results
}

// detectContentType sniffs a content type from magic bytes
func detectContentType(data []byte) string {
	return mimetype.Detect(data).String()
}

// GenerateAttachmentAnalysis converts internal results to the API model
func (a *AttachmentAnalyzer) GenerateAttachmentAnalysis(results *AttachmentResults) *model.AttachmentAnalysis {
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
	for _, result := range results.Attachments {
		check := model.AttachmentCheck{
			Sha256: result.SHA256,
			Size:   result.Size,
		}
		if result.Filename != "" {
			check.Filename = utils.PtrTo(result.Filename)
		}
		if result.DeclaredType != "" {
			check.DeclaredContentType = utils.PtrTo(result.DeclaredType)
		}
		if result.DetectedType != "" {
			check.DetectedContentType = utils.PtrTo(result.DetectedType)
		}
		if result.Inline {
			check.Inline = utils.PtrTo(true)
		}

		check.Clamav = &model.ClamAVResult{Status: model.ClamAVResultStatusSkipped}
		check.Virustotal = &model.VirusTotalResult{Status: model.VirusTotalResultStatusSkipped}

		if len(result.Findings) > 0 {
			issues := make([]model.AttachmentIssue, 0, len(result.Findings))
			for _, finding := range result.Findings {
				issue := model.AttachmentIssue{
					Type:     finding.Type,
					Severity: finding.Severity,
					Message:  finding.Message,
				}
				if finding.Location != "" {
					issue.Location = utils.PtrTo(finding.Location)
				}
				if finding.Advice != "" {
					issue.Advice = utils.PtrTo(finding.Advice)
				}
				issues = append(issues, issue)
			}
			check.Issues = &issues
		}

		checks = append(checks, check)
	}
	analysis.Attachments = &checks

	return analysis
}

// CalculateAttachmentScore computes the attachments category score.
// An email without attachments scores a perfect 100.
func (a *AttachmentAnalyzer) CalculateAttachmentScore(results *AttachmentResults) (int, string) {
	if results == nil {
		return 100, ScoreToGrade(100)
	}

	score := 100

	for i := range results.Attachments {
		result := &results.Attachments[i]

		// One penalty per finding type per attachment
		seen := make(map[model.AttachmentIssueType]bool)
		for _, finding := range result.Findings {
			if seen[finding.Type] {
				continue
			}
			seen[finding.Type] = true
			score -= findingPenalty(finding)
		}
	}

	if score < 0 {
		score = 0
	}

	return score, ScoreToGrade(score)
}

// findingPenalty maps a finding to its score deduction. Informational
// findings (scanner disabled, unknown hash, oversize) cost nothing.
func findingPenalty(finding AttachmentFinding) int {
	switch finding.Type {
	case model.AttachmentIssueTypeExecutableContent:
		return 50
	case model.AttachmentIssueTypeDangerousExtension, model.AttachmentIssueTypeDoubleExtension,
		model.AttachmentIssueTypeArchiveBomb:
		return 40
	case model.AttachmentIssueTypeMacroDetected:
		return 30
	case model.AttachmentIssueTypePdfActiveContent, model.AttachmentIssueTypeScriptContent:
		if finding.Severity == model.AttachmentIssueSeverityHigh {
			return 30
		}
		return 15
	case model.AttachmentIssueTypeTypeMismatch:
		if finding.Severity == model.AttachmentIssueSeverityHigh {
			return 40
		}
		return 20
	case model.AttachmentIssueTypePasswordProtected, model.AttachmentIssueTypeNestedArchive:
		return 15
	default:
		// malware_detected is handled via the score floor; scan_error,
		// scan_skipped and other informational findings carry no penalty
		return 0
	}
}
