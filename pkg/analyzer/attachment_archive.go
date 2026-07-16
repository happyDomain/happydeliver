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
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"git.happydns.org/happyDeliver/internal/model"
)

const (
	// archiveMaxDepth is the maximum nesting level inspected (zip in zip in zip)
	archiveMaxDepth = 3
	// archiveMaxTotalSize bounds the cumulated uncompressed bytes read per attachment
	archiveMaxTotalSize = 100 << 20 // 100 MiB
	// archiveMaxEntries bounds the number of archive members inspected per attachment
	archiveMaxEntries = 1000
	// archiveMaxEntrySize bounds a single decompressed member
	archiveMaxEntrySize = 50 << 20 // 50 MiB
	// archiveBombRatio flags entries whose compression ratio betrays a zip bomb
	archiveBombRatio = 100
)

// archiveBudget carries the shared extraction limits across the recursion
type archiveBudget struct {
	remainingBytes    int64
	remainingEntries  int
	reportedExhausted bool
}

// budgetExhausted emits a finding, once per attachment, when the extraction
// budget runs out so members skipped afterwards don't silently read as empty
func budgetExhausted(location string, budget *archiveBudget) []AttachmentFinding {
	if budget.reportedExhausted {
		return nil
	}
	budget.reportedExhausted = true
	return []AttachmentFinding{{
		Type:     model.AttachmentIssueTypeScanSkipped,
		Severity: model.AttachmentIssueSeverityMedium,
		Message:  "Archive extraction budget exhausted; remaining members were not scanned",
		Location: location,
		Advice:   "Split large archives or resend the file directly so every member can be scanned",
	}}
}

// inspectArchive recursively analyzes archive attachments (zip, gzip, tar).
// It reports password-protected members, nesting beyond archiveMaxDepth,
// zip bombs, and runs the static checks on every extracted member.
// Non-archive data yields no findings.
func inspectArchive(data []byte, location string, depth int, budget *archiveBudget) (findings []AttachmentFinding) {
	if budget == nil {
		budget = &archiveBudget{
			remainingBytes:   archiveMaxTotalSize,
			remainingEntries: archiveMaxEntries,
		}
	}

	switch {
	case bytes.HasPrefix(data, []byte("PK")):
		return inspectZip(data, location, depth, budget)
	case bytes.HasPrefix(data, []byte("\x1f\x8b")):
		return inspectGzip(data, location, depth, budget)
	case isTar(data):
		return inspectTar(data, location, depth, budget)
	}
	return nil
}

// isArchive reports whether data looks like an archive format handled by
// inspectArchive
func isArchive(data []byte) bool {
	return bytes.HasPrefix(data, []byte("PK")) ||
		bytes.HasPrefix(data, []byte("\x1f\x8b")) ||
		isTar(data)
}

// isTar checks the ustar magic at the fixed header offset
func isTar(data []byte) bool {
	return len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar"))
}

// exceededDepth emits the nested-archive finding when recursion goes too deep
func exceededDepth(location string) []AttachmentFinding {
	return []AttachmentFinding{{
		Type:     model.AttachmentIssueTypeNestedArchive,
		Severity: model.AttachmentIssueSeverityMedium,
		Message:  fmt.Sprintf("Archive nesting exceeds %d levels; deeper content was not inspected", archiveMaxDepth),
		Location: location,
		Advice:   "Deeply nested archives are used to evade content scanners",
	}}
}

// inspectMember runs the per-file checks on an extracted archive member and
// recurses into nested archives
func inspectMember(name string, content []byte, location string, depth int, budget *archiveBudget) (findings []AttachmentFinding) {
	memberLocation := fmt.Sprintf("%s → %s", location, name)

	_, memberFindings := staticCheckAttachment(name, "", content, memberLocation)
	findings = append(findings, memberFindings...)

	if isArchive(content) {
		if depth+1 >= archiveMaxDepth {
			findings = append(findings, exceededDepth(memberLocation)...)
		} else {
			findings = append(findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeNestedArchive,
				Severity: model.AttachmentIssueSeverityMedium,
				Message:  fmt.Sprintf("Archive contains a nested archive %q", name),
				Location: memberLocation,
				Advice:   "Nested archives are frequently used to hide malicious payloads from scanners",
			})
			findings = append(findings, inspectArchive(content, memberLocation, depth+1, budget)...)
		}
	}

	return findings
}

func inspectZip(data []byte, location string, depth int, budget *archiveBudget) (findings []AttachmentFinding) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}

	reportedEncrypted := false
	for _, entry := range reader.File {
		if budget.remainingEntries <= 0 {
			break
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if budget.remainingBytes <= 0 {
			findings = append(findings, budgetExhausted(location, budget)...)
			break
		}
		budget.remainingEntries--

		// Flag bit 0 marks an encrypted member
		if entry.Flags&0x1 != 0 {
			if !reportedEncrypted {
				reportedEncrypted = true
				findings = append(findings, AttachmentFinding{
					Type:     model.AttachmentIssueTypePasswordProtected,
					Severity: model.AttachmentIssueSeverityMedium,
					Message:  "Archive is password-protected and cannot be scanned",
					Location: location,
					Advice:   "Password-protected archives are a common malware-delivery technique because scanners cannot inspect them",
				})
			}
			continue
		}

		// Zip-bomb heuristic on declared sizes. Only the flagged entry is
		// skipped: later entries may hold the actual payload and must still
		// be scanned.
		if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > archiveBombRatio &&
			entry.UncompressedSize64 > 1<<20 {
			findings = append(findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeArchiveBomb,
				Severity: model.AttachmentIssueSeverityHigh,
				Message:  fmt.Sprintf("Archive member %q has an extreme compression ratio (possible archive bomb)", entry.Name),
				Location: location,
				Advice:   "Archive bombs expand to enormous sizes to exhaust scanner and system resources",
			})
			continue
		}

		// Declared sizes are attacker-controlled and not trusted: the read is
		// capped purely by the shared budget, and truncation is detected by
		// reading one byte past the cap rather than trusting UncompressedSize64.
		maxRead := min(budget.remainingBytes, archiveMaxEntrySize)
		content, truncated, ok := readArchiveMember(entry, maxRead, budget)
		if !ok {
			continue
		}
		if truncated {
			findings = append(findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeScanSkipped,
				Severity: model.AttachmentIssueSeverityMedium,
				Message:  fmt.Sprintf("Archive member %q exceeds the scan budget and was only partially scanned", entry.Name),
				Location: location,
				Advice:   "Oversized archive members cannot be fully scanned; treat them as unverified",
			})
		}

		findings = append(findings, inspectMember(entry.Name, content, location, depth, budget)...)
	}

	return findings
}

// readArchiveMember extracts one zip member within the byte budget. It reads
// one byte past maxRead to detect truncation without trusting the entry's
// declared (attacker-controlled) UncompressedSize64.
func readArchiveMember(entry *zip.File, maxRead int64, budget *archiveBudget) (content []byte, truncated bool, ok bool) {
	rc, err := entry.Open()
	if err != nil {
		return nil, false, false
	}
	defer rc.Close()

	buf, err := io.ReadAll(io.LimitReader(rc, maxRead+1))
	if err != nil {
		return nil, false, false
	}
	if int64(len(buf)) > maxRead {
		buf = buf[:maxRead]
		truncated = true
	}
	budget.remainingBytes -= int64(len(buf))
	return buf, truncated, true
}

func inspectGzip(data []byte, location string, depth int, budget *archiveBudget) (findings []AttachmentFinding) {
	if budget.remainingBytes <= 0 {
		return budgetExhausted(location, budget)
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer reader.Close()

	maxRead := min(budget.remainingBytes, archiveMaxEntrySize)
	content, err := io.ReadAll(io.LimitReader(reader, maxRead+1))
	if err != nil {
		return nil
	}
	truncated := int64(len(content)) > maxRead
	if truncated {
		content = content[:maxRead]
	}
	budget.remainingBytes -= int64(len(content))
	if truncated {
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeScanSkipped,
			Severity: model.AttachmentIssueSeverityMedium,
			Message:  "Gzip content exceeds the scan budget and was only partially scanned",
			Location: location,
			Advice:   "Oversized archive members cannot be fully scanned; treat them as unverified",
		})
	}

	if int64(len(content)) > int64(len(data))*archiveBombRatio && len(content) > 1<<20 {
		findings = append(findings, AttachmentFinding{
			Type:     model.AttachmentIssueTypeArchiveBomb,
			Severity: model.AttachmentIssueSeverityHigh,
			Message:  "Compressed data has an extreme compression ratio (possible archive bomb)",
			Location: location,
			Advice:   "Archive bombs expand to enormous sizes to exhaust scanner and system resources",
		})
		return findings
	}

	name := reader.Name
	if name == "" {
		name = "(gzip content)"
	}

	// A gzip stream holds a single member: tar inside is the common case
	if isTar(content) {
		findings = append(findings, inspectTar(content, fmt.Sprintf("%s → %s", location, name), depth, budget)...)
		return findings
	}
	findings = append(findings, inspectMember(name, content, location, depth, budget)...)
	return findings
}

func inspectTar(data []byte, location string, depth int, budget *archiveBudget) (findings []AttachmentFinding) {
	reader := tar.NewReader(bytes.NewReader(data))

	for budget.remainingEntries > 0 {
		if budget.remainingBytes <= 0 {
			findings = append(findings, budgetExhausted(location, budget)...)
			break
		}

		header, err := reader.Next()
		if err != nil {
			break
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		budget.remainingEntries--

		maxRead := min(budget.remainingBytes, archiveMaxEntrySize)
		content, err := io.ReadAll(io.LimitReader(reader, maxRead+1))
		if err != nil {
			break
		}
		truncated := int64(len(content)) > maxRead
		if truncated {
			content = content[:maxRead]
		}
		budget.remainingBytes -= int64(len(content))
		if truncated {
			findings = append(findings, AttachmentFinding{
				Type:     model.AttachmentIssueTypeScanSkipped,
				Severity: model.AttachmentIssueSeverityMedium,
				Message:  fmt.Sprintf("Archive member %q exceeds the scan budget and was only partially scanned", header.Name),
				Location: location,
				Advice:   "Oversized archive members cannot be fully scanned; treat them as unverified",
			})
		}

		findings = append(findings, inspectMember(header.Name, content, location, depth, budget)...)
	}

	return findings
}
