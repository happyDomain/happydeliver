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

// Package attachment reads what a message carries alongside its body.
//
// It is built like the content analysis: what is observed about a file is
// gathered once, and what that is worth is read off a registry of checks.
// Reading the formats themselves is fileinspect's business, which answers
// facts and prices none of them; this package says which of those facts is a
// defect, how grave it is, and what a sender is to do about it.
package attachment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// scanConcurrency bounds how many attachments are handed to the external
// scanners at once.
const scanConcurrency = 4

// Options is what an operator decides about the attachment analysis as a
// whole. What each scanner needs to run is declared in that scanner's file.
type Options struct {
	// ScanTimeout bounds each external scan.
	ScanTimeout time.Duration

	// MaxSize is the largest attachment whose content is analysed, in bytes.
	// Zero means no limit.
	MaxSize int64

	// scanners, when set, are the engines this instance runs instead of the
	// ones the operator configured. Tests set it to hand over a fake.
	scanners []scanner
}

// Analyzer reads the attachments of a message.
type Analyzer struct {
	// scanners are the engines this instance actually runs.
	scanners    []scanner
	scanTimeout time.Duration
	maxSize     int64
}

// defaultScanTimeout bounds a scan, and the reading of an attachment, when the
// caller named no bound.
const defaultScanTimeout = 30 * time.Second

// New creates an attachment analyzer. A scanner with no address or no
// credentials is not run, and the report does not mention it: which engines
// an instance leaves unconfigured is the instance's business, not the
// reader's.
func New(opts Options) *Analyzer {
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = defaultScanTimeout
	}

	a := &Analyzer{
		scanTimeout: opts.ScanTimeout,
		maxSize:     opts.MaxSize,
	}

	if opts.scanners != nil {
		a.scanners = opts.scanners
		return a
	}

	for _, def := range knownScanners {
		if engine := def.build(opts.ScanTimeout); engine != nil {
			a.scanners = append(a.scanners, engine)
		}
	}

	return a
}

// scannerFor is the engine this instance runs under that name, or nil when it
// runs none.
func (a *Analyzer) scannerFor(name string) scanner {
	for _, engine := range a.scanners {
		if engine.info().Name == name {
			return engine
		}
	}

	return nil
}

// Results is what was observed about the attachments of one message, before
// anything is judged.
type Results struct {
	Attachments []Attachment
}

// Attachment is one file a message carries, as it was read off it.
type Attachment struct {
	Filename string

	// DeclaredType is the Content-Type header as the part wrote it, which the
	// report shows, and DeclaredMediaType the type it names, which the checks
	// compare against.
	DeclaredType      string
	DeclaredMediaType string

	DetectedType string
	SHA256       string
	Size         int64
	Inline       bool

	// Location names this attachment in a finding. It is settled here, once,
	// so that every check names the same file the same way.
	Location string

	// Data is the decoded payload, and nil when the attachment was too large
	// to look at.
	Data []byte

	// Scans is what the engines said about this file: one entry per scanner
	// the analysis knows of, including the ones this instance does not run and
	// the ones not asked about this file, so that a reader never reads our
	// silence as a clean bill.
	Scans []Scan

	// facts are what reading the file offline turned up. The file is read
	// once, here, and every check reads its own part off it. A file too large
	// to look at carries only its name and its type.
	facts fileinspect.Facts
}

// ScanBy is what the named engine said about this file, or nil when the
// analysis does not know that engine at all.
func (a *Attachment) ScanBy(scanner string) *Scan {
	for i := range a.Scans {
		if a.Scans[i].Scanner == scanner {
			return &a.Scans[i]
		}
	}

	return nil
}

// tooLarge reports that the attachment was left unanalysed for its size.
func (a *Attachment) tooLarge(maxSize int64) bool {
	return maxSize > 0 && a.Size > maxSize
}

// Analyze reads the attachments off a message and asks the scanners about
// them. It observes and judges nothing: that is Read's job.
func (a *Analyzer) Analyze(email *mailmsg.Message) *Results {
	results := &Results{}

	parts := email.GetAttachments()
	if len(parts) == 0 {
		return results
	}

	results.Attachments = make([]Attachment, len(parts))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, scanConcurrency)

	for i := range parts {
		part := &parts[i]
		attachment := &results.Attachments[i]

		data := part.DecodedBytes()
		checksum := sha256.Sum256(data)

		attachment.Filename = part.Filename
		attachment.DeclaredType = part.ContentType
		attachment.DeclaredMediaType = part.MediaType
		attachment.Inline = part.IsInline()
		attachment.SHA256 = hex.EncodeToString(checksum[:])
		attachment.Size = int64(len(data))
		attachment.Location = attachmentLocation(i, part)

		// A file too large to look at is still named, sized and typed in the
		// report; leaving Data nil tells the checks its content was not read.
		if attachment.tooLarge(a.maxSize) {
			attachment.facts = fileinspect.InspectHeader(part.Filename, part.MediaType, data)
		} else {
			attachment.Data = data
			attachment.facts = fileinspect.Inspect(part.Filename, part.MediaType, data)
		}
		attachment.DetectedType = attachment.facts.Type.Detected

		// Only the scanners this instance runs get an entry: an engine the
		// reader never hears of is one that was never in the picture.
		attachment.Scans = make([]Scan, len(a.scanners))

		for j, engine := range a.scanners {
			name := engine.info().Name

			if attachment.Data == nil {
				attachment.Scans[j] = Scan{
					Scanner: name,
					Status:  model.ScanResultStatusSkipped,
					Detail:  fmt.Sprintf("the attachment was not read: it is larger than the %d bytes this analysis looks at", a.maxSize),
				}
				continue
			}

			attachment.Scans[j] = Scan{Scanner: name, Status: model.ScanResultStatusPending}

			wg.Add(1)
			go func(scan *Scan, engine scanner, attachment *Attachment) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				ctx, cancel := context.WithTimeout(context.Background(), a.scanTimeout)
				defer cancel()
				*scan = engine.scan(ctx, attachment)
			}(&attachment.Scans[j], engine, attachment)
		}
	}

	wg.Wait()

	return results
}

// attachmentLocation names an attachment in a finding: the name it gives
// itself, or its rank in the message when it gives none.
func attachmentLocation(index int, part *mailmsg.Part) string {
	if part.Filename != "" {
		return part.Filename
	}

	return fmt.Sprintf("attachment #%d (%s)", index+1, part.ContentType)
}
