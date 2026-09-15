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
// It is built like the content analysis next door, and for the same reason:
// what is observed about a file (its bytes, its name, what a scanner said) is
// gathered once, and what that is worth is read off a registry of checks, so
// that adding a way of being suspicious is writing a check rather than
// threading a verdict through a pipeline.
package attachment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/pkg/clamav"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
	"git.happydns.org/happyDeliver/pkg/virustotal"
)

// scanConcurrency bounds how many attachments are handed to the external
// scanners at once.
const scanConcurrency = 4

// Options is what an operator decides about the attachment analysis: which
// scanners it may ask, and how much of a message it will look at.
//
// It is a struct rather than a run of arguments so that a caller reads what it
// is configuring, and so that adding a scanner tomorrow does not renumber
// every call site.
type Options struct {
	// ClamAVAddress is the clamd instance attachments are submitted to. Empty
	// leaves them unscanned.
	ClamAVAddress string

	// VirusTotalAPIKey is the key the attachment hashes are looked up with.
	// Empty leaves them unqueried.
	VirusTotalAPIKey string

	// VirusTotalUpload allows submitting an attachment VirusTotal does not
	// already know the hash of. Off by default: it hands the file over to a
	// third party.
	VirusTotalUpload bool

	// ScanTimeout bounds each external scan.
	ScanTimeout time.Duration

	// MaxSize is the largest attachment whose content is analysed, in bytes.
	// Zero means no limit.
	MaxSize int64
}

// Analyzer reads the attachments of a message.
type Analyzer struct {
	clamav      *clamav.Client     // nil = disabled
	virustotal  *virustotal.Client // nil = disabled
	scanTimeout time.Duration
	maxSize     int64
}

// defaultScanTimeout bounds a scan, and the reading of an attachment, when the
// caller named no bound: a zero duration would hand every check a deadline
// that has already passed.
const defaultScanTimeout = 30 * time.Second

// New creates an attachment analyzer. A scanner with no address or no
// credentials is disabled, and the report says so rather than staying silent
// about a verdict nobody produced.
func New(opts Options) *Analyzer {
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = defaultScanTimeout
	}

	return &Analyzer{
		clamav:      clamav.New(opts.ClamAVAddress, opts.ScanTimeout),
		virustotal:  virustotal.New(opts.VirusTotalAPIKey, opts.VirusTotalUpload, opts.ScanTimeout),
		scanTimeout: opts.ScanTimeout,
		maxSize:     opts.MaxSize,
	}
}

// Results is what was observed about the attachments of one message, before
// anything is judged.
type Results struct {
	Attachments []Attachment

	// ClamAVEnabled and VirusTotalEnabled say whether an operator configured
	// the scanner at all, which is what tells a missing verdict from a clean
	// one.
	ClamAVEnabled     bool
	VirusTotalEnabled bool
}

// Attachment is one file a message carries, as it was read off it.
type Attachment struct {
	Filename     string
	DeclaredType string
	DetectedType string
	SHA256       string
	Size         int64
	Inline       bool

	// Location names this attachment in a finding. It is settled here, once,
	// so that every check names the same file the same way, whether or not the
	// part bothered to give itself a filename.
	Location string

	// Data is the decoded payload, and nil when the attachment was too large
	// to look at: that is what a check reading bytes tests before reading any.
	Data []byte

	// ClamAV and VirusTotal are what the scanners said, nil when the scanner
	// is disabled or was never asked. They are observed here rather than in a
	// check because the report shows them whether or not they raised a
	// finding, exactly as it shows what the spam filter said about the body.
	ClamAV     *clamav.Scan
	VirusTotal *virustotal.Scan

	// mime is the type sniffed from the payload, kept as the library returned
	// it: a check comparing a declared type to it walks its parents, which a
	// string cannot do. The message is sniffed once, here.
	mime *mimetype.MIME
}

// tooLarge reports that the attachment was left unanalysed for its size.
func (a *Attachment) tooLarge(maxSize int64) bool {
	return maxSize > 0 && a.Size > maxSize
}

// Analyze reads the attachments off a message and asks the scanners about
// them. It observes, and judges nothing: what the observations are worth is
// Read's answer.
func (a *Analyzer) Analyze(email *mailmsg.Message) *Results {
	results := &Results{
		ClamAVEnabled:     a.clamav != nil,
		VirusTotalEnabled: a.virustotal != nil,
	}

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
		attachment.Inline = part.IsInline()
		attachment.SHA256 = hex.EncodeToString(checksum[:])
		attachment.Size = int64(len(data))
		attachment.Location = attachmentLocation(i, part)
		attachment.mime = mimetype.Detect(data)
		attachment.DetectedType = attachment.mime.String()

		// A file nobody will look at is still named, sized and typed in the
		// report: what is withheld is the reading of its content, which is
		// what leaving Data nil says to the checks.
		if attachment.tooLarge(a.maxSize) {
			continue
		}
		attachment.Data = data

		// The scanners are the only slow part of the observation, and they are
		// independent of one another: they run together, under a bound, while
		// the rest of the message is read.
		if a.clamav != nil {
			wg.Add(1)
			go func(attachment *Attachment, data []byte) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				ctx, cancel := context.WithTimeout(context.Background(), a.scanTimeout)
				defer cancel()
				attachment.ClamAV = a.clamav.ScanBytes(ctx, data)
			}(attachment, data)
		}
		if a.virustotal != nil {
			wg.Add(1)
			go func(attachment *Attachment, sum string, data []byte) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				ctx, cancel := context.WithTimeout(context.Background(), a.scanTimeout)
				defer cancel()
				attachment.VirusTotal = a.virustotal.CheckHash(ctx, sum, data)
			}(attachment, attachment.SHA256, data)
		}
	}

	wg.Wait()

	return results
}

// attachmentLocation names an attachment in a finding: the name it gives
// itself, or its rank in the message when it gives none.
//
// There is one of these, and every finding about the file goes through it: a
// reader following two findings about one attachment must not be shown two
// names for it.
func attachmentLocation(index int, part *mailmsg.Part) string {
	if part.Filename != "" {
		return part.Filename
	}

	return fmt.Sprintf("attachment #%d (%s)", index+1, part.ContentType)
}
