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

package fileinspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"slices"

	"github.com/gabriel-vasile/mimetype"
)

// Limits bounds what looking inside an archive may cost.
type Limits struct {
	// MaxDepth is how many archives deep the walk goes. Content below it is
	// reported as unreached.
	MaxDepth int

	// MaxTotalBytes bounds the uncompressed bytes read out of one file, every
	// member and every nesting level together.
	MaxTotalBytes int64

	// MaxEntries bounds the members read out of one file.
	MaxEntries int

	// MaxEntryBytes bounds a single decompressed member.
	MaxEntryBytes int64

	// BombRatio is the compression ratio past which a member the budget could
	// not read through is reported as a bomb rather than as cut short.
	BombRatio uint64
}

// DefaultLimits is what an archive is read under when the caller names none.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:      3,
		MaxTotalBytes: 100 << 20,
		MaxEntries:    1000,
		MaxEntryBytes: 50 << 20,
		BombRatio:     100,
	}
}

// EntryKind says what looking inside an archive turned up at one place.
type EntryKind string

const (
	// KindMember is a file that was read, exactly as one handed to Inspect.
	KindMember EntryKind = "member"

	// KindNested is a member that is itself an archive. The walk goes on
	// inside it, and the entries it turns up follow this one.
	KindNested EntryKind = "nested"

	// KindEncrypted is an archive whose members are locked. It is reported
	// once per archive.
	KindEncrypted EntryKind = "encrypted"

	// KindBomb is a member the budget could not read through, and that had
	// by then expanded out of all proportion to its compressed size.
	KindBomb EntryKind = "bomb"

	// KindTruncated is a member read only as far as the budget went.
	KindTruncated EntryKind = "truncated"

	// KindTooDeep is an archive the walk stopped at, having reached MaxDepth.
	// It was read as a file, but not what it holds.
	KindTooDeep EntryKind = "too_deep"

	// KindBudgetExhausted is the walk giving up: what follows was not read.
	// It is reported once.
	KindBudgetExhausted EntryKind = "budget_exhausted"
)

// Entry is one thing looking inside an archive turned up: a file that was
// read, or a place the reading stopped.
type Entry struct {
	// Kind says what was turned up.
	Kind EntryKind

	// At is where it was found: the member names from the file handed to Walk
	// inwards, the innermost last. It is empty for what is about that file
	// itself: one that is locked, or that the walk gave up on.
	At []string

	// Name is the member this entry is about, empty when the entry is about an
	// archive rather than one of its members. It is the name as the archive
	// wrote it, which is not to be trusted as a path.
	Name string

	// Facts is what reading the member turned up. It is set for every entry
	// naming a member that was read (KindMember, KindNested, KindTooDeep), and
	// is the zero Facts otherwise.
	Facts Facts
}

// tarMediaType is named apart from the other openers because a gzip stream
// asks after it: a tar inside a gzip is how the stream is laid out, not a
// member of it.
const tarMediaType = "application/x-tar"

// opener says how Walk looks inside content of the given media type, and nil
// when the content is not an archive. It goes by the detected type, not by the
// magic number: an Office document, an OpenDocument file or a jar all start
// the way a zip does, and are read as documents rather than archives.
func opener(mediaType string) func(*walker, []byte, []string, int) {
	switch mediaType {
	case "application/zip":
		return (*walker).insideZip
	case "application/gzip":
		return (*walker).insideGzip
	case tarMediaType:
		return (*walker).insideTar
	}

	return nil
}

// Walk looks inside an archive and answers what it turned up, in order: every
// member read, and every place the reading stopped. A file that is not an
// archive answers nothing, and zero limits are the default ones.
func Walk(data []byte, limits Limits) []Entry {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}

	walk := &walker{
		limits:           limits,
		remainingBytes:   limits.MaxTotalBytes,
		remainingEntries: limits.MaxEntries,
	}
	walk.inside(mimetype.Detect(data).String(), data, nil, 0)

	return walk.entries
}

// walker carries what the walk has spent across the recursion, and what it has
// turned up so far.
type walker struct {
	limits            Limits
	remainingBytes    int64
	remainingEntries  int
	reportedExhausted bool
	entries           []Entry
}

// add records one thing turned up.
func (w *walker) add(entry Entry) {
	w.entries = append(w.entries, entry)
}

// afford says whether there is budget left to read one more member, and when
// there is not, records once per file that the walk gave up.
func (w *walker) afford(at []string) bool {
	if w.remainingBytes > 0 && w.remainingEntries > 0 {
		w.remainingEntries--
		return true
	}

	if !w.reportedExhausted {
		w.reportedExhausted = true
		w.add(Entry{Kind: KindBudgetExhausted, At: at})
	}

	return false
}

// inside walks one archive, whichever format it was detected in.
func (w *walker) inside(mediaType string, data []byte, at []string, depth int) {
	if open := opener(mediaType); open != nil {
		open(w, data, at, depth)
	}
}

// extract reads one member out of its stream, as far as the budget goes.
// compressed is the room the member takes in the archive, 0 when the format
// does not compress. A member that had to be cut short and had expanded out
// of all proportion to that room by then is a bomb; one that fits in the
// budget is read whatever its ratio, since a log or a dump compresses very
// well.
func (w *walker) extract(from io.Reader, compressed int64, at []string, name string) ([]byte, bool) {
	maxRead := min(w.remainingBytes, w.limits.MaxEntryBytes)

	buf, err := io.ReadAll(io.LimitReader(from, maxRead+1))
	if err != nil {
		return nil, false
	}
	if int64(len(buf)) <= maxRead {
		w.remainingBytes -= int64(len(buf))
		return buf, true
	}
	w.remainingBytes -= maxRead

	if compressed > 0 && maxRead > compressed*int64(w.limits.BombRatio) {
		w.add(Entry{Kind: KindBomb, At: at, Name: name})
		return nil, false
	}

	w.add(Entry{Kind: KindTruncated, At: at, Name: name})

	return buf[:maxRead], true
}

// member reads one extracted file as a file, and goes on inside it when it is
// itself an archive.
func (w *walker) member(name string, content []byte, at []string, depth int) {
	within := append(slices.Clone(at), name)

	// A member declares no type of its own.
	facts := Inspect(name, "", content)

	open := opener(facts.Type.Detected)
	if open == nil {
		w.add(Entry{Kind: KindMember, At: within, Name: name, Facts: facts})
		return
	}

	if depth+1 >= w.limits.MaxDepth {
		w.add(Entry{Kind: KindTooDeep, At: within, Name: name, Facts: facts})
		return
	}

	w.add(Entry{Kind: KindNested, At: within, Name: name, Facts: facts})
	open(w, content, within, depth+1)
}

func (w *walker) insideZip(data []byte, at []string, depth int) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}

	reportedEncrypted := false
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if !w.afford(at) {
			break
		}

		// Flag bit 0 marks an encrypted member. The archive answers for it
		// once.
		if entry.Flags&0x1 != 0 {
			if !reportedEncrypted {
				reportedEncrypted = true
				w.add(Entry{Kind: KindEncrypted, At: at})
			}
			continue
		}

		rc, err := entry.Open()
		if err != nil {
			continue
		}
		content, ok := w.extract(rc, int64(entry.CompressedSize64), at, entry.Name)
		rc.Close()
		if !ok {
			continue
		}

		w.member(entry.Name, content, at, depth)
	}
}

func (w *walker) insideGzip(data []byte, at []string, depth int) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer reader.Close()

	if !w.afford(at) {
		return
	}

	// A gzip stream holds one member, which has no name of its own.
	content, ok := w.extract(reader, int64(len(data)), at, "")
	if !ok {
		return
	}

	name := reader.Name
	if name == "" {
		name = "(gzip content)"
	}

	// A tar inside is not a member of the stream but the way it is laid out.
	if mimetype.Detect(content).Is(tarMediaType) {
		w.insideTar(content, append(slices.Clone(at), name), depth)
		return
	}

	w.member(name, content, at, depth)
}

func (w *walker) insideTar(data []byte, at []string, depth int) {
	reader := tar.NewReader(bytes.NewReader(data))

	for {
		header, err := reader.Next()
		if err != nil {
			return
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !w.afford(at) {
			return
		}

		content, ok := w.extract(reader, 0, at, header.Name)
		if !ok {
			return
		}

		w.member(header.Name, content, at, depth)
	}
}
