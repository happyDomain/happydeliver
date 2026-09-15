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
	"fmt"
	"slices"
	"strings"
	"testing"
)

// zipOf builds a zip holding one member.
func zipOf(t *testing.T, name string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	entry.Write(content)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// kinds is what a walk turned up, counted by kind.
func kinds(entries []Entry) map[EntryKind]int {
	counted := make(map[EntryKind]int, len(entries))
	for _, entry := range entries {
		counted[entry.Kind]++
	}

	return counted
}

func TestWalkNestedZip(t *testing.T) {
	entries := Walk(zipOf(t, "inner.zip", zipOf(t, "payload.pdf.exe", mzStub)), Limits{})

	nested := false
	member := false
	for _, entry := range entries {
		switch entry.Kind {
		case KindNested:
			nested = true
			if !slices.Equal(entry.At, []string{"inner.zip"}) {
				t.Errorf("Expected the nested archive to be found at inner.zip, got %v", entry.At)
			}
		case KindMember:
			member = true
			// The path is what a recipient would double-click their way
			// through.
			if !slices.Equal(entry.At, []string{"inner.zip", "payload.pdf.exe"}) {
				t.Errorf("Expected the payload to be found inside inner.zip, got %v", entry.At)
			}
			if entry.Facts.Executable == "" {
				t.Errorf("Expected the member to be read as a program, got %+v", entry.Facts)
			}
			if entry.Facts.Name.Decoy != "pdf" {
				t.Errorf("Expected the member's name to be read as a disguise, got %+v", entry.Facts.Name)
			}
		}
	}

	if !nested || !member {
		t.Errorf("Expected both the nested archive and its payload, got %v", kinds(entries))
	}
}

// TestWalkMemberIsReadAsAFile: what is inside an archive is read exactly as
// what is attached to the message. An Office document is laid out as a zip
// and is a document all the same: the walk does not go on inside it.
func TestWalkMemberIsReadAsAFile(t *testing.T) {
	entries := Walk(zipOf(t, "macro.docm", ooxml(t, "[Content_Types].xml", "word/vbaProject.bin")), Limits{})

	if len(entries) != 1 {
		t.Fatalf("Expected the document to be the one thing turned up, got %v", kinds(entries))
	}
	if entries[0].Kind != KindMember {
		t.Errorf("Expected the document to be read as a member, got %v", entries[0].Kind)
	}
	if !slices.Equal(entries[0].At, []string{"macro.docm"}) {
		t.Errorf("Expected the macros to be found in the document itself, got %v", entries[0].At)
	}
	if entries[0].Facts.Macro != MacroVBAProject {
		t.Errorf("Expected the macros of a member to be found, got %+v", entries[0].Facts)
	}
}

// TestWalkDocumentIsNotAnArchive: a document handed to Walk directly is not
// walked either, whatever its bytes start with.
func TestWalkDocumentIsNotAnArchive(t *testing.T) {
	entries := Walk(ooxml(t, "[Content_Types].xml", "word/document.xml"), Limits{})

	if len(entries) != 0 {
		t.Errorf("Expected nothing from a document, got %v", kinds(entries))
	}
}

func TestWalkDepthLimit(t *testing.T) {
	limits := DefaultLimits()

	// A zip nested past the depth the walk goes to.
	payload := []byte("innermost")
	for range limits.MaxDepth + 2 {
		payload = zipOf(t, "level.zip", payload)
	}

	entries := Walk(payload, limits)

	if kinds(entries)[KindTooDeep] == 0 {
		t.Errorf("Expected the walk to stop and say so, got %v", kinds(entries))
	}

	// Nothing below the limit is reported as read.
	for _, entry := range entries {
		if len(entry.At) > limits.MaxDepth {
			t.Errorf("Expected nothing past %d levels, got one at %v", limits.MaxDepth, entry.At)
		}
	}
}

func TestWalkPasswordProtected(t *testing.T) {
	// Craft a zip then set the encryption flag bit in both the local file
	// header and the central directory record
	data := zipOf(t, "secret.txt", []byte("hidden"))
	patched := 0
	for i := 0; i+7 < len(data); i++ {
		// Local file header PK\x03\x04 (flags at offset 6) and central
		// directory header PK\x01\x02 (flags at offset 8)
		if data[i] == 'P' && data[i+1] == 'K' {
			switch {
			case data[i+2] == 0x03 && data[i+3] == 0x04:
				data[i+6] |= 0x1
				patched++
			case data[i+2] == 0x01 && data[i+3] == 0x02 && i+9 < len(data):
				data[i+8] |= 0x1
				patched++
			}
		}
	}
	if patched < 2 {
		t.Fatalf("Failed to patch encryption flags (patched %d headers)", patched)
	}

	entries := Walk(data, Limits{})

	if kinds(entries)[KindEncrypted] != 1 {
		t.Errorf("Expected the archive to be reported locked once, got %v", kinds(entries))
	}
}

func TestWalkGzipBomb(t *testing.T) {
	// Highly compressible payload: 64 MiB of zeros
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	zeros := make([]byte, 1<<20)
	for range 64 {
		writer.Write(zeros)
	}
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{})

	if kinds(entries)[KindBomb] == 0 {
		t.Errorf("Expected the expansion to be reported rather than read, got %v", kinds(entries))
	}
}

// TestWalkCompressibleIsNotABomb: a log compresses hundreds of times over and
// is a log all the same.
func TestWalkCompressibleIsNotABomb(t *testing.T) {
	log := bytes.Repeat([]byte("2026-09-19T10:00:00Z GET /health 200 0.001s\n"), 100_000)

	entries := Walk(zipOf(t, "access.log", log), Limits{})

	if len(entries) != 1 || entries[0].Kind != KindMember {
		t.Errorf("Expected the log to be read as a member, got %v", kinds(entries))
	}
}

func TestWalkEntriesBudgetIsReported(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for i := range 5 {
		entry, err := writer.Create(fmt.Sprintf("%d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		entry.Write([]byte("x"))
	}
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 3, MaxEntryBytes: 1 << 20, BombRatio: 100})

	counted := kinds(entries)
	if counted[KindMember] != 3 || counted[KindBudgetExhausted] != 1 {
		t.Errorf("Expected three members then the walk giving up once, got %v", counted)
	}
}

// TestWalkBudgetIsSharedAcrossMembers holds the budget to being one budget: a
// file cannot buy itself more reading by splitting into members.
func TestWalkBudgetIsSharedAcrossMembers(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(bytes.Repeat([]byte("A"), 4096))
	}
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 4096, MaxEntries: 10, MaxEntryBytes: 4096, BombRatio: 100})

	counted := kinds(entries)
	if counted[KindBudgetExhausted] != 1 {
		t.Errorf("Expected the walk to give up once, got %v", counted)
	}
	if counted[KindMember] > 1 {
		t.Errorf("Expected the budget to be spent on the first member alone, got %v", counted)
	}
}

func TestWalkCleanZip(t *testing.T) {
	entries := Walk(zipOf(t, "notes.txt", []byte("meeting notes")), Limits{})

	if len(entries) != 1 || entries[0].Kind != KindMember {
		t.Fatalf("Expected the one member and nothing else, got %v", entries)
	}
	facts := entries[0].Facts
	if facts.Name.Dangerous || facts.Executable != "" || facts.Macro != MacroNone ||
		len(facts.PDF) != 0 || facts.Script != (Script{}) {
		t.Errorf("Expected nothing to be found in a clean member, got %+v", facts)
	}
}

func TestWalkOfSomethingElse(t *testing.T) {
	if entries := Walk([]byte("just plain text"), Limits{}); entries != nil {
		t.Errorf("Expected nothing to be turned up in a file that is not an archive, got %v", entries)
	}
}

// TestWalkTarInGzip keeps the two formats that travel together readable: a
// .tar.gz names its members, not the tar it is made of.
func TestWalkTarInGzip(t *testing.T) {
	var tarred bytes.Buffer
	writeTar(t, &tarred, "payload.exe", mzStub)

	var gzipped bytes.Buffer
	writer := gzip.NewWriter(&gzipped)
	writer.Name = "bundle.tar"
	writer.Write(tarred.Bytes())
	writer.Close()

	entries := Walk(gzipped.Bytes(), Limits{})

	found := false
	for _, entry := range entries {
		if entry.Kind == KindMember && strings.HasSuffix(strings.Join(entry.At, "/"), "payload.exe") {
			found = true
			if entry.Facts.Executable == "" {
				t.Errorf("Expected the tar member to be read as a program, got %+v", entry.Facts)
			}
		}
	}
	if !found {
		t.Errorf("Expected the member of the tar to be turned up, got %v", entries)
	}
}

// writeTar lays one file out as a tar.
func writeTar(t *testing.T, out *bytes.Buffer, name string, content []byte) {
	t.Helper()

	writer := tar.NewWriter(out)
	if err := writer.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWalkBareTar(t *testing.T) {
	var tarred bytes.Buffer
	writeTar(t, &tarred, "payload.exe", mzStub)

	entries := Walk(tarred.Bytes(), Limits{})

	if len(entries) != 1 || entries[0].Kind != KindMember || entries[0].Name != "payload.exe" {
		t.Fatalf("Expected the one member of the tar to be turned up, got %v", entries)
	}
	if entries[0].Facts.Executable == "" {
		t.Errorf("Expected the member to be read as a program, got %+v", entries[0].Facts)
	}
}

// TestWalkGzipOfAFile: a gzip stream holds one member, named by the stream
// when it names it, and by a placeholder otherwise.
func TestWalkGzipOfAFile(t *testing.T) {
	for name, tc := range map[string]struct {
		streamName, expected string
	}{
		"named":   {"payload.exe", "payload.exe"},
		"unnamed": {"", "(gzip content)"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := gzip.NewWriter(&buf)
			writer.Name = tc.streamName
			writer.Write(mzStub)
			writer.Close()

			entries := Walk(buf.Bytes(), Limits{})

			if len(entries) != 1 || entries[0].Kind != KindMember {
				t.Fatalf("Expected the one member and nothing else, got %v", entries)
			}
			if entries[0].Name != tc.expected || !slices.Equal(entries[0].At, []string{tc.expected}) {
				t.Errorf("Expected the member to be called %q, got %+v", tc.expected, entries[0])
			}
			if entries[0].Facts.Executable == "" {
				t.Errorf("Expected the member to be read as a program, got %+v", entries[0].Facts)
			}
		})
	}
}

// TestWalkTruncatedMemberIsStillRead: a member too large for the budget that
// did not expand out of proportion is read as far as the budget went, and
// said to be.
func TestWalkTruncatedMemberIsStillRead(t *testing.T) {
	// Stored, not deflated: the member takes as much room as it is, so it
	// cannot be mistaken for a bomb.
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: "payload.exe", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	entry.Write(append(slices.Clone(mzStub), bytes.Repeat([]byte("A"), 4096)...))
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 10, MaxEntryBytes: 1024, BombRatio: 100})

	if len(entries) != 2 || entries[0].Kind != KindTruncated || entries[1].Kind != KindMember {
		t.Fatalf("Expected the member to be reported cut short, then read, got %v", entries)
	}
	if entries[0].Name != "payload.exe" || entries[1].Facts.Executable == "" {
		t.Errorf("Expected what was read of the member to be read as a program, got %+v", entries)
	}
}

// TestWalkTarMemberIsNeverABomb: a tar compresses nothing, so a member the
// budget cannot read through is cut short, never a bomb.
func TestWalkTarMemberIsNeverABomb(t *testing.T) {
	var tarred bytes.Buffer
	writeTar(t, &tarred, "zeros.bin", make([]byte, 1<<16))

	entries := Walk(tarred.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 10, MaxEntryBytes: 64, BombRatio: 100})

	counted := kinds(entries)
	if counted[KindBomb] != 0 || counted[KindTruncated] != 1 || counted[KindMember] != 1 {
		t.Errorf("Expected the member to be cut short and read, got %v", counted)
	}
}

// TestWalkCorruptedArchiveAnswersNothing: a file that starts the way an
// archive does and goes on some other way is not read at all.
func TestWalkCorruptedArchiveAnswersNothing(t *testing.T) {
	for name, data := range map[string][]byte{
		"zip":         []byte("PK\x03\x04this is not the rest of a zip"),
		"gzip header": []byte("\x1f\x8b\x07not the compression method gzip knows"),
		"gzip stream": []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03not a deflate stream"),
	} {
		t.Run(name, func(t *testing.T) {
			if entries := Walk(data, Limits{}); entries != nil {
				t.Errorf("Expected nothing to be turned up in a corrupted archive, got %v", entries)
			}
		})
	}
}

// TestWalkDirectoriesCostNothing: only files are members, so a directory
// entry neither shows up nor spends the budget.
func TestWalkDirectoriesCostNothing(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	if _, err := writer.Create("docs/"); err != nil {
		t.Fatal(err)
	}
	entry, err := writer.Create("docs/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte("meeting notes"))
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 1, MaxEntryBytes: 1 << 20, BombRatio: 100})

	if len(entries) != 1 || entries[0].Kind != KindMember || entries[0].Name != "docs/notes.txt" {
		t.Errorf("Expected the one file and nothing else, got %v", entries)
	}
}

// TestWalkTarSkipsWhatIsNotAFile: links and directories carry nothing to
// read.
func TestWalkTarSkipsWhatIsNotAFile(t *testing.T) {
	var tarred bytes.Buffer
	writer := tar.NewWriter(&tarred)
	for _, header := range []*tar.Header{
		{Name: "bin/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "bin/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "bin/run.exe", Mode: 0o644, Size: int64(len(mzStub)), Typeflag: tar.TypeReg},
	} {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			writer.Write(mzStub)
		}
	}
	writer.Close()

	entries := Walk(tarred.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 1, MaxEntryBytes: 1 << 20, BombRatio: 100})

	if len(entries) != 1 || entries[0].Kind != KindMember || entries[0].Name != "bin/run.exe" {
		t.Errorf("Expected the one file and nothing else, got %v", entries)
	}
}

func TestWalkTarEntriesBudgetIsReported(t *testing.T) {
	var tarred bytes.Buffer
	writer := tar.NewWriter(&tarred)
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		writer.Write([]byte("x"))
	}
	writer.Close()

	entries := Walk(tarred.Bytes(), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 1, MaxEntryBytes: 1 << 20, BombRatio: 100})

	counted := kinds(entries)
	if counted[KindMember] != 1 || counted[KindBudgetExhausted] != 1 {
		t.Errorf("Expected one member then the walk giving up once, got %v", counted)
	}
}

// TestWalkTruncatedTarStops: a tar cut off in the middle of a member is read
// up to there.
func TestWalkTruncatedTarStops(t *testing.T) {
	var tarred bytes.Buffer
	writer := tar.NewWriter(&tarred)
	for _, member := range []struct {
		name    string
		content []byte
	}{
		{"first.txt", []byte("complete")},
		{"second.bin", bytes.Repeat([]byte("B"), 4096)},
	} {
		if err := writer.WriteHeader(&tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		writer.Write(member.content)
	}
	writer.Flush()

	// Headers and contents come in 512-byte blocks: the second header is
	// whole, its content is not.
	entries := Walk(tarred.Bytes()[:512+512+512+100], Limits{})

	if len(entries) != 1 || entries[0].Kind != KindMember || entries[0].Name != "first.txt" {
		t.Errorf("Expected the whole member alone to be turned up, got %v", entries)
	}
}

// TestWalkNestedBudgetIsReportedWhereItRanOut: the walk giving up says where
// it was.
func TestWalkNestedBudgetIsReportedWhereItRanOut(t *testing.T) {
	var inner bytes.Buffer
	writer := gzip.NewWriter(&inner)
	writer.Write([]byte("deep"))
	writer.Close()

	entries := Walk(zipOf(t, "inner.gz", inner.Bytes()), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 1, MaxEntryBytes: 1 << 20, BombRatio: 100})

	if len(entries) != 2 || entries[0].Kind != KindNested || entries[1].Kind != KindBudgetExhausted {
		t.Fatalf("Expected the nested archive then the walk giving up, got %v", entries)
	}
	if !slices.Equal(entries[1].At, []string{"inner.gz"}) {
		t.Errorf("Expected the walk to give up inside the nested archive, got %v", entries[1].At)
	}
}

// TestWalkZipBomb: what TestWalkGzipBomb holds a gzip stream to, a zip member
// is held to as well.
func TestWalkZipBomb(t *testing.T) {
	entries := Walk(zipOf(t, "zeros.bin", make([]byte, 1<<20)), Limits{MaxDepth: 3, MaxTotalBytes: 1 << 20, MaxEntries: 10, MaxEntryBytes: 512 << 10, BombRatio: 100})

	if len(entries) != 1 || entries[0].Kind != KindBomb || entries[0].Name != "zeros.bin" {
		t.Errorf("Expected the member to be reported as a bomb and nothing else, got %v", entries)
	}
}

// TestWalkUnreadableMemberIsSkipped: a member compressed a way the reader
// does not know is passed over, and the walk goes on.
func TestWalkUnreadableMemberIsSkipped(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	raw, err := writer.CreateRaw(&zip.FileHeader{Name: "odd.bin", Method: 99, CompressedSize64: 4, UncompressedSize64: 4})
	if err != nil {
		t.Fatal(err)
	}
	raw.Write([]byte("????"))
	entry, err := writer.Create("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte("meeting notes"))
	writer.Close()

	entries := Walk(buf.Bytes(), Limits{})

	if len(entries) != 1 || entries[0].Kind != KindMember || entries[0].Name != "notes.txt" {
		t.Errorf("Expected the readable member alone to be turned up, got %v", entries)
	}
}
