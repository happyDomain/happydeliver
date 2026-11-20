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
	"bytes"
	"slices"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// webpStub is enough of a WebP image for its type to be detected.
var webpStub = append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), bytes.Repeat([]byte{0}, 32)...)

// pngStub is enough of a PNG image for its type to be detected.
var pngStub = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 32)...)

func rspamdWith(symbols map[string]string) *model.RspamdResult {
	result := &model.RspamdResult{Symbols: map[string]model.SpamTestDetail{}}

	for name, params := range symbols {
		detail := model.SpamTestDetail{Name: name}
		if params != "" {
			detail.Params = utils.PtrTo(params)
		}
		result.Symbols[name] = detail
	}

	return result
}

// TestAWebPNamedPNGIsReportedOnItsFile is the report this reading was moved
// for: rspamd names a file by its extension and its real type, and among
// several images of one name, only one is a WebP.
func TestAWebPNamedPNGIsReportedOnItsFile(t *testing.T) {
	results := &Results{Attachments: []Attachment{
		*observed("image.png", "image/webp", webpStub),
		*observed("image.png", "image/png", pngStub),
		*observed("image.png", "image/png", pngStub),
	}}

	analyzer := newOfflineAnalyzer()
	readings := analyzer.Read(results, rspamdWith(map[string]string{"MIME_BAD_ATTACHMENT": "png:image/webp"}))

	if len(readings.Message.Issues) != 0 {
		t.Errorf("Expected nothing left at the message, got %+v", readings.Message.Issues)
	}

	issues := readings.Files[0].Issues
	if len(issues) != 1 || issues[0].Symbol == nil || *issues[0].Symbol != "MIME_BAD_ATTACHMENT" {
		t.Fatalf("Expected MIME_BAD_ATTACHMENT on the WebP, got %+v", issues)
	}
	if issues[0].Type != model.IssueTypeTypeMismatch {
		t.Errorf("Expected it filed as type_mismatch, got %q", issues[0].Type)
	}
	// One image format passing for another hides nothing: it is a few points
	// of spam score, not a disguised payload.
	if issues[0].Severity != model.IssueSeverityLow || issues[0].Category != model.IssueCategoryDeliverability {
		t.Errorf("Expected a low deliverability finding, got %q %q", issues[0].Severity, issues[0].Category)
	}
	if want := "An image is named .png but its content is image/webp."; issues[0].Message != want {
		t.Errorf("Expected %q, got %q", want, issues[0].Message)
	}
	if issues[0].Location == nil || *issues[0].Location != "image.png" {
		t.Errorf("Expected it located at the file, got %v", issues[0].Location)
	}
	for i := 1; i < len(readings.Files); i++ {
		if len(readings.Files[i].Issues) != 0 {
			t.Errorf("file %d: expected nothing, got %+v", i, readings.Files[i].Issues)
		}
	}

	score, _ := analyzer.Score(results, readings)
	if want := 100 - readings.Files[0].Penalty; score != want || readings.Files[0].Penalty == 0 {
		t.Errorf("Expected the worst file to set the score at %d, with something charged, got %d (penalty %d)", want, score, readings.Files[0].Penalty)
	}

	analysis := analyzer.Analysis(results, readings)
	if analysis.Issues != nil {
		t.Errorf("Expected no message-level issues, got %+v", *analysis.Issues)
	}
	if got := (*analysis.Attachments)[0].Issues; got == nil || len(*got) != 1 {
		t.Errorf("Expected the finding shown on the first attachment, got %+v", got)
	}
}

// TestAnOptionNoSingleFileAnswersToStaysWithTheMessage holds the attribution
// to never picking a file among several.
func TestAnOptionNoSingleFileAnswersToStaysWithTheMessage(t *testing.T) {
	attachments := []Attachment{
		*observed("a.png", "image/png", pngStub),
		*observed("b.png", "image/png", pngStub),
	}

	tests := []struct {
		name   string
		option string
		want   int
	}{
		{"by its whole name", "B.PNG", 1},
		{"by extension and type", "png:image/png", -1},
		{"by an extension several share", ".png", -1},
		{"by a name nothing carries", "c.pdf", -1},
		{"by nothing at all", "", -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := attachmentNamedBy(attachments, test.option); got != test.want {
				t.Errorf("attachmentNamedBy(%q) = %d, want %d", test.option, got, test.want)
			}
		})
	}

	if got := attachmentNamedBy([]Attachment{*observed("invoice.pdf.exe", "application/pdf", mzStub), attachments[0]}, ".pdf.exe"); got != 0 {
		t.Errorf("Expected a double extension to name the one file carrying it, got %d", got)
	}
}

// TestWhatTheFilterSaysOfNoFileIsShownAndCharged checks that a symbol naming
// no file is neither lost nor free.
func TestWhatTheFilterSaysOfNoFileIsShownAndCharged(t *testing.T) {
	results := &Results{Attachments: []Attachment{
		*observed("a.pdf", "application/pdf", []byte("%PDF-1.4")),
		*observed("b.pdf", "application/pdf", []byte("%PDF-1.4")),
	}}

	analyzer := newOfflineAnalyzer()
	readings := analyzer.Read(results, rspamdWith(map[string]string{"PDF_ENCRYPTED": ""}))

	if len(readings.Message.Issues) != 1 || readings.Message.Penalty == 0 {
		t.Fatalf("Expected one charged finding at the message, got %+v", readings.Message)
	}

	score, _ := analyzer.Score(results, readings)
	if score != 100-readings.Message.Penalty {
		t.Errorf("Expected the message penalty charged to the files, got %d", score)
	}

	analysis := analyzer.Analysis(results, readings)
	if analysis.Issues == nil || len(*analysis.Issues) != 1 {
		t.Errorf("Expected the finding shown with the attachments, got %+v", analysis.Issues)
	}
}

// TestAFileTheFilterSawAndWeDidNotIsStillGraded covers a filter seeing an
// attachment our parser found none of.
func TestAFileTheFilterSawAndWeDidNotIsStillGraded(t *testing.T) {
	results := &Results{}

	analyzer := newOfflineAnalyzer()
	readings := analyzer.Read(results, rspamdWith(map[string]string{"MIME_BAD_EXTENSION": "scr"}))

	score, grade := analyzer.Score(results, readings)
	if grade == "" || score != 100-readings.Message.Penalty {
		t.Errorf("Expected a grade for what the filter saw, got %d %q", score, grade)
	}
}

// TestTheFilterAgreeingWithUsIsNotedNotCharged checks that a defect one of our
// checks found in a file, and the filter too, is one finding and one charge.
func TestTheFilterAgreeingWithUsIsNotedNotCharged(t *testing.T) {
	results := &Results{Attachments: []Attachment{
		*observed("invoice.pdf.exe", "application/pdf", mzStub),
	}}

	analyzer := newOfflineAnalyzer()
	alone := analyzer.Read(results, nil)
	agreed := analyzer.Read(results, rspamdWith(map[string]string{"MIME_DOUBLE_BAD_EXTENSION": ".pdf.exe"}))

	if agreed.Files[0].Penalty != alone.Files[0].Penalty {
		t.Errorf("Expected the filter's agreement to cost nothing, got %d against %d", agreed.Files[0].Penalty, alone.Files[0].Penalty)
	}
	if len(agreed.Files[0].Issues) != len(alone.Files[0].Issues) {
		t.Fatalf("Expected no extra finding, got %+v", agreed.Files[0].Issues)
	}

	noted := false
	for _, issue := range agreed.Files[0].Issues {
		if issue.Type == model.IssueTypeDoubleExtension && issue.CorroboratedBy != nil && slices.Contains(*issue.CorroboratedBy, "MIME_DOUBLE_BAD_EXTENSION") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("Expected the double extension noted as corroborated, got %+v", agreed.Files[0].Issues)
	}
}

// TestAFileLyingAboutItsTypeKeepsItsGravity checks that only one image format
// passing for another is made light of.
func TestAFileLyingAboutItsTypeKeepsItsGravity(t *testing.T) {
	finding := rspamdFindingCatalog["MIME_BAD_ATTACHMENT"]

	tests := []struct {
		option   string
		severity model.IssueSeverity
		message  string
	}{
		{"png:image/webp", model.IssueSeverityLow, "An image is named .png but its content is image/webp."},
		{"jpg:image/png", model.IssueSeverityLow, "An image is named .jpg but its content is image/png."},
		{"pdf:application/x-dosexec", model.IssueSeverityHigh, "An attachment is named .pdf but its content is application/x-dosexec."},
		{"png:image/svg+xml", model.IssueSeverityHigh, "An attachment is named .png but its content is image/svg+xml."},
		{"svg:image/png", model.IssueSeverityHigh, "An attachment is named .svg but its content is image/png."},
		{"garbled", model.IssueSeverityHigh, finding.Message},
	}

	for _, test := range tests {
		t.Run(test.option, func(t *testing.T) {
			got := finding.Refine(finding, test.option)
			if got.Severity != test.severity {
				t.Errorf("severity %q, want %q", got.Severity, test.severity)
			}
			if got.Message != test.message {
				t.Errorf("message %q, want %q", got.Message, test.message)
			}
			if test.severity == model.IssueSeverityHigh && (got.Category != "" || got.Counterpart != defectTypeMismatch) {
				t.Errorf("Expected a disguised file to stay a security matter our type check agrees with, got %q %v", got.Category, got.Counterpart)
			}
		})
	}
}
