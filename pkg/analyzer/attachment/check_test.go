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
	"context"
	"slices"
	"testing"

	"github.com/gabriel-vasile/mimetype"

	"git.happydns.org/happyDeliver/pkg/reading"
)

// observed builds an attachment as Analyze would have, so that a test can hand
// the checks a file without going through a message.
func observed(filename, declaredType string, data []byte) *Attachment {
	attachment := &Attachment{
		Filename:     filename,
		DeclaredType: declaredType,
		Size:         int64(len(data)),
		Location:     filename,
		Data:         data,
	}
	attachment.mime = mimetype.Detect(data)
	attachment.DetectedType = attachment.mime.String()

	return attachment
}

// speakingInputs is one file per thing the registry looks for: together they
// make every check speak, so that what each of them reports can be held to
// what it declares.
//
// They are several because they have to be: a file too large to open silences
// every check reading bytes. What matters is that no check stays silent across
// the whole set, which is how a wrong declaration survives unnoticed.
func speakingInputs(t *testing.T) map[string]*attachmentInput {
	t.Helper()

	oversize := observed("big.bin", "application/octet-stream", bytes.Repeat([]byte("A"), 64))
	oversize.Data = nil

	inputs := map[string]*Attachment{
		"oversize": oversize,
	}

	speaking := make(map[string]*attachmentInput, len(inputs))
	for name, attachment := range inputs {
		maxSize := int64(0)
		if attachment.Data == nil {
			maxSize = 16
		}
		speaking[name] = &attachmentInput{Attachment: attachment, MaxSize: maxSize}
	}

	return speaking
}

// TestEveryDefectIsPricedOnce is the rule the attachment score rests on: a
// defect is charged for by exactly one party, and a defect nobody charges for
// says so out loud.
//
// It reads the vocabulary and runs nothing: the rule is a property of how the
// defects are declared, not of what a given file happens to trigger.
func TestEveryDefectIsPricedOnce(t *testing.T) {
	for _, defect := range attachmentDefects {
		t.Run(defect.Name, func(t *testing.T) {
			switch {
			case defect.Family != nil && defect.Uncharged != "":
				t.Errorf("family %q charges for it, yet it claims to cost nothing (%q): one of the two is wrong",
					defect.Family.Name, defect.Uncharged)

			case defect.Family == nil && defect.Uncharged == "":
				t.Error("nobody charges for it: give it a penalty family, or say in Uncharged why it costs nothing on purpose")
			}
		})
	}
}

// TestAttachmentRegistryIsWellFormed holds every check to naming itself, to
// answering a reading the report groups by, and to declaring what it may
// report out of the vocabulary.
func TestAttachmentRegistryIsWellFormed(t *testing.T) {
	names := make(map[string]bool, len(attachmentChecks))

	for _, check := range attachmentChecks {
		if check.Name == "" {
			t.Error("a check carries no name, so nothing can report which one failed")
			continue
		}
		if names[check.Name] {
			t.Errorf("two checks answer to %q, so a corroboration cannot tell them apart", check.Name)
		}
		names[check.Name] = true

		if !check.Category.Valid() {
			t.Errorf("check %q answers %q, which the schema does not offer a reader", check.Name, check.Category)
		}
		if len(check.Reports) == 0 {
			t.Errorf("check %q declares no defect, so nothing says what its findings cost", check.Name)
		}
		for _, defect := range check.Reports {
			if !slices.Contains(attachmentDefects, defect) {
				t.Errorf("check %q declares %q, which the defect vocabulary does not hold", check.Name, defect.Name)
			}
		}
	}
}

// TestACheckOnlyReportsWhatItDeclares runs every check over the files built to
// make it speak, and holds what it reports to what it said it may report.
func TestACheckOnlyReportsWhatItDeclares(t *testing.T) {
	inputs := speakingInputs(t)

	for _, check := range attachmentChecks {
		t.Run(check.Name, func(t *testing.T) {
			spoke := false

			for name, in := range inputs {
				findings, err := check.Run(context.Background(), in)
				if err != nil {
					t.Fatalf("the check could not answer about %s: %v", name, err)
				}
				if len(findings) > 0 {
					spoke = true
				}

				for _, finding := range findings {
					if finding.Category != "" && !finding.Category.Valid() {
						t.Errorf("%q answers %q, which the schema does not offer a reader", finding.Message, finding.Category)
					}
					if finding.Defect == nil {
						t.Errorf("%q is reported with no defect, so nothing says what it costs", finding.Message)
						continue
					}
					if !slices.Contains(check.Reports, finding.Defect) {
						t.Errorf("%q is reported as %q, which the check does not declare in Reports", finding.Message, finding.Defect.Name)
					}
				}
			}

			// A check that says nothing about any of the files built to make
			// every check speak leaves its declaration unverified, which is
			// how a wrong one survives. speakingInputs is what has to grow.
			if !spoke {
				t.Error("the check reported nothing on any of the files built to make every check speak: add what it looks for to speakingInputs")
			}
		})
	}
}

// TestEveryIssueAnswersAReading holds the whole registry to filing every
// finding under one of the readings the report groups by: the web report shows
// issues by category, so one carrying none would be a finding no reader is
// ever shown.
func TestEveryIssueAnswersAReading(t *testing.T) {
	seen := false

	for name, in := range speakingInputs(t) {
		issues, _ := reading.Run(context.Background(), attachmentChecks, in)
		if len(issues) > 0 {
			seen = true
		}

		for _, issue := range issues {
			if !issue.Category.Valid() {
				t.Errorf("%s: %q is filed under %q, which is not a reading the report groups by", name, issue.Message, issue.Category)
			}
		}
	}

	if !seen {
		t.Fatal("the checks reported nothing on the files built to make every check speak")
	}
}
