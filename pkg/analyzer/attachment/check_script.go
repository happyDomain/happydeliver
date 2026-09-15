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
	"git.happydns.org/happyDeliver/pkg/fileinspect"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// scriptCheck reads a file for the script it is, or the one it carries.
var scriptCheck = staticCheck{
	Name:    "attachment_script",
	Reports: []*reading.Defect{defectScriptContent},
	Findings: func(facts fileinspect.Facts, location string) []reading.Finding {
		return scriptFindings(facts.Script, location)
	},
}

// scriptFindings says what a script sent by email, and a page that carries
// one, are worth.
func scriptFindings(script fileinspect.Script, location string) (findings []reading.Finding) {
	if script.Shebang {
		return []reading.Finding{reading.NewFinding(
			defectScriptContent,
			model.IssueTypeScriptContent,
			model.IssueSeverityMedium,
			location,
			"Attachment is an executable script (shebang)",
			"Host the script and link to it, or paste it in the body of the message",
		)}
	}

	if script.HTMLScript {
		severity := model.IssueSeverityMedium
		message := "HTML attachment contains scripts"
		if script.Smuggling {
			severity = model.IssueSeverityHigh
			message = "HTML attachment contains scripts that decode an embedded payload (HTML smuggling pattern)"
		}

		findings = append(findings, reading.NewFinding(
			defectScriptContent,
			model.IssueTypeScriptContent,
			severity,
			location,
			message,
			"Host the page and link to it; an HTML attachment needs no script to be read",
		))
	}

	return findings
}
