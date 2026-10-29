// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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
	"git.happydns.org/happyDeliver/internal/model"
)

// checkScore is the score of one check, out of 100, along with the issues
// that cost it points. Each issue is charged what it actually took from the
// score when it was found, so a cap another issue already reached costs
// nothing more, and the penalties always add up to what the check lost.
type checkScore struct {
	score  int
	issues []model.Issue
}

// cap lowers the score to max, charging the difference to the issue.
func (c *checkScore) cap(max int, issue model.Issue) {
	penalty := 0
	if c.score > max {
		penalty = c.score - max
		c.score = max
	}
	issue.Penalty = &penalty
	c.issues = append(c.issues, issue)
}

// note records an issue that costs the check nothing.
func (c *checkScore) note(issue model.Issue) {
	penalty := 0
	issue.Penalty = &penalty
	c.issues = append(c.issues, issue)
}

// weighIssues turns penalties counted out of a check's own 100 points into
// points of the section score, of which the check makes weight out of total.
// The list, empty when the check found nothing, is always there: it is what
// tells a reader the check was scored.
func weighIssues(issues []model.Issue, weight, total int) *[]model.Issue {
	weighed := make([]model.Issue, len(issues))
	for i, issue := range issues {
		penalty := (*issue.Penalty*weight + total/2) / total
		issue.Penalty = &penalty
		weighed[i] = issue
	}
	return &weighed
}

// newIssue builds an issue the analyser found reading the message or the
// records of its sender, filed under deliverability.
func newIssue(issueType model.IssueType, severity model.IssueSeverity, location, message, advice string) model.Issue {
	issue := model.Issue{
		Type:     issueType,
		Category: model.IssueCategoryDeliverability,
		Severity: severity,
		Message:  message,
	}
	if location != "" {
		issue.Location = &location
	}
	if advice != "" {
		issue.Advice = &advice
	}
	return issue
}
