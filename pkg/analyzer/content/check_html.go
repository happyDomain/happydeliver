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

package content

import (
	"context"
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/reading"
	"golang.org/x/net/html"
)

// brokenHTMLCheck reports what parsing the HTML went wrong on.
//
// It deducts nothing here: whether the HTML parses is one of the weighted
// criteria of Score, which withholds its ten points outright.
var brokenHTMLCheck = contentCheck{
	Name:     "broken_html",
	Category: reading.CategoryRendering,
	Reports:  []*reading.Defect{defectBrokenHTML},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.Results.HTMLValid || len(in.Results.HTMLErrors) == 0 {
			return nil, nil
		}

		issues := make([]reading.Finding, 0, len(in.Results.HTMLErrors))
		for _, errMsg := range in.Results.HTMLErrors {
			issues = append(issues, reading.Finding{Defect: defectBrokenHTML, Issue: model.Issue{
				Type:     model.IssueTypeBrokenHtml,
				Severity: model.IssueSeverityHigh,
				Message:  errMsg,
				Advice:   utils.PtrTo("Fix HTML structure errors to improve email rendering across clients"),
			}})
		}

		return issues, nil
	},
}

// harmfulHTMLCheck reports markup an email client blocks outright.
//
// Each tag costs a flat twenty points under a cap of forty: whatever the tag,
// the part of the message that depended on it does not render, so weighing
// them by severity would say nothing the flat rate does not.
var harmfulHTMLCheck = contentCheck{
	Name:     "harmful_html",
	Category: reading.CategorySecurity,
	Reports:  []*reading.Defect{defectDangerousHTML},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.HTML == nil {
			return nil, nil
		}

		var findings []reading.Finding
		forEachElement(in.HTML, func(n *html.Node) {
			message := harmfulTagMessage(n)
			if message == "" {
				return
			}

			findings = append(findings, reading.Finding{Defect: defectDangerousHTML, Issue: model.Issue{
				Type:     model.IssueTypeDangerousHtml,
				Severity: model.IssueSeverityCritical,
				Message:  message,
				Advice:   utils.PtrTo("Remove dangerous HTML tags like <script>, <iframe>, <object>, <embed>, <applet>, <form>, and <base> from email content"),
			}})
		})

		return findings, nil
	},
}

// harmfulTagMessage says what an element does that no email client will let it
// do, and says nothing of an element that is not one of them.
//
// The message names the attribute that makes the tag what it is - what the
// iframe loads, where the form posts - because a sender looking for the tag in
// their template finds it by that, not by its name.
func harmfulTagMessage(n *html.Node) string {
	switch n.Data {
	case "script":
		// JavaScript in emails is a security risk and typically blocked
		return "Dangerous <script> tag detected - JavaScript is blocked by most email clients"

	case "iframe":
		// Iframes are security risks and blocked by most email clients
		issue := "Dangerous <iframe> tag detected"
		if src := getAttrOf(n, "src"); src != "" {
			issue += fmt.Sprintf(" with src='%s'", src)
		}
		return issue + " - iframes are blocked by most email clients"

	case "object", "embed", "applet":
		// Legacy embedding tags, security risks
		return fmt.Sprintf("Dangerous <%s> tag detected - legacy embedding tags are security risks and blocked by email clients", n.Data)

	case "form":
		// Forms in emails can be phishing vectors
		issue := "Suspicious <form> tag detected"
		if action := getAttrOf(n, "action"); action != "" {
			issue += fmt.Sprintf(" with action='%s'", action)
		}
		return issue + " - forms can be phishing vectors and are often blocked"

	case "base":
		// Base tag can be used for phishing by redirecting relative URLs
		issue := "Potentially dangerous <base> tag detected"
		if href := getAttrOf(n, "href"); href != "" {
			issue += fmt.Sprintf(" with href='%s'", href)
		}
		return issue + " - can redirect all relative URLs"

	case "meta":
		// A meta refresh takes the reader somewhere they did not ask to go
		if strings.EqualFold(getAttrOf(n, "http-equiv"), "refresh") {
			return fmt.Sprintf("Suspicious <meta http-equiv='refresh'> tag detected with content='%s' - can be used for phishing redirects", getAttrOf(n, "content"))
		}
	}

	return ""
}

// htmlRemarkCheck reports the lesser remarks a reading of the markup gathers
// along the way, an external stylesheet being the one it raises today.
//
// They are filed under broken_html at a low severity for want of a type of
// their own in the schema, and deduct nothing: none of them keeps the message
// from being read.
var htmlRemarkCheck = contentCheck{
	Name:     "html_remark",
	Category: reading.CategoryRendering,
	Reports:  []*reading.Defect{defectHTMLRemark},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.HTML == nil {
			return nil, nil
		}

		var findings []reading.Finding
		forEachElement(in.HTML, func(n *html.Node) {
			if n.Data != "link" {
				return
			}

			// A stylesheet the client must fetch: it may never arrive, and
			// fetching it tells its host the message was opened.
			rel := getAttrOf(n, "rel")
			href := getAttrOf(n, "href")
			if !strings.Contains(strings.ToLower(rel), "stylesheet") || href == "" {
				return
			}
			if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
				return
			}

			findings = append(findings, reading.Finding{
				Defect: defectHTMLRemark,
				Issue: model.Issue{
					Type:     model.IssueTypeBrokenHtml,
					Severity: model.IssueSeverityLow,
					Message:  fmt.Sprintf("External stylesheet link detected: %s - may cause rendering issues or privacy concerns", href),
					Advice:   utils.PtrTo("Use inline CSS instead of external stylesheets for better email compatibility"),
				},
				// rspamd's EXT_CSS names the same stylesheet: keying on its URL
				// lets the two be recognised as one finding.
				Concern: concernForURL("external_css", href),
			})
		})

		return findings, nil
	},
}

// forEachElement calls back on every element of the tree, once.
func forEachElement(n *html.Node, visit func(*html.Node)) {
	if n.Type == html.ElementNode {
		visit(n)
	}

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		forEachElement(child, visit)
	}
}
