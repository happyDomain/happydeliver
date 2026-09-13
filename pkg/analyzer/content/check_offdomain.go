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
	"slices"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/reading"
)

// offDomainLinksMinLinks is how many links a message must carry before the
// destinations it does not lead to say anything. One or two links away from
// the sender's domain are what an ordinary message is made of: a social
// network, a legal notice, a partner. Below this the finding would report the
// shape of email itself.
const offDomainLinksMinLinks = 3

// offDomainLinksNamed is how many destination domains the finding spells out
// before counting the rest. The point is to let the sender recognise where
// their message leads, which the first few already do; a list of thirty
// domains is read by nobody.
const offDomainLinksNamed = 5

// offDomainLinksCheck reports a message not one of whose links leads back to
// the domain it is sent from.
//
// It reads the destinations at the end of their redirections, so a mailing
// whose links go through a click tracker is judged on where the recipient
// actually lands. What the tracker forwards to is what the sender publishes;
// the tracker itself is an intermediary, and reading it as the destination
// would report every professional sender and nobody else.
var offDomainLinksCheck = contentCheck{
	Name:     "off_domain_links",
	Category: reading.CategoryDeliverability,
	Reports:  []*reading.Defect{defectOffDomainLinks},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if len(in.Results.Links) < offDomainLinksMinLinks {
			return nil, nil
		}

		sender := senderDomains(in.Message)
		if len(sender) == 0 {
			return nil, nil
		}

		destinations := in.Results.destinationDomains()
		if len(destinations) == 0 {
			return nil, nil
		}

		if slices.ContainsFunc(destinations, func(domain string) bool {
			return slices.Contains(sender, domain)
		}) {
			return nil, nil
		}

		// What is stated is what was read: the destinations found, and that
		// none of them is the sender's. A body that stopped short has been
		// reported as such above, which qualifies this as it qualifies
		// everything read off the parts that arrived.
		return []reading.Finding{reading.NewFinding(
			defectOffDomainLinks,
			model.ContentIssueTypeSenderDomainMismatch,
			model.ContentIssueSeverityLow,
			"",
			fmt.Sprintf(
				"None of the %d destinations this message links to belongs to %s: %s",
				len(destinations), sender[0], namedDomains(destinations),
			),
			"Send at least the main call to action through your own domain, or through a subdomain delegated to your provider; filters score a message whose destinations all lie elsewhere as unrelated to the domain it is sent from",
		)}, nil
	},
}

// namedDomains writes a list of domains out for a reader, naming the first
// offDomainLinksNamed and counting whatever follows, the way listClients does
// for the clients of a compatibility finding.
func namedDomains(domains []string) string {
	if len(domains) <= offDomainLinksNamed {
		return joinWithAnd(domains)
	}

	rest := len(domains) - offDomainLinksNamed
	others := "others"
	if rest == 1 {
		others = "other"
	}

	// Commas up to the count, and one "and" before it: the named domains are
	// not the end of the list, so they must not read as if they were.
	return strings.Join(domains[:offDomainLinksNamed], ", ") + fmt.Sprintf(" and %d %s", rest, others)
}
