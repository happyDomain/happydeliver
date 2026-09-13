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
	"git.happydns.org/happyDeliver/pkg/reading"
)

// clientCompatCheck reports what an email client will not render as the sender
// saw it: CSS it drops, a font it never fetches, a viewport it was never given,
// a handler it never runs.
//
// It reads the parsed markup itself rather than asking the HTML pass to gather
// one more thing, because nothing else in the analysis needs the vocabulary of
// CSS: the declarations, the at-rules and the stylesheet hrefs are this check's
// business alone.
//
// Who fails what is not its judgement but Can I email's, embedded in
// data/caniemail.json and refreshable; which features are worth reporting, and
// what to do instead, are its own and live in compatFeatures.
var clientCompatCheck = contentCheck{
	Name:     "client_compat",
	Category: reading.CategoryRendering,
	Reports:  []*reading.Defect{defectClientCompat, defectEventHandler},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.HTML == nil {
			return nil, nil
		}

		return clientCompatFindings(harvestMarkup(in.HTML), in.Results.Images), nil
	},
}
