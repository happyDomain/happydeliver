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

// lowContrastCheck reports text a reader cannot make out against what is behind
// it, measured against the thresholds WCAG 2 level AA fixes.
//
// It reads only what the message declares inline, on the element and on its
// ancestors. That is a deliberate bound, not an unfinished one: pairing a colour
// from a <style> block with the text it lands on takes selector matching and
// specificity, and a wrong pairing would accuse a sender of a contrast they
// never wrote. Where a colour belongs to the client rather than to the message,
// this says nothing, because an absent contrast is not a passing one.
//
// What it does reach is where the colours of an email mostly live, and the
// button in particular: the element whose contrast matters most is also the one
// that carries both its colours in one attribute.
var lowContrastCheck = contentCheck{
	Name:     "low_contrast",
	Category: reading.CategoryAccessibility,
	Reports:  []*reading.Defect{defectLowContrast},
	Run: func(_ context.Context, in *contentInput) ([]reading.Finding, error) {
		if in.HTML == nil {
			return nil, nil
		}

		return lowContrastFindings(in.HTML), nil
	},
}
