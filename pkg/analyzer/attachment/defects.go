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

import "git.happydns.org/happyDeliver/pkg/reading"

// attachmentDefects is the whole vocabulary. A defect missing from it is
// priced by nobody, and the tests say so.
var attachmentDefects = []*reading.Defect{
	defectScanSkipped,
}

// defectScanSkipped: something was not looked at, and the reader is told so
// rather than left to read silence as a clean bill.
//
// It is what our own limits cost, not what the message did: an attachment
// larger than the analysis will read. Charging for it would bill a sender for
// our ceilings.
var defectScanSkipped = &reading.Defect{
	Name:      "scan_skipped",
	Uncharged: "it reports a limit of this analysis rather than a defect of the message, and a sender cannot answer for our ceilings",
}
