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

// Package fileinspect reads a file for what it is, and for what it would do
// when opened.
//
// It knows nothing of email, of reports, or of what any of it costs. What it
// answers are facts about bytes: the format the first of them name, the
// extension the file gives itself against the content behind it, the macros an
// Office document carries, the actions a PDF would take, the members hidden
// inside an archive. Pricing those facts and showing them to a reader is the
// caller's business.
package fileinspect

// Facts is what reading one file offline turned up.
//
// Every field is a fact about the file, never a verdict about it. A zero Facts
// is what a file nobody could read leaves behind, and every field of it reads
// as "nothing found".
type Facts struct {
	// Type is what the file turns out to be.
	Type Type
}

// InspectHeader reads what can be read of a file without reading it through,
// which for now is the type its first bytes are in.
//
// It is for the caller that declines to look at a payload, for its size or for
// its price, and still owes a reader something about it.
func InspectHeader(data []byte) Facts {
	return Facts{Type: inspectType(data)}
}
