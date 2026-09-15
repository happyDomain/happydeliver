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

// attachmentChecks is every check the attachment analysis runs on one file, in
// the order their findings are read.
//
// This is the one place to touch to add a check: write its file, declare an
// attachmentCheck in it, and name it here. Where it sits in the list is where
// its findings sit in the report, so the order is not arbitrary: what
// qualifies the whole reading of a file comes first, what merely informs comes
// last.
var attachmentChecks = []attachmentCheck{
	// A file nobody opened qualifies everything said below it, which only ever
	// saw its name and its size. It is read first for that reason.
	sizeCheck,

	// What the engines made of the whole file comes last: they complement the
	// readings above rather than replacing them, and the reader has met what
	// happyDeliver saw for itself by the time they reach a verdict nobody here
	// can explain. Ours first, so that a sample both recognise is reported
	// under the scanner this instance runs.
	clamavCheck,
	virustotalCheck,
}
