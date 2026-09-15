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
// the order their findings are read: what qualifies the whole reading of a
// file comes first, what merely informs comes last. To add a check, write its
// file and name it here, or in staticChecks when it reads the facts of a file
// alone; the scanner checks are derived from knownScanners.
var attachmentChecks = registry()

func registry() (checks []attachmentCheck) {
	// A file nobody opened qualifies everything said below it.
	checks = append(checks, sizeCheck)

	// What the file says it is, and what its content turns out to be.
	for _, c := range staticChecks {
		checks = append(checks, c.check())
	}

	// What it hides inside itself.
	checks = append(checks, archiveCheck)

	// What the engines made of it, in the order of knownScanners, so that a
	// sample two of them recognise is reported under the one listed first.
	return append(checks, scannerChecks()...)
}
