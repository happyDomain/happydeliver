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

package app

import (
	"fmt"
	"io"

	"git.happydns.org/happyDeliver/pkg/analyzer"
)

// RunLicenses prints the notices for the third-party material embedded in the
// happyDeliver binary. Release artifacts and container images ship the binary
// alone, so this command is how their recipients get the attribution the
// embedded data is licensed under.
func RunLicenses(writer io.Writer) error {
	fmt.Fprintln(writer, "happyDeliver is licensed under the GNU Affero General Public License v3.0")
	fmt.Fprintln(writer, "or later (AGPL-3.0-or-later), or under a commercial license obtained from")
	fmt.Fprintln(writer, "happyDomain <contact@happydomain.org>.")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "It embeds the following third-party material, under its own license:")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, analyzer.ThirdPartyNotices())
	return nil
}
