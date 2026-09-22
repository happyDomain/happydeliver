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

	"git.happydns.org/happyDeliver/pkg/bimi"
	"git.happydns.org/happyDeliver/pkg/emaildata/caniemail"
	"git.happydns.org/happyDeliver/pkg/emaildata/disposable"
	"git.happydns.org/happyDeliver/pkg/emaildata/shorteners"
	"git.happydns.org/happyDeliver/pkg/rspamd"
)

// notice is one embedded work's credit and the license text it must be
// distributed with. A release artifact or a container image ships the binary
// alone, so both have to travel inside it, and this command is where they come
// out; nothing else in the tree has a use for the pair.
type notice struct {
	// Attribution is the credit the license asks to be kept with the material.
	Attribution string

	// License is the license text itself, reproduced in full: a link to it is
	// not what the license asks for, and a binary-only recipient has no other
	// way to read it.
	License string
}

// embeddedWorks is every third-party work this binary carries, in the order
// they are printed. A work embedded anywhere in the tree without a line here
// reaches its recipients unnamed, which TestLicensesNameEveryEmbeddedWork
// refuses.
//
// A work listed with no license text is listed all the same: that it comes with
// no terms of its own is worth saying, and is not a reason to leave the
// material unnamed.
var embeddedWorks = []notice{
	{Attribution: shorteners.Attribution, License: shorteners.License},
	{Attribution: disposable.Attribution, License: disposable.License},
	{Attribution: caniemail.Attribution, License: caniemail.License},
	{Attribution: rspamd.Attribution, License: rspamd.License},
	{Attribution: bimi.RootsAttribution},
}

// RunLicenses prints the notices for the third-party material embedded in the
// happyDeliver binary. Release artifacts and container images ship the binary
// alone, so this command is how their recipients get the attribution the
// embedded data is licensed under.
func RunLicenses(writer io.Writer) error {
	fmt.Fprintln(writer, "happyDeliver is licensed under the GNU Affero General Public License v3.0")
	fmt.Fprintln(writer, "or later (AGPL-3.0-or-later), or under a commercial license obtained from")
	fmt.Fprintln(writer, "happyDomain <contact@happydomain.org>.")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "It embeds the following third-party material:")
	fmt.Fprintln(writer)
	for _, notice := range embeddedWorks {
		fmt.Fprintln(writer, notice.Attribution)
		fmt.Fprintln(writer)

		if notice.License != "" {
			fmt.Fprintln(writer, notice.License)
		}
	}

	return nil
}
