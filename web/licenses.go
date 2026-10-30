// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package web

import (
	_ "embed"
)

// The front-end bundle embedded from build/ carries the npm dependencies Vite
// compiled into it. Neither node_modules nor build/ is tracked, so the license
// texts those dependencies ship with are copied under licenses/ and embedded
// from there.

// BootstrapLicense is the MIT license Bootstrap ships with, its copyright
// notice included.
//
//go:embed licenses/bootstrap.LICENSE
var BootstrapLicense string

// BootstrapAttribution names Bootstrap, whose Sass and JavaScript are compiled
// into the bundle.
const BootstrapAttribution = `Bootstrap
---------

Copyright (c) 2011-2025 The Bootstrap Authors
Source:  https://github.com/twbs/bootstrap
License: MIT
Changes: the Sass sources are compiled with happyDeliver's own variable
         overrides; the JavaScript is bundled unmodified.`

// BootstrapIconsLicense is the MIT license Bootstrap Icons ships with, its
// copyright notice included.
//
//go:embed licenses/bootstrap-icons.LICENSE
var BootstrapIconsLicense string

// BootstrapIconsAttribution names Bootstrap Icons, whose icon font and
// stylesheet are embedded in the bundle.
const BootstrapIconsAttribution = `Bootstrap Icons
---------------

Copyright (c) 2019-2024 The Bootstrap Authors
Source:  https://github.com/twbs/icons
License: MIT
Changes: none, the icon font and its stylesheet are embedded as published.`

// PopperLicense is the MIT license Popper ships with, its copyright notice
// included.
//
//go:embed licenses/popper.LICENSE
var PopperLicense string

// PopperAttribution names Popper, which Bootstrap's tooltips pull into the
// bundle.
const PopperAttribution = `Popper
------

Copyright (c) 2019 Federico Zivolo
Source:  https://github.com/floating-ui/floating-ui, package @popperjs/core
License: MIT
Changes: none, it is bundled unmodified as a dependency of Bootstrap.`
