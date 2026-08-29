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

//go:build refresh_shorteners

// This file holds nothing but the directives that re-download the embedded URL
// shortener list.
//
// Refresh the data on demand with:
//
//	go generate -tags refresh_shorteners ./pkg/analyzer/

package analyzer

//go:generate wget -q -O data/url-shorteners.list https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list
//go:generate wget -q -O data/url-shorteners.LICENSE https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/LICENSE
