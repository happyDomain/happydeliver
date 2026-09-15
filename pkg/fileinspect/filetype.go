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

package fileinspect

import (
	"github.com/gabriel-vasile/mimetype"
)

// Type is what a file turns out to be.
type Type struct {
	// Detected is the media type the content is in, as sniffed from its first
	// bytes.
	Detected string
}

// inspectType reads what the first bytes of a file say it is.
//
// What a file claims to be, in whatever carried it and in its own name, is not
// compared against it here: there is nothing yet to compare it with.
func inspectType(data []byte) Type {
	return Type{Detected: mimetype.Detect(data).String()}
}
