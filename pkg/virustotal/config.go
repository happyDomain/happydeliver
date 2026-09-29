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

package virustotal

import (
	"flag"
)

// APIKey is the VirusTotal API key, shared by every consumer of this package:
// attachment hash lookups and domain blacklist checking alike, since both
// spend the quota of the same VirusTotal account. Empty disables VirusTotal
// wherever it is read.
var APIKey string

func init() {
	flag.StringVar(&APIKey, "virustotal-api-key", APIKey, "VirusTotal API key (attachment hash lookups and domain blacklist checks; empty = disabled)")
}
