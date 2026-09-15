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

import (
	"flag"
)

// Settings is what the operator decided about the attachment analysis, read
// off the command line, the environment or the configuration file. Each
// scanner declares its own flags the same way, in its own file.
var Settings = Options{
	ScanTimeout: defaultScanTimeout,
	MaxSize:     25 << 20, // 25 MiB, matches clamd's default StreamMaxLength
}

func init() {
	flag.DurationVar(&Settings.ScanTimeout, "scan-timeout", Settings.ScanTimeout, "Timeout for reading one attachment, external scans included")
	flag.Int64Var(&Settings.MaxSize, "max-attachment-size", Settings.MaxSize, "Maximum attachment size in bytes to analyze")
}
