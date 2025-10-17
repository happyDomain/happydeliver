// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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

package config

import (
	"fmt"
	"os"
	"strings"
)

// parseEnvironmentVariables analyzes all the environment variables to find
// each one starting by HAPPYDELIVER_
func parseEnvironmentVariables(o *Config) (err error) {
	for _, line := range os.Environ() {
		if strings.HasPrefix(line, "HAPPYDELIVER_") || strings.HasPrefix(line, "HAPPYDOMAIN_") {
			err := parseLine(o, line)
			if err != nil {
				return fmt.Errorf("error in environment (%q): %w", line, err)
			}
		}
	}
	return
}
