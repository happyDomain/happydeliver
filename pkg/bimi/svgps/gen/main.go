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

//go:build ignore

// Command gen renders the SVG Tiny Portable/Secure profile tables from the
// RELAX NG schema. Run it through "go generate ./pkg/bimi/svgps/".
package main

import (
	"log"
	"os"

	"git.happydns.org/happyDeliver/pkg/bimi/svgps/internal/rng"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("svgps/gen: ")

	schema, err := os.ReadFile(rng.SchemaPath)
	if err != nil {
		log.Fatal(err)
	}

	source, err := rng.Generate(schema)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(rng.GeneratedPath, source, 0644); err != nil {
		log.Fatal(err)
	}
}
