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

// The tests of the generated profile live in the external test package: the
// package that reads the schema is imported by the generator, so an in-package
// test would close an import cycle.
package svgps_test

import (
	"bytes"
	"os"
	"testing"

	"git.happydns.org/happyDeliver/pkg/bimi/svgps/internal/rng"
)

// readSchema loads the RELAX NG schema the profile is derived from.
func readSchema(t *testing.T) []byte {
	t.Helper()

	schema, err := os.ReadFile(rng.SchemaPath)
	if err != nil {
		t.Fatalf("reading %s: %s", rng.SchemaPath, err)
	}
	return schema
}

// TestGeneratedProfileMatchesSchema guards against the tables drifting from the
// schema they are derived from, whether because the schema was refreshed without
// regenerating or because the generated file was edited by hand.
func TestGeneratedProfileMatchesSchema(t *testing.T) {
	want, err := rng.Generate(readSchema(t))
	if err != nil {
		t.Fatalf("generating the profile: %s", err)
	}

	got, err := os.ReadFile(rng.GeneratedPath)
	if err != nil {
		t.Fatalf("reading %s: %s", rng.GeneratedPath, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date, run: go generate ./pkg/bimi/svgps/", rng.GeneratedPath)
	}
}

// TestSchemaInvariants checks the properties the validator relies on. Should an
// upstream schema change quietly drop one of them, the failure names what was
// lost instead of leaving the validator silently permissive.
func TestSchemaInvariants(t *testing.T) {
	profile, err := rng.Parse(readSchema(t))
	if err != nil {
		t.Fatalf("parsing the schema: %s", err)
	}

	if len(profile) != 24 {
		t.Errorf("the profile defines %d elements, want 24", len(profile))
	}

	svg, ok := profile["svg"]
	if !ok {
		t.Fatal("the profile defines no <svg> element")
	}

	if svg.FirstChild != "title" {
		t.Errorf("the first child of <svg> is %q, want \"title\"", svg.FirstChild)
	}

	for _, name := range []string{"version", "baseProfile"} {
		if a, ok := svg.Attrs[name]; !ok || !a.Required {
			t.Errorf("<svg> does not require the %q attribute", name)
		}
	}

	// Absent from the schema, and the reason a BIMI logo may not carry a
	// position: it is placed by the mail client, not by the document.
	for _, name := range []string{"x", "y"} {
		if _, ok := svg.Attrs[name]; ok {
			t.Errorf("<svg> accepts the %q attribute, which the profile forbids", name)
		}
	}

	// Elements the validator must reject, checked here rather than only
	// through documents so a schema regression is caught at the source.
	for _, name := range []string{"script", "image", "a", "switch", "style", "animate", "foreignObject", "tspan"} {
		if _, ok := profile[name]; ok {
			t.Errorf("the profile defines <%s>, which it must not", name)
		}
	}

	if _, ok := profile["use"].Attrs["href"]; !ok {
		t.Error("<use> does not accept the href attribute")
	}
}
