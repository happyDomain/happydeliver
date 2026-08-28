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

// Package svgps validates a document against the SVG Tiny Portable/Secure
// profile, the format BIMI requires for the brand indicator published in the l=
// tag of an Assertion Record.
//
// The profile is a closed grammar, not a list of prohibitions: the schema
// published by the AuthIndicators Working Group (see schema/README.md) permits
// twenty-four elements, and states for each one which attributes it accepts,
// which values those attributes may take, and which children may appear. The
// validator is driven by that grammar, so anything the profile does not
// explicitly permit is reported, including constructs nobody thought to
// blocklist.
//
// The grammar alone is not the whole profile: draft-svg-tiny-ps-abrotman also
// states requirements in prose that no schema can express (the title must not be
// empty, the document must render in at least two colours, and so on). Those are
// implemented alongside, and carry their normative strength: a MUST is reported
// as an error, a SHOULD as a warning.
package svgps

//go:generate go run gen/main.go

import (
	"regexp"
	"slices"
)

// attr is one attribute the profile permits on an element.
type attr struct {
	// required reports whether the element is invalid without it.
	required bool
	// enum lists the only permitted values; nil when the profile accepts
	// arbitrary text.
	enum []string
	// pattern is the regular expression the value must match; empty when
	// the profile imposes none.
	pattern string
}

// element is one element the profile permits.
type element struct {
	attrs map[string]attr
	// firstChild is the element that must appear exactly once, ahead of any
	// other child. Only <svg> has one: <title>.
	firstChild string
	// children are the elements allowed as repeatable children.
	children map[string]bool
	// allowsText reports whether character data may appear as content.
	allowsText bool
}

// Namespaces the validator has to tell apart.
const (
	svgNS   = "http://www.w3.org/2000/svg"
	xmlNS   = "http://www.w3.org/XML/1998/namespace"
	xlinkNS = "http://www.w3.org/1999/xlink"
)

// maxTitleLength is the length beyond which a <title> draws a warning
// (draft-svg-tiny-ps-abrotman section 2.1: "SHOULD be no more 64 characters").
const maxTitleLength = 64

// patterns holds the compiled form of every pattern the profile carries. XSD
// patterns are anchored on the whole value, unlike Go's regexps.
var patterns = map[string]*regexp.Regexp{}

// profileElements is the profile keyed the way the validator reads it: by
// pointer, so that looking an element up while walking a document neither
// copies the entry nor heap-allocates a copy per node.
var profileElements = map[string]*element{}

// requiredAttrs lists, per element, the attributes the profile makes
// mandatory. The profile has only two, both on <svg>, so an element absent
// from this map spares the validator the bookkeeping of tracking which
// attributes a node carried.
var requiredAttrs = map[string][]string{}

func init() {
	for name, e := range profile {
		for _, a := range e.attrs {
			if a.pattern != "" {
				patterns[a.pattern] = regexp.MustCompile(`^(?:` + a.pattern + `)$`)
			}
		}

		profileElements[name] = &e

		var required []string
		for attrName, a := range e.attrs {
			if a.required {
				required = append(required, attrName)
			}
		}
		if len(required) > 0 {
			slices.Sort(required)
			requiredAttrs[name] = required
		}
	}
}

// forbiddenReasons explains, for the elements most often found in a logo that
// was not produced for BIMI, why the profile leaves them out. Without it every
// one of them would be reported as merely "not part of the profile", which is
// true but tells the domain owner nothing about the risk it carries. Keyed by
// lowercase name, so a document using <SCRIPT> is still recognised.
var forbiddenReasons = map[string]string{
	"script":           "scripting is not allowed",
	"handler":          "scripting is not allowed",
	"listener":         "interactivity is not allowed",
	"a":                "linking is not allowed",
	"animate":          "animation is not allowed",
	"animatecolor":     "animation is not allowed",
	"animatemotion":    "animation is not allowed",
	"animatetransform": "animation is not allowed",
	"animation":        "multimedia content is not allowed",
	"set":              "animation is not allowed",
	"discard":          "animation is not allowed",
	"mpath":            "animation is not allowed",
	"audio":            "multimedia content is not allowed",
	"video":            "multimedia content is not allowed",
	"switch":           "conditional processing is not allowed",
	"iframe":           "embedded documents are not allowed",
	"foreignobject":    "embedded documents are not allowed",
	"prefetch":         "external content hints are not allowed",
	"image":            "raster and external images are not allowed",
	"style":            "stylesheets are not allowed, styling must use presentation attributes",
	"filter":           "filters are not part of SVG Tiny",
	"clippath":         "clipping is not part of SVG Tiny",
	"mask":             "masking is not part of SVG Tiny",
	"pattern":          "patterns are not part of SVG Tiny",
	"symbol":           "symbols are not part of SVG Tiny",
	"marker":           "markers are not part of SVG Tiny",
	"tspan":            "text spans are not part of the profile",
}

// discouragedAttrs are the attributes the profile says SHOULD NOT be present,
// while constraining the value they must carry when they are. The schema already
// rejects a wrong value; presence alone is only worth a warning.
var discouragedAttrs = map[string]bool{
	"zoomAndPan":                true,
	"externalResourcesRequired": true,
	"focusable":                 true,
	"snapshotTime":              true,
	"playbackOrder":             true,
	"timelineBegin":             true,
	"editable":                  true,
}

// colorAttrs are the attributes examined to approximate the "at least two
// colours" requirement.
var colorAttrs = map[string]bool{
	"fill":        true,
	"stroke":      true,
	"stop-color":  true,
	"solid-color": true,
	"color":       true,
}

// fontElements are defined by the schema but unreachable from it: no content
// model references them, so a strict reading forbids embedded fonts outright,
// while section 2.4 of the draft explicitly allows them. See toleratedNote.
var fontElements = map[string]bool{
	"font":      true,
	"font-face": true,
	"glyph":     true,
	"hkern":     true,
}

// toleratedNote is appended to the three warnings where the schema and the prose
// of the draft disagree, so the reader knows the official validator is stricter.
const toleratedNote = " (the schema forbids it, so the BIMI Group validator rejects it, but the specification text allows it)"
