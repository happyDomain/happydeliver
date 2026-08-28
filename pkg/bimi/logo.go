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

package bimi

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// CheckLogoXML performs an xmllint-like well-formedness check on the SVG
// document, reporting the position of the first syntax error.
func CheckLogoXML(content []byte) Check {
	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	decoder.Strict = true

	hasRootElement := false
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			msg := err.Error()
			if syntaxErr, ok := err.(*xml.SyntaxError); ok {
				msg = fmt.Sprintf("line %d: %s", syntaxErr.Line, syntaxErr.Msg)
			}
			return newCheck("logo_xml", "Logo XML well-formedness", StatusFail,
				fmt.Sprintf("The SVG file is not well-formed XML: %s", msg))
		}
		if _, ok := tok.(xml.StartElement); ok {
			hasRootElement = true
		}
	}

	if !hasRootElement {
		return newCheck("logo_xml", "Logo XML well-formedness", StatusFail,
			"The file does not contain any XML element: it does not look like an SVG document")
	}

	return newCheck("logo_xml", "Logo XML well-formedness", StatusPass)
}

// svgTinyPSForbiddenElements lists the SVG elements prohibited by the SVG
// Tiny Portable/Secure profile (draft-svg-tiny-ps-abrotman): scripting,
// interactivity, animation, multimedia, raster images and external content.
var svgTinyPSForbiddenElements = map[string]string{
	"script":           "scripting is not allowed",
	"handler":          "scripting is not allowed",
	"listener":         "interactivity is not allowed",
	"animate":          "animation is not allowed",
	"animatecolor":     "animation is not allowed",
	"animatemotion":    "animation is not allowed",
	"animatetransform": "animation is not allowed",
	"set":              "animation is not allowed",
	"discard":          "animation is not allowed",
	"audio":            "multimedia content is not allowed",
	"video":            "multimedia content is not allowed",
	"iframe":           "embedded documents are not allowed",
	"foreignobject":    "embedded documents are not allowed",
	"prefetch":         "external content hints are not allowed",
	"image":            "raster/external images are not allowed",
}

// CheckLogoSVGTinyPS validates the SVG document against the SVG Tiny
// Portable/Secure profile required by BIMI.
func CheckLogoSVGTinyPS(content []byte) Check {
	var problems []string

	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	decoder.Strict = false

	var (
		rootSeen   bool
		depth      int
		titleFound bool
	)

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Well-formedness is reported by the dedicated XML check
			return newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusSkipped,
				"Skipped: the file could not be parsed as XML")
		}

		switch t := tok.(type) {
		case xml.Directive:
			if strings.HasPrefix(strings.TrimSpace(string(t)), "DOCTYPE") {
				problems = append(problems, "The document contains a DOCTYPE declaration, which is not allowed by SVG P/S")
			}

		case xml.StartElement:
			local := strings.ToLower(t.Name.Local)

			if !rootSeen {
				rootSeen = true
				if local != "svg" {
					problems = append(problems, fmt.Sprintf("Root element is <%s>, expected <svg>", t.Name.Local))
				}
				if t.Name.Space != "http://www.w3.org/2000/svg" {
					problems = append(problems, fmt.Sprintf("Root element namespace is %q, expected \"http://www.w3.org/2000/svg\"", t.Name.Space))
				}

				var version, baseProfile string
				for _, attr := range t.Attr {
					switch strings.ToLower(attr.Name.Local) {
					case "version":
						version = attr.Value
					case "baseprofile":
						baseProfile = attr.Value
					case "x", "y":
						if attr.Name.Space == "" {
							problems = append(problems, fmt.Sprintf("The root <svg> element must not have a %q attribute", attr.Name.Local))
						}
					}
				}
				if version != "1.2" {
					if version == "" {
						problems = append(problems, `The root <svg> element is missing the required version="1.2" attribute`)
					} else {
						problems = append(problems, fmt.Sprintf(`The root <svg> element declares version=%q, expected version="1.2"`, version))
					}
				}
				if baseProfile != "tiny-ps" {
					if baseProfile == "" {
						problems = append(problems, `The root <svg> element is missing the required baseProfile="tiny-ps" attribute`)
					} else {
						problems = append(problems, fmt.Sprintf(`The root <svg> element declares baseProfile=%q, expected baseProfile="tiny-ps"`, baseProfile))
					}
				}
			} else if depth == 1 && local == "title" {
				titleFound = true
			}

			if reason, forbidden := svgTinyPSForbiddenElements[local]; forbidden {
				problems = append(problems, fmt.Sprintf("Element <%s> is not allowed: %s", t.Name.Local, reason))
			}

			for _, attr := range t.Attr {
				attrLocal := strings.ToLower(attr.Name.Local)

				// Event attributes (onclick, onload, ...) enable scripting
				if strings.HasPrefix(attrLocal, "on") && attr.Name.Space == "" {
					problems = append(problems, fmt.Sprintf("Event attribute %q on <%s> is not allowed: scripting/interactivity is prohibited", attr.Name.Local, t.Name.Local))
				}

				// External references are prohibited; only local
				// fragment references (#id) are acceptable.
				if attrLocal == "href" {
					if !strings.HasPrefix(attr.Value, "#") {
						problems = append(problems, fmt.Sprintf("External reference %q on <%s> is not allowed: only references within the document (#id) are permitted", attr.Value, t.Name.Local))
					}
				}

				// External resources pulled in from inline styles
				if attrLocal == "style" && strings.Contains(strings.ToLower(attr.Value), "url(") && strings.Contains(strings.ToLower(attr.Value), "http") {
					problems = append(problems, fmt.Sprintf("Inline style on <%s> references an external URL, which is not allowed", t.Name.Local))
				}
			}

			depth++

		case xml.EndElement:
			depth--
		}
	}

	if rootSeen && !titleFound {
		problems = append(problems, "The <svg> element must contain a <title> child element (it should reflect the company name)")
	}

	if len(problems) > 0 {
		return newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusFail, problems...)
	}

	return newCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", StatusPass)
}
