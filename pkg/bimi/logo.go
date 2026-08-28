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
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"git.happydns.org/happyDeliver/pkg/bimi/svgps"
)

// errNotUTF8 stops the walk of a document that is not encoded in UTF-8. Its
// text is never reported: the check names the encoding instead.
var errNotUTF8 = errors.New("not encoded in UTF-8")

// CheckLogoXML performs an xmllint-like well-formedness check on the SVG
// document, reporting the position of the first syntax error.
func CheckLogoXML(content []byte) Check {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	decoder.Strict = true

	// encoding/xml reads UTF-8 and nothing else. Left to itself it reports
	// any other encoding in terms of its own internals ("Decoder.
	// CharsetReader is nil"), which tells the domain owner nothing; refusing
	// the encoding here keeps hold of the name to report.
	var declaredCharset string
	decoder.CharsetReader = func(charset string, _ io.Reader) (io.Reader, error) {
		declaredCharset = charset
		return nil, errNotUTF8
	}

	hasRootElement := false
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// The encoding is not a well-formedness problem: the
			// markup was never read.
			if declaredCharset != "" {
				return newCheck("logo_xml", "Logo XML well-formedness", StatusFail,
					fmt.Sprintf("The SVG file declares the character encoding %q, which this check cannot read: the logo must be encoded in UTF-8", declaredCharset))
			}

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

// maxLogoProblems caps how many distinct profile problems a single check
// reports. A logo exported by a general-purpose editor can break dozens of
// distinct rules; past a couple of dozen the list stops informing the reader
// and the remainder is summarised instead.
const maxLogoProblems = 25

// CheckLogoSVGTinyPS validates the SVG document against the SVG Tiny
// Portable/Secure profile required by BIMI. Requirements the profile states as
// MUST make the check fail; those it states as SHOULD are reported as warnings,
// which leave the logo compliant.
func CheckLogoSVGTinyPS(content []byte) Check {
	const (
		name        = "logo_svg_tiny_ps"
		description = "Logo SVG Tiny Portable/Secure profile"
	)

	problems, err := svgps.Validate(content)
	if err != nil {
		// Well-formedness is reported by the dedicated XML check, whose
		// diagnostic is more precise.
		return newCheck(name, description, StatusSkipped,
			"Skipped: the file could not be parsed as XML")
	}

	var errors, warnings []string
	droppedErrors := 0

	for i, problem := range problems {
		if i >= maxLogoProblems {
			if problem.Severity == svgps.SeverityError {
				droppedErrors++
			}
			continue
		}
		if problem.Severity == svgps.SeverityWarning {
			warnings = append(warnings, formatLogoProblem(problem))
		} else {
			errors = append(errors, formatLogoProblem(problem))
		}
	}

	if dropped := len(problems) - maxLogoProblems; dropped > 0 {
		summary := fmt.Sprintf("%d further problems are not listed", dropped)
		if droppedErrors > 0 {
			errors = append(errors, summary)
		} else {
			warnings = append(warnings, summary)
		}
	}

	status := StatusPass
	switch {
	case len(errors) > 0:
		status = StatusFail
	case len(warnings) > 0:
		status = StatusWarning
	}

	return newCheckWithSeverities(name, description, status, errors, warnings)
}

// formatLogoProblem renders a profile problem, locating it in the file and
// folding the repeats of a rule broken throughout the document into one line.
func formatLogoProblem(problem svgps.Problem) string {
	text := problem.Text
	if problem.Line > 0 {
		text = fmt.Sprintf("line %d: %s", problem.Line, text)
	}
	if problem.Count > 1 {
		text = fmt.Sprintf("%s (%d occurrences)", text, problem.Count)
	}
	return text
}
