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
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"git.happydns.org/happyDeliver/pkg/bimi/svgps"
)

// errNotUTF8 stops the walk of a document that is not encoded in UTF-8. Its
// text is never reported: the check names the encoding instead.
var errNotUTF8 = errors.New("not encoded in UTF-8")

// DecodeLogo returns the SVG document carried by content, inflating it when the
// file is an SVGZ. RFC 6170 section 5.2 defines SVGZ as an image/svg+xml octet
// stream compressed with gzip, and BIMI accepts SVG and SVGZ alike for the l=
// tag, so the published file has to be decoded before anything can be said
// about the document it carries.
//
// The file is recognised by its gzip header, not by its URL suffix nor by its
// Content-Type: RFC 6170 requires image/svg+xml to be announced for an SVGZ
// too, so the media type carries no signal.
//
// compressed reports whether content was an SVGZ. The inflated size is capped
// at MaxLogoSize, both because the profile evaluates that limit on the
// uncompressed document and to stop a decompression bomb.
func DecodeLogo(content []byte) (svg []byte, compressed bool, err error) {
	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		// Not a gzip stream: the bytes are the document itself, which is
		// the common case for a logo published at the l= URL. The
		// certificate profile also goes through here, but it requires the
		// mark it embeds to be compressed; compressed says which of the
		// two this was, so that caller can tell.
		return content, false, nil
	}

	// The payload announces itself as gzip, so a read failure means a corrupt
	// stream, not a raw SVG: reporting it beats handing the still-compressed
	// bytes back as if they were the logo.
	inflated, err := io.ReadAll(io.LimitReader(reader, MaxLogoSize+1))
	if err != nil {
		return nil, true, fmt.Errorf("the file announces itself as gzip but the stream is corrupt: %w", err)
	}
	if int64(len(inflated)) > MaxLogoSize {
		return nil, true, fmt.Errorf("the decompressed document exceeds the maximum allowed size of %d bytes", MaxLogoSize)
	}

	return inflated, true, nil
}

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

	return newCheckWithSeverities(name, description, statusFor(errors, warnings), errors, warnings, nil)
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
