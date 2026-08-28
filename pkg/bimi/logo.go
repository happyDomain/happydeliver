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
