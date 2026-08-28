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
