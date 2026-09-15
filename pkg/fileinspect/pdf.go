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

package fileinspect

import "bytes"

// PDFFeature is one thing a PDF would do, or carry, when opened.
type PDFFeature string

const (
	// PDFJavaScript is a document carrying embedded JavaScript.
	PDFJavaScript PDFFeature = "javascript"

	// PDFLaunch is a document carrying a /Launch action, which starts an
	// external program.
	PDFLaunch PDFFeature = "launch"

	// PDFAutoAction is a document that acts of its own accord when opened, or
	// when a page is reached: /OpenAction and the additional-actions
	// dictionary alike.
	PDFAutoAction PDFFeature = "auto_action"

	// PDFEmbeddedFile is a document carrying files of its own.
	PDFEmbeddedFile PDFFeature = "embedded_file"
)

// pdfHeaderWindow is how far into a file the %PDF header is looked for. It is
// not always the first bytes: a document may carry a preamble, and readers
// accept it.
const pdfHeaderWindow = 1024

// inspectPDF reads a PDF for what it would do when opened, and answers nothing
// for a file that is not one. The features come back in a fixed order.
func inspectPDF(data []byte) (features []PDFFeature) {
	if !bytes.Contains(data[:min(len(data), pdfHeaderWindow)], []byte("%PDF")) {
		return nil
	}

	if containsPDFToken(data, "/JavaScript") || containsPDFToken(data, "/JS") {
		features = append(features, PDFJavaScript)
	}
	if containsPDFToken(data, "/Launch") {
		features = append(features, PDFLaunch)
	}
	if containsPDFToken(data, "/OpenAction") || containsPDFToken(data, "/AA") {
		features = append(features, PDFAutoAction)
	}
	if containsPDFToken(data, "/EmbeddedFile") {
		features = append(features, PDFEmbeddedFile)
	}

	return features
}

// containsPDFToken searches for a PDF name token ensuring it is not merely a
// prefix of a longer name (e.g. /JS must not match /JSFoo)
func containsPDFToken(data []byte, token string) bool {
	for offset := 0; ; {
		idx := bytes.Index(data[offset:], []byte(token))
		if idx < 0 {
			return false
		}
		after := offset + idx + len(token)
		if after >= len(data) || isPDFDelimiter(data[after]) {
			return true
		}
		offset = after
	}
}

// isPDFDelimiter reports whether the byte ends a PDF name token
func isPDFDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\f', '\x00', '/', '<', '>', '[', ']', '(', ')':
		return true
	}
	return false
}
