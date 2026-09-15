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

import (
	"bytes"

	"github.com/gabriel-vasile/mimetype"
)

// Script is the script a file is, or the one it carries.
type Script struct {
	// Shebang says the file names the interpreter that is to run it.
	Shebang bool

	// HTMLScript says the file is a page carrying scripts.
	HTMLScript bool

	// Smuggling says those scripts decode a payload the page carries with it,
	// which is how a file gets past a filter that only ever saw HTML.
	Smuggling bool
}

// inspectScript reads a file for the script it is, and a page for the scripts
// it carries.
func inspectScript(name Name, mtype *mimetype.MIME, data []byte) Script {
	script := Script{Shebang: bytes.HasPrefix(data, []byte("#!"))}

	// A shebang is no part of a page.
	if script.Shebang {
		return script
	}

	if !name.HTMLExtension() && !mimeMatches(mtype, "text/html") {
		return script
	}

	lower := bytes.ToLower(data)
	if !bytes.Contains(lower, []byte("<script")) {
		return script
	}

	script.HTMLScript = true
	// HTML smuggling: a scripted page that decodes an embedded payload.
	script.Smuggling = bytes.Contains(lower, []byte("atob")) || bytes.Contains(lower, []byte("blob"))

	return script
}
