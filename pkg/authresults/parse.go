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

package authresults

import "strings"

// Parse reads an Authentication-Results field value, and says whether it read
// one at all: a value naming no authentication service identifier is not one,
// whatever else it holds.
//
// A method it cannot read is left out, and the methods around it are reported.
// A receiver writing one method nobody can read must not cost the reader the
// verdicts written before and after it, and RFC 7601 section 2.7.6 asks a
// consumer to ignore what it does not understand rather than to give up.
func Parse(value string) (Header, bool) {
	segments := scan(value)

	// The first segment carries the authserv-id and, if the receiver wrote
	// one, the version of the specification it claims to follow.
	head := glue(segments[0].words)
	if len(head) == 0 {
		return Header{}, false
	}

	header := Header{AuthservID: head[0]}
	if len(head) > 1 && isNumber(head[1]) {
		header.Version = head[1]
	}

	for _, segment := range segments[1:] {
		items := glue(segment.words)

		// "none" alone is how the field says that nothing was checked, as
		// opposed to a method whose result could not be read.
		if len(items) == 1 && strings.EqualFold(items[0], "none") {
			header.None = true
			continue
		}

		if method, read := readMethod(items, segment); read {
			header.Methods = append(header.Methods, method)
		}
	}

	return header, true
}

// ParseMethod reads a single method, written as it would be inside a field but
// without the authserv-id that precedes it: "dkim=pass header.d=example.com".
func ParseMethod(value string) (Method, bool) {
	// A value holding no semicolon is read as the one segment it is, so the
	// method is the first of them whether or not anything follows it.
	segments := scan(value)

	return readMethod(glue(segments[0].words), segments[0])
}

// readMethod reads one resinfo: the methodspec that opens it, then the
// reasonspec and the propspecs that may follow.
func readMethod(items []string, written segment) (Method, bool) {
	if len(items) == 0 {
		return Method{}, false
	}

	name, result, spelled := strings.Cut(items[0], "=")
	if !spelled {
		return Method{}, false
	}

	method := Method{
		Result:   strings.ToLower(strings.TrimSpace(result)),
		Comments: written.comments,
		Raw:      written.raw,
	}

	// A method may name the version of itself it was run under, "dkim/1".
	method.Name, method.Version = cutVersion(name)
	if method.Name == "" {
		return Method{}, false
	}

	for _, item := range items[1:] {
		key, value, spelled := strings.Cut(item, "=")
		if !spelled {
			continue
		}

		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		// The reason a receiver gives is a clause of its own, not a
		// property of the message.
		if key == "reason" {
			method.Reason = value
			continue
		}

		ptype, property, written := strings.Cut(key, ".")
		if !written {
			// A property written without its ptype, which the grammar
			// does not allow and receivers write all the same.
			ptype, property = "", ptype
		}

		if property == "" {
			continue
		}

		method.Properties = append(method.Properties, Property{Type: ptype, Name: property, Value: value})
	}

	return method, true
}

// cutVersion separates a method from the version of itself it was run under.
func cutVersion(name string) (string, string) {
	method, version, written := strings.Cut(name, "/")

	method = strings.ToLower(strings.TrimSpace(method))
	if !written {
		return method, ""
	}

	version = strings.TrimSpace(version)
	if !isNumber(version) {
		return method, ""
	}

	return method, version
}

// isNumber says whether a token is the 1*DIGIT a version is written as.
func isNumber(token string) bool {
	if token == "" {
		return false
	}

	return strings.IndexFunc(token, func(r rune) bool { return r < '0' || r > '9' }) < 0
}
