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

// Package authresults reads the Authentication-Results header field, the one
// place a receiver writes down what it made of a message's authentication.
//
// It reads the field as RFC 7601 defines it, and nothing beyond: a method is
// named, it reports a result, and it says which properties of the message it
// looked at. What any of that means, which methods are worth reading and what a
// failing one should cost a sender, is a judgement made elsewhere.
//
// Two things the grammar allows are what this package exists for, because
// reading the field with a regular expression gets both wrong. Comments may
// appear between any two elements, so "dkim (Because I like it) / 1 (One yay) =
// (wait for it) fail" is one method reporting one result; and a property value
// may be a quoted string, so an envelope sender whose local part carries a
// space is written whole and must be read whole.
//
// What it is handed is a header field value, from which a receiver's authority
// has already been established or is about to be: this package reports what the
// field says, never whether to believe it.
package authresults

import "strings"

// Header is one Authentication-Results field, read.
type Header struct {
	// AuthservID is the authentication service identifier the receiver
	// signed the field with, empty for a field that names none.
	AuthservID string

	// Version is the version of RFC 7601 the field claims to be written to,
	// empty when it claims none, which the RFC says is to be read as "1".
	Version string

	// None says the field explicitly reports that no authentication was
	// done, which RFC 7601 section 2.2 writes as a lone "none" and which is
	// not the same as a field whose methods could not be read.
	None bool

	// Methods are the methods the field reports, in the order written.
	Methods []Method
}

// Method is one method of the field: what was checked, what came of it, and
// which properties of the message it was checked against.
type Method struct {
	// Name is the method, lowercased: "dkim", "spf", or whatever extension
	// a receiver has invented.
	Name string

	// Version is the version of the method the receiver reports, empty when
	// it reports none.
	Version string

	// Result is the result keyword, lowercased. Which keywords a method may
	// report is the method's business, not this package's, so whatever was
	// written is reported.
	Result string

	// Reason is the free-form reason the receiver gave, empty when none was
	// given. RFC 7601 gives it a clause of its own rather than leaving it to
	// a comment, so it is read as a field rather than as prose.
	Reason string

	// Properties are the properties the method was evaluated against, in the
	// order written.
	Properties []Property

	// Comments are the comments written inside this method, in the order
	// written and without their parentheses. They carry no meaning the RFC
	// defines, but receivers write things in them that are found nowhere
	// else, an iprev check's hostname above all.
	Comments []string

	// Raw is the method as it was written, comments and all, which is what a
	// report quotes when it shows a sender what its receiver said.
	Raw string
}

// Property is one "ptype.property=pvalue" clause.
type Property struct {
	// Type is the ptype, lowercased: "header", "smtp", "policy", "body", or
	// an extension. It is empty for a property written without one, which
	// the grammar does not allow and receivers write anyway.
	Type string

	// Name is the property, lowercased.
	Name string

	// Value is the pvalue as written, with the quotes of a quoted string
	// removed and nothing else taken off: what a value means is the reading
	// of whoever asked for it.
	Value string
}

// Property answers the value of the first property written under any of the
// given names, or "" when the method names none of them.
//
// A name is written as the RFC writes it, "header.d", and matches only that
// ptype and property. A name with no ptype, "d", matches only a property
// written without one, which is how a receiver departs from the grammar.
//
// The first one written wins, whichever name matched it: a method naming a
// property twice has already contradicted itself, and the reading that follows
// is the one a receiver reading its own field would take.
func (m Method) Property(names ...string) string {
	value, _ := m.Lookup(names...)

	return value
}

// Lookup answers the value of the first property written under any of the given
// names, and whether the method wrote one at all.
//
// A property written with an empty value says something that a property nobody
// wrote does not. An SPF check reporting smtp.mailfrom="" was run against the
// envelope sender of a bounce, which is empty by definition: the check knows
// which identity it looked at, and only the presence of the property says so.
func (m Method) Lookup(names ...string) (string, bool) {
	for _, property := range m.Properties {
		for _, name := range names {
			if strings.EqualFold(property.key(), name) {
				return property.Value, true
			}
		}
	}

	return "", false
}

// Comment answers the first comment written inside the method, or "" when it
// carries none.
func (m Method) Comment() string {
	if len(m.Comments) == 0 {
		return ""
	}

	return m.Comments[0]
}

// Find answers the first method of the field written under the given name, and
// whether the field reported it at all.
func (h Header) Find(name string) (Method, bool) {
	for _, method := range h.Methods {
		if method.Name == name {
			return method, true
		}
	}

	return Method{}, false
}

// key writes the property back the way the RFC names it, which is what
// Property matches against.
func (p Property) key() string {
	if p.Type == "" {
		return p.Name
	}

	return p.Type + "." + p.Name
}
