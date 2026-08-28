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

// Package rng reduces the SVG Tiny Portable/Secure RELAX NG schema to the small
// model the validator needs, and renders that model as Go source.
//
// It is not a RELAX NG engine: it recognises only the handful of constructs the
// published schema actually uses, and returns an error on anything else. That
// strictness is the point. The schema is the normative definition of the
// profile, so an upstream change the reducer cannot represent must stop the
// build rather than silently drop a rule.
//
// The package is under internal/ and imported only by the code generator and by
// the test that guards against the generated file drifting from the schema, so
// it never reaches a production binary.
package rng

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"go/format"
	"sort"
	"strings"
)

// Namespaces appearing in the schema.
const (
	svgNS = "http://www.w3.org/2000/svg"
	xmlNS = "http://www.w3.org/XML/1998/namespace"
)

// Paths of the schema and of the file generated from it, relative to the svgps
// package directory: both the generator and the test guarding against drift run
// from there.
const (
	SchemaPath    = "schema/SVG_PS-latest.rng"
	GeneratedPath = "profile_gen.go"
)

// Attr is one attribute permitted on an element.
type Attr struct {
	// Required reports whether the schema mandates the attribute, i.e. it
	// is not wrapped in <optional>. Only version and baseProfile are.
	Required bool
	// Enum lists the permitted values, in schema order, when the value is a
	// closed enumeration. It is nil when the schema accepts arbitrary text,
	// which is the case as soon as a <data> appears among the alternatives.
	Enum []string
	// Pattern is the XSD regular expression the value must match, or "" when
	// the schema imposes none.
	Pattern string
}

// Element is one element permitted by the profile.
type Element struct {
	// Attrs maps a qualified attribute name to its constraints. The key is
	// the local name, prefixed with "xml:" for the XML namespace, because
	// the schema defines both id and xml:id.
	Attrs map[string]Attr
	// FirstChild is the element that must appear once, before any other
	// child. Only <svg> has one: <title>.
	FirstChild string
	// Children lists the elements allowed as (repeatable) children, sorted.
	Children []string
	// AllowsText reports whether character data is allowed as content.
	AllowsText bool
}

// node is a RELAX NG XML node. The schema uses a small enough subset that one
// recursive struct decodes all of it.
type node struct {
	XMLName  xml.Name
	Name     string `xml:"name,attr"`
	NS       string `xml:"ns,attr"`
	Type     string `xml:"type,attr"`
	Chardata string `xml:",chardata"`
	Nodes    []node `xml:",any"`
}

// grammar is the root <grammar> of the schema.
type grammar struct {
	XMLName xml.Name `xml:"grammar"`
	Defines []node   `xml:"define"`
}

// Parse reduces the RELAX NG schema to the validator's model, keyed by element
// name.
func Parse(schema []byte) (map[string]Element, error) {
	var g grammar
	if err := xml.Unmarshal(schema, &g); err != nil {
		return nil, fmt.Errorf("decoding the schema: %w", err)
	}
	if len(g.Defines) == 0 {
		return nil, fmt.Errorf("the schema defines no element")
	}

	// A <ref> names a define, not an element, and the two differ (the
	// define "svgTitle" holds the element "title"). Resolve the mapping
	// first so content models can be expressed in element names.
	elementOf := make(map[string]string, len(g.Defines))
	elements := make([]node, len(g.Defines))
	for i, def := range g.Defines {
		elem, err := definedElement(def)
		if err != nil {
			return nil, err
		}
		name, err := elementName(elem)
		if err != nil {
			return nil, err
		}
		elementOf[def.Name] = name
		elements[i] = elem
	}

	profile := make(map[string]Element, len(g.Defines))
	for i, def := range g.Defines {
		elem := elements[i]
		name := elementOf[def.Name]

		e := Element{Attrs: map[string]Attr{}}
		// Skip the leading <name>, which carries the element's own name.
		if err := (&contentWalker{elementOf: elementOf, elem: &e}).walk(elem.Nodes[1:], false); err != nil {
			return nil, fmt.Errorf("element <%s>: %w", name, err)
		}
		sort.Strings(e.Children)

		if _, dup := profile[name]; dup {
			return nil, fmt.Errorf("element <%s> is defined twice", name)
		}
		profile[name] = e
	}

	return profile, nil
}

// definedElement returns the single <element> a <define> wraps.
func definedElement(def node) (node, error) {
	var found *node
	for i, n := range def.Nodes {
		if n.XMLName.Local != "element" {
			return node{}, fmt.Errorf("define %q: unexpected <%s>, expected <element>", def.Name, n.XMLName.Local)
		}
		if found != nil {
			return node{}, fmt.Errorf("define %q: holds more than one <element>", def.Name)
		}
		found = &def.Nodes[i]
	}
	if found == nil {
		return node{}, fmt.Errorf("define %q: holds no <element>", def.Name)
	}
	return *found, nil
}

// elementName returns the name an <element> declares through its leading
// <name> child, checking it belongs to the SVG namespace.
func elementName(elem node) (string, error) {
	if len(elem.Nodes) == 0 || elem.Nodes[0].XMLName.Local != "name" {
		return "", fmt.Errorf("an <element> does not start with a <name>")
	}
	name := elem.Nodes[0]
	if name.NS != svgNS {
		return "", fmt.Errorf("element %q is in namespace %q, expected the SVG namespace", name.Chardata, name.NS)
	}
	return strings.TrimSpace(name.Chardata), nil
}

// contentWalker accumulates an element's content model.
type contentWalker struct {
	elementOf map[string]string
	elem      *Element
	// sawRepeat reports whether a repetition has been entered, which tells a
	// bare <ref> (the mandatory first child) apart from a repeatable one.
	sawRepeat bool
}

// walk reduces the content nodes of an element. optional reports whether the
// nodes sit under an <optional>, which is what makes an attribute optional.
func (w *contentWalker) walk(nodes []node, optional bool) error {
	for _, n := range nodes {
		switch n.XMLName.Local {
		case "optional":
			if err := w.walk(n.Nodes, true); err != nil {
				return err
			}

		case "group", "interleave", "choice":
			// Structural grouping: the schema only ever uses these to
			// assemble attribute groups or alternatives of children,
			// so flattening them loses nothing the validator needs.
			if err := w.walk(n.Nodes, optional); err != nil {
				return err
			}

		case "zeroOrMore", "oneOrMore":
			saved := w.sawRepeat
			w.sawRepeat = true
			err := w.walk(n.Nodes, optional)
			w.sawRepeat = saved
			if err != nil {
				return err
			}

		case "attribute":
			name, a, err := parseAttribute(n)
			if err != nil {
				return err
			}
			a.Required = !optional
			if _, dup := w.elem.Attrs[name]; dup {
				return fmt.Errorf("attribute %q is declared twice", name)
			}
			w.elem.Attrs[name] = a

		case "ref":
			child, known := w.elementOf[n.Name]
			if !known {
				return fmt.Errorf("reference to the undefined pattern %q", n.Name)
			}
			// A reference outside any repetition is the mandatory
			// first child; <svg> uses this for <title>.
			if w.sawRepeat {
				w.elem.Children = append(w.elem.Children, child)
			} else if w.elem.FirstChild != "" {
				return fmt.Errorf("more than one mandatory child (%q and %q)", w.elem.FirstChild, child)
			} else {
				w.elem.FirstChild = child
			}

		case "text":
			w.elem.AllowsText = true

		case "empty":
			// Nothing to record.

		default:
			return fmt.Errorf("unsupported RELAX NG construct <%s>", n.XMLName.Local)
		}
	}
	return nil
}

// parseAttribute reduces an <attribute> to its qualified name and constraints.
func parseAttribute(n node) (string, Attr, error) {
	if len(n.Nodes) == 0 || n.Nodes[0].XMLName.Local != "name" {
		return "", Attr{}, fmt.Errorf("an <attribute> does not start with a <name>")
	}

	name := strings.TrimSpace(n.Nodes[0].Chardata)
	switch n.Nodes[0].NS {
	case "":
	case xmlNS:
		name = "xml:" + name
	default:
		return "", Attr{}, fmt.Errorf("attribute %q is in the unsupported namespace %q", name, n.Nodes[0].NS)
	}

	a, err := parseValue(n.Nodes[1:])
	if err != nil {
		return "", Attr{}, fmt.Errorf("attribute %q: %w", name, err)
	}
	return name, a, nil
}

// parseValue reduces the value model of an attribute. An enumeration is closed
// only when every alternative is a literal <value>: as soon as a <data> appears
// the schema accepts arbitrary text and the validator must not constrain it.
func parseValue(nodes []node) (Attr, error) {
	var a Attr
	open := false

	var visit func(ns []node) error
	visit = func(ns []node) error {
		for _, n := range ns {
			switch n.XMLName.Local {
			case "choice":
				if err := visit(n.Nodes); err != nil {
					return err
				}
			case "optional", "empty":
				// The value itself may be omitted (xml:lang is
				// declared as "xsd:language?"), so nothing can be
				// required of it.
				open = true
				if err := visit(n.Nodes); err != nil {
					return err
				}
			case "value":
				a.Enum = append(a.Enum, strings.TrimSpace(n.Chardata))
			case "data":
				open = true
				for _, p := range n.Nodes {
					if p.XMLName.Local != "param" {
						return fmt.Errorf("unsupported <data> child <%s>", p.XMLName.Local)
					}
					if p.Name != "pattern" {
						return fmt.Errorf("unsupported <data> parameter %q", p.Name)
					}
					if a.Pattern != "" {
						return fmt.Errorf("more than one pattern")
					}
					a.Pattern = strings.TrimSpace(p.Chardata)
				}
			case "text":
				open = true
			default:
				return fmt.Errorf("unsupported value construct <%s>", n.XMLName.Local)
			}
		}
		return nil
	}

	if err := visit(nodes); err != nil {
		return Attr{}, err
	}
	if open {
		a.Enum = nil
	}
	return a, nil
}

// Generate renders the profile tables as the Go source of profile_gen.go.
func Generate(schema []byte) ([]byte, error) {
	profile, err := Parse(schema)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(profile))
	for name := range profile {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("\nvar profile = map[string]element{\n")
	for _, name := range names {
		e := profile[name]
		fmt.Fprintf(&buf, "\t%q: {\n", name)

		if len(e.Attrs) > 0 {
			attrNames := make([]string, 0, len(e.Attrs))
			for attrName := range e.Attrs {
				attrNames = append(attrNames, attrName)
			}
			sort.Strings(attrNames)

			buf.WriteString("\t\tattrs: map[string]attr{\n")
			for _, attrName := range attrNames {
				a := e.Attrs[attrName]
				fmt.Fprintf(&buf, "\t\t\t%q: {", attrName)
				var fields []string
				if a.Required {
					fields = append(fields, "required: true")
				}
				if len(a.Enum) > 0 {
					quoted := make([]string, len(a.Enum))
					for i, v := range a.Enum {
						quoted[i] = fmt.Sprintf("%q", v)
					}
					fields = append(fields, "enum: []string{"+strings.Join(quoted, ", ")+"}")
				}
				if a.Pattern != "" {
					fields = append(fields, fmt.Sprintf("pattern: %q", a.Pattern))
				}
				buf.WriteString(strings.Join(fields, ", "))
				buf.WriteString("},\n")
			}
			buf.WriteString("\t\t},\n")
		}

		if e.FirstChild != "" {
			fmt.Fprintf(&buf, "\t\tfirstChild: %q,\n", e.FirstChild)
		}
		if len(e.Children) > 0 {
			quoted := make([]string, len(e.Children))
			for i, c := range e.Children {
				quoted[i] = fmt.Sprintf("%q: true", c)
			}
			fmt.Fprintf(&buf, "\t\tchildren: map[string]bool{%s},\n", strings.Join(quoted, ", "))
		}
		if e.AllowsText {
			buf.WriteString("\t\tallowsText: true,\n")
		}

		buf.WriteString("\t},\n")
	}
	buf.WriteString("}\n")

	src, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting the generated source: %w", err)
	}
	return src, nil
}

const generatedHeader = `// Code generated from schema/SVG_PS-latest.rng by gen/main.go. DO NOT EDIT.

package svgps
`
