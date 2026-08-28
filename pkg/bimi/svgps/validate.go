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

package svgps

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Severity is the normative strength of a Problem: a requirement the profile
// states as MUST is reported as an error, one it states as SHOULD as a warning.
type Severity int

const (
	// SeverityError marks a violation that makes the logo non-compliant.
	SeverityError Severity = iota
	// SeverityWarning marks a recommendation the document does not follow,
	// which leaves it compliant.
	SeverityWarning
)

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// Problem is one violation of the SVG Tiny Portable/Secure profile.
type Problem struct {
	// Text explains the violation.
	Text string
	// Severity is the normative strength of the requirement violated.
	Severity Severity
	// Line is where the violation was first seen, or 0 when unknown.
	Line int
	// Count is how many times the same violation occurs. A logo exported by
	// a general-purpose editor breaks the same rule on nearly every node, so
	// identical problems are reported once with a count rather than flooding
	// the report.
	Count int
}

// Validate reports how content departs from the SVG Tiny Portable/Secure
// profile. An empty result means the document is compliant.
//
// It returns an error only when content cannot be parsed as XML at all; the
// caller is expected to have a dedicated well-formedness check, whose diagnostic
// is more precise than anything this function would add.
func Validate(content []byte) ([]Problem, error) {
	v := &validator{
		seen: map[string]int{},
		// The decoder is lenient because well-formedness is somebody
		// else's check: the aim here is to walk as much of the document
		// as possible and report profile violations, not to re-diagnose
		// broken markup.
		dec:    xml.NewDecoder(bytes.NewReader(content)),
		colors: map[string]bool{},
	}
	v.dec.Strict = false

	for {
		tok, err := v.dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the document could not be parsed as XML: %w", err)
		}

		switch t := tok.(type) {
		case xml.ProcInst:
			v.procInst(t)
		case xml.Directive:
			v.directive(t)
		case xml.CharData:
			v.charData(t)
		case xml.StartElement:
			v.startElement(t)
		case xml.EndElement:
			v.endElement()
		}
	}

	v.finish()
	return v.problems, nil
}

// validator carries the state of one document walk.
type validator struct {
	dec      *xml.Decoder
	problems []Problem
	// seen indexes problems by text, so a repeated violation increments a
	// count instead of appending.
	seen map[string]int

	stack []frame
	// rootSeen reports whether the root element has been reached, and
	// rootIsSVG whether it was an <svg> the walk could carry on with.
	rootSeen  bool
	rootIsSVG bool
	// unnamespaced records that the document declares no SVG namespace. The
	// root already said so; repeating it for every descendant would drown
	// the report.
	unnamespaced bool
	// metadataWarned keeps the tolerated <metadata> content warning to a
	// single occurrence, however many foreign nodes the subtree holds.
	metadataWarned bool
	// colors approximates the set of colours the document paints with.
	colors map[string]bool
}

// frame is one open element.
type frame struct {
	name string
	// elem is the profile entry, nil when the element is not in the profile.
	elem *element
	// skip suppresses validation of the subtree, because the element itself
	// was already rejected or because it is tolerated foreign content.
	skip bool
	// metadata marks the <metadata> element, whose content the profile
	// restricts to text but which real logos fill with RDF.
	metadata bool
	// children counts the element children seen so far.
	children int
	// firstIndex is the position of the mandatory first child, -1 until it
	// appears, and firstCount how many times it appeared.
	firstIndex int
	firstCount int
	// text accumulates character data, to check <title> and <desc> content.
	// A []byte rather than a strings.Builder: frames live in a slice, and
	// growing that slice copies them, which a used Builder refuses.
	text []byte
}

// add records a problem, merging it with an identical one already reported.
func (v *validator) add(severity Severity, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	if i, ok := v.seen[text]; ok {
		v.problems[i].Count++
		return
	}

	line, _ := v.dec.InputPos()
	v.seen[text] = len(v.problems)
	v.problems = append(v.problems, Problem{
		Text:     text,
		Severity: severity,
		Line:     line,
		Count:    1,
	})
}

// top returns the innermost open element, or nil at the document level.
func (v *validator) top() *frame {
	if len(v.stack) == 0 {
		return nil
	}
	return &v.stack[len(v.stack)-1]
}

// procInst rejects processing instructions, which can pull in an external
// resource, while letting the XML declaration through.
func (v *validator) procInst(t xml.ProcInst) {
	if t.Target == "xml" {
		return
	}
	v.add(SeverityError, "Processing instruction <?%s?> is not allowed: it can pull in an external resource", t.Target)
}

// directive rejects a DOCTYPE declaration.
func (v *validator) directive(t xml.Directive) {
	if strings.HasPrefix(strings.TrimSpace(string(t)), "DOCTYPE") {
		v.add(SeverityError, "The document contains a DOCTYPE declaration, which is not allowed by SVG Tiny P/S")
	}
}

// charData checks that text appears only where the profile allows it, and
// collects it for the elements whose content is constrained.
func (v *validator) charData(t xml.CharData) {
	f := v.top()
	if f == nil || f.skip || f.elem == nil {
		return
	}

	if f.elem.allowsText {
		f.text = append(f.text, t...)
		return
	}
	if len(bytes.TrimSpace(t)) != 0 {
		v.add(SeverityError, "Text is not allowed inside <%s>", f.name)
	}
}

// pushSkipped stacks an element whose subtree is tolerated but not validated.
func (v *validator) pushSkipped(name string) {
	v.pushFrame(frame{name: name, skip: true})
}

// pushFrame stacks f, filling in the sentinel firstIndex a frame is born with:
// no first child has been seen yet.
func (v *validator) pushFrame(f frame) {
	f.firstIndex = -1
	v.stack = append(v.stack, f)
}

// startElement validates an element and pushes it on the stack.
func (v *validator) startElement(t xml.StartElement) {
	local := t.Name.Local
	parent := v.top()

	// Content tolerated but not validated: the subtree of a rejected
	// element, and the RDF blocks editors leave in <metadata>.
	if parent != nil && parent.skip {
		v.pushSkipped(local)
		return
	}
	// Only the foreign markup the tolerance is meant for: an SVG element
	// nested in <metadata> is validated like any other, so <script> hidden
	// there is still reported as scripting.
	if parent != nil && parent.metadata && !v.inSVGNamespace(t.Name) {
		if !v.metadataWarned {
			v.metadataWarned = true
			v.add(SeverityWarning, "<metadata> holds elements, whereas the profile restricts it to text%s", toleratedNote)
		}
		v.pushSkipped(local)
		return
	}

	if parent != nil {
		parent.children++
	}

	if !v.rootSeen {
		v.startRoot(t)
		return
	}

	if !v.inSVGNamespace(t.Name) {
		v.add(SeverityError, "Element <%s> belongs to the namespace %q: only SVG elements are allowed", local, t.Name.Space)
		v.pushSkipped(local)
		return
	}

	elem, known := profileElements[local]
	switch {
	case !known:
		v.add(SeverityError, "Element <%s> is not part of the SVG Tiny P/S profile: %s", local, reasonFor(local))
		v.pushSkipped(local)
		return

	case parent == nil || parent.elem == nil:
		// No usable parent to check placement against.

	case parent.elem.children[local]:
		// Allowed here.

	case local == parent.elem.firstChild:
		parent.firstCount++
		if parent.firstIndex < 0 {
			parent.firstIndex = parent.children - 1
		}

	case fontElements[local]:
		// The schema defines the font elements but no content model
		// reaches them, so a literal reading forbids embedded fonts that
		// section 2.4 of the draft allows.
		v.add(SeverityWarning, "Element <%s> is unreachable in the profile schema%s", local, toleratedNote)

	default:
		v.add(SeverityError, "Element <%s> is not allowed as a child of <%s>", local, parent.name)
		v.pushSkipped(local)
		return
	}

	v.checkAttributes(local, elem, t.Attr)
	v.pushFrame(frame{
		name:     local,
		elem:     elem,
		metadata: local == "metadata",
	})
}

// startRoot validates the root element, which the profile fixes to <svg>.
func (v *validator) startRoot(t xml.StartElement) {
	v.rootSeen = true
	local := t.Name.Local

	if local != "svg" {
		v.add(SeverityError, "The root element is <%s>, expected <svg>", local)
		v.pushSkipped(local)
		return
	}

	if t.Name.Space != svgNS {
		// Carry on validating: the structure of the document is still
		// worth reporting on, and the descendants inherit the same
		// missing declaration, so say it once.
		v.unnamespaced = true
		v.add(SeverityError, "The root <svg> element declares the namespace %q, expected %q", t.Name.Space, svgNS)
	}

	v.rootIsSVG = true
	elem := profileElements["svg"]
	v.checkAttributes("svg", elem, t.Attr)
	v.pushFrame(frame{name: "svg", elem: elem})
}

// inSVGNamespace reports whether a name belongs to the SVG namespace, treating
// an absent namespace as SVG once the root has been reported as unnamespaced.
func (v *validator) inSVGNamespace(name xml.Name) bool {
	return name.Space == svgNS || (v.unnamespaced && name.Space == "")
}

// endElement pops the innermost element, running the checks that need its whole
// content.
func (v *validator) endElement() {
	f := v.top()
	if f == nil {
		return
	}
	v.stack = v.stack[:len(v.stack)-1]

	if f.skip || f.elem == nil {
		return
	}

	if child := f.elem.firstChild; child != "" {
		switch {
		case f.firstCount == 0:
			v.add(SeverityError, "<%s> must contain a <%s> element (it should carry the company name)", f.name, child)
		case f.firstCount > 1:
			v.add(SeverityError, "<%s> must contain exactly one <%s> element", f.name, child)
		case f.firstIndex > 0:
			v.add(SeverityError, "<%s> must be the first child of <%s>", child, f.name)
		}
	}

	switch f.name {
	case "title":
		text := strings.TrimSpace(string(f.text))
		if text == "" {
			v.add(SeverityError, "The <title> element must not be empty")
		} else if utf8.RuneCountInString(text) > maxTitleLength {
			v.add(SeverityWarning, "The <title> element should be no more than %d characters, it has %d", maxTitleLength, utf8.RuneCountInString(text))
		}
	case "desc":
		if strings.TrimSpace(string(f.text)) == "" {
			v.add(SeverityError, "The <desc> element must not be empty")
		}
	}
}

// finish runs the checks that need the whole document.
func (v *validator) finish() {
	if !v.rootSeen {
		v.add(SeverityError, "The file contains no XML element: it does not look like an SVG document")
		return
	}

	// Section 2.4: "An SVG Tiny PS document MUST include at least two colors
	// when rendered." Rendering is not simulated, so an element left to the
	// default paint is not counted; report it as a warning rather than
	// failing a logo that may well be compliant.
	if v.rootIsSVG && len(v.colors) < 2 {
		v.add(SeverityWarning, "The document paints with fewer than two distinct colours, whereas the profile requires at least two when rendered (the actual rendering is not simulated)")
	}
}

// checkAttributes validates every attribute carried by an element.
func (v *validator) checkAttributes(local string, elem *element, attrs []xml.Attr) {
	// Only <svg> carries required attributes, so the vast majority of the
	// nodes of a document need no presence bookkeeping at all.
	required := requiredAttrs[local]
	var present map[string]bool
	if len(required) > 0 {
		present = make(map[string]bool, len(attrs))
	}

	for _, a := range attrs {
		name, decl := v.attrName(a)
		if decl {
			continue
		}

		// SVG Tiny 1.2 addresses a fragment with xlink:href, which the
		// schema dropped in favour of the plain href of SVG 1.2.
		if name == "xlink:href" {
			v.add(SeverityWarning, "Attribute xlink:href on <%s> should be written href%s", local, toleratedNote)
			name = "href"
		}

		if present != nil {
			present[name] = true
		}

		spec, allowed := elem.attrs[name]
		if !allowed {
			v.add(SeverityError, "Attribute %q is not allowed on <%s>: %s", name, local, attrReason(name))
			continue
		}

		// A wrong value is already an error; adding that the attribute
		// should not be there at all would only be noise.
		if v.checkValue(local, name, a.Value, spec) && discouragedAttrs[name] {
			v.add(SeverityWarning, "Attribute %q should not be present on <%s>", name, local)
		}
		if name == "href" && !strings.HasPrefix(a.Value, "#") {
			v.add(SeverityError, "Reference %q on <%s> is not allowed: only references inside the document (#id) are permitted", a.Value, local)
		}
		v.checkFuncIRIs(local, name, a.Value)
		if colorAttrs[name] {
			if c := strings.ToLower(strings.TrimSpace(a.Value)); c != "" && c != "none" && c != "inherit" && c != "transparent" {
				v.colors[c] = true
			}
		}
	}

	for _, name := range required {
		if !present[name] {
			v.add(SeverityError, "The <%s> element is missing the required %s attribute", local, describeRequired(name, elem.attrs[name]))
		}
	}
}

// funcIRI matches a url(...) reference, with the target in the first group.
// SVG addresses a paint server this way, and the schema types every attribute
// that accepts one as a plain string, so the grammar cannot tell a reference
// inside the document from one that leaves it.
var funcIRI = regexp.MustCompile(`(?i)url\(\s*(?:'([^']*)'|"([^"]*)"|([^)'"\s]*))\s*\)`)

// checkFuncIRIs rejects the url(...) references of a value that leave the
// document, which section 2.3 of the draft forbids just as it forbids an
// external href.
func (v *validator) checkFuncIRIs(local, name, value string) {
	// Every attribute value of every element reaches this, including the
	// long path data of a <path>. A url(...) cannot exist without an opening
	// parenthesis, so that one byte scan spares the regexp the vast majority
	// of the document.
	if !strings.ContainsRune(value, '(') {
		return
	}

	for _, match := range funcIRI.FindAllStringSubmatch(value, -1) {
		target := match[1] + match[2] + match[3]
		if !strings.HasPrefix(target, "#") {
			v.add(SeverityError, "Reference %q in %s on <%s> is not allowed: only references inside the document (#id) are permitted", target, name, local)
		}
	}
}

// checkValue enforces the enumeration or the pattern the profile attaches to an
// attribute, and reports whether the value is acceptable.
func (v *validator) checkValue(local, name, value string, spec attr) bool {
	if len(spec.enum) > 0 {
		for _, candidate := range spec.enum {
			if value == candidate {
				return true
			}
		}
		v.add(SeverityError, "Attribute %s=%q on <%s> is not one of the permitted values (%s)", name, value, local, strings.Join(spec.enum, ", "))
		return false
	}

	if spec.pattern != "" {
		if re, ok := patterns[spec.pattern]; ok && !re.MatchString(value) {
			v.add(SeverityError, "Attribute %s=%q on <%s> does not match the required form %q", name, value, local, spec.pattern)
			return false
		}
	}

	return true
}

// attrName returns the qualified name of an attribute, and whether it is a
// namespace declaration rather than an attribute of the element. Prefixes the
// decoder could not resolve are kept verbatim, which is enough to tell the
// author the attribute is not part of the profile.
func (v *validator) attrName(a xml.Attr) (string, bool) {
	switch {
	case a.Name.Space == "xmlns":
		return "", true
	case a.Name.Space == "" && a.Name.Local == "xmlns":
		return "", true
	case a.Name.Space == "":
		return a.Name.Local, false
	case a.Name.Space == xmlNS || a.Name.Space == "xml":
		return "xml:" + a.Name.Local, false
	case a.Name.Space == xlinkNS || a.Name.Space == "xlink":
		return "xlink:" + a.Name.Local, false
	default:
		return "{" + a.Name.Space + "}" + a.Name.Local, false
	}
}

// reasonFor explains why an element is absent from the profile.
func reasonFor(local string) string {
	if reason, known := forbiddenReasons[strings.ToLower(local)]; known {
		return reason
	}
	return "the profile permits no such element"
}

// attrReason explains why an attribute is absent from an element's profile.
func attrReason(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "on") && !strings.Contains(name, ":"):
		return "event attributes enable scripting, which is prohibited"
	case lower == "style":
		return "styling must use presentation attributes, not CSS"
	case lower == "class":
		return "the profile has no styling mechanism to select on"
	case strings.HasPrefix(name, "{"):
		return "it belongs to a namespace the profile does not define"
	default:
		return "the profile does not define it there"
	}
}

// describeRequired names a required attribute along with its only permitted
// value, which is what the author actually has to write.
func describeRequired(name string, spec attr) string {
	if len(spec.enum) == 1 {
		return fmt.Sprintf("%s=%q", name, spec.enum[0])
	}
	return fmt.Sprintf("%q", name)
}
