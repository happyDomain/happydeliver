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

package analyzer

import (
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
)

// maxBIMILogoSize is the maximum size allowed for a BIMI SVG logo (BIMI
// group recommendation: 32 kilobytes).
const maxBIMILogoSize = 32 * 1024

// maxBIMIFileSize is a hard cap on any file downloaded during BIMI
// evidence collection (VMC chains are larger than logos).
const maxBIMIFileSize = 512 * 1024

// bimiCheck is a small helper to build model.BIMICheck values.
func bimiCheck(name, description string, status model.BIMICheckStatus, messages ...string) model.BIMICheck {
	c := model.BIMICheck{
		Name:        name,
		Description: description,
		Status:      status,
	}
	if len(messages) > 0 {
		c.Messages = &messages
	}
	return c
}

// fetchBIMIFile downloads a file referenced by a BIMI record and validates
// transport requirements (HTTPS, reachability, size). It returns the file
// content, the Content-Type announced by the server and the list of
// problems encountered (empty when the fetch is acceptable).
func (d *DNSAnalyzer) fetchBIMIFile(fileURL string, maxSize int64) (content []byte, contentType string, problems []string) {
	u, err := url.Parse(fileURL)
	if err != nil {
		return nil, "", []string{fmt.Sprintf("Invalid URL: %s", err)}
	}

	if !strings.EqualFold(u.Scheme, "https") {
		problems = append(problems, fmt.Sprintf("URL uses %q scheme: BIMI requires files to be served over HTTPS", u.Scheme))
		return nil, "", problems
	}

	resp, err := d.httpClient.Get(fileURL)
	if err != nil {
		problems = append(problems, fmt.Sprintf("Unable to retrieve file: %s", err))
		return nil, "", problems
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		problems = append(problems, fmt.Sprintf("Server responded with HTTP status %d instead of 200", resp.StatusCode))
		return nil, "", problems
	}

	content, err = io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		problems = append(problems, fmt.Sprintf("Error while downloading file: %s", err))
		return nil, "", problems
	}

	if int64(len(content)) > maxSize {
		problems = append(problems, fmt.Sprintf("File exceeds the maximum allowed size of %d bytes", maxSize))
		return nil, "", problems
	}

	contentType = resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		contentType = mt
	}

	return content, contentType, nil
}

// checkBIMILogoXML performs an xmllint-like well-formedness check on the
// SVG document, reporting the position of the first syntax error.
func checkBIMILogoXML(content []byte) *model.BIMICheck {
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
			c := bimiCheck("logo_xml", "Logo XML well-formedness", model.BIMICheckStatusFail,
				fmt.Sprintf("The SVG file is not well-formed XML: %s", msg))
			return &c
		}
		if _, ok := tok.(xml.StartElement); ok {
			hasRootElement = true
		}
	}

	if !hasRootElement {
		c := bimiCheck("logo_xml", "Logo XML well-formedness", model.BIMICheckStatusFail,
			"The file does not contain any XML element: it does not look like an SVG document")
		return &c
	}

	c := bimiCheck("logo_xml", "Logo XML well-formedness", model.BIMICheckStatusPass)
	return &c
}

// svgTinyPSForbiddenElements lists the SVG elements prohibited by the SVG
// Tiny Portable/Secure profile (draft-svg-tiny-ps-abrotman): scripting,
// interactivity, animation, multimedia, raster images and external content.
var svgTinyPSForbiddenElements = map[string]string{
	"script":           "scripting is not allowed",
	"handler":          "scripting is not allowed",
	"listener":         "interactivity is not allowed",
	"animate":          "animation is not allowed",
	"animatecolor":     "animation is not allowed",
	"animatemotion":    "animation is not allowed",
	"animatetransform": "animation is not allowed",
	"set":              "animation is not allowed",
	"discard":          "animation is not allowed",
	"audio":            "multimedia content is not allowed",
	"video":            "multimedia content is not allowed",
	"iframe":           "embedded documents are not allowed",
	"foreignobject":    "embedded documents are not allowed",
	"prefetch":         "external content hints are not allowed",
	"image":            "raster/external images are not allowed",
}

// checkBIMILogoSVGTinyPS validates the SVG document against the SVG Tiny
// Portable/Secure profile required by BIMI.
func checkBIMILogoSVGTinyPS(content []byte) *model.BIMICheck {
	var problems []string

	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	decoder.Strict = false

	var (
		rootSeen   bool
		depth      int
		titleFound bool
	)

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Well-formedness is reported by the dedicated XML check
			c := bimiCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", model.BIMICheckStatusSkipped,
				"Skipped: the file could not be parsed as XML")
			return &c
		}

		switch t := tok.(type) {
		case xml.Directive:
			if strings.HasPrefix(strings.TrimSpace(string(t)), "DOCTYPE") {
				problems = append(problems, "The document contains a DOCTYPE declaration, which is not allowed by SVG P/S")
			}

		case xml.StartElement:
			local := strings.ToLower(t.Name.Local)

			if !rootSeen {
				rootSeen = true
				if local != "svg" {
					problems = append(problems, fmt.Sprintf("Root element is <%s>, expected <svg>", t.Name.Local))
				}
				if t.Name.Space != "http://www.w3.org/2000/svg" {
					problems = append(problems, fmt.Sprintf("Root element namespace is %q, expected \"http://www.w3.org/2000/svg\"", t.Name.Space))
				}

				var version, baseProfile string
				for _, attr := range t.Attr {
					switch strings.ToLower(attr.Name.Local) {
					case "version":
						version = attr.Value
					case "baseprofile":
						baseProfile = attr.Value
					case "x", "y":
						if attr.Name.Space == "" {
							problems = append(problems, fmt.Sprintf("The root <svg> element must not have a %q attribute", attr.Name.Local))
						}
					}
				}
				if version != "1.2" {
					if version == "" {
						problems = append(problems, `The root <svg> element is missing the required version="1.2" attribute`)
					} else {
						problems = append(problems, fmt.Sprintf(`The root <svg> element declares version=%q, expected version="1.2"`, version))
					}
				}
				if baseProfile != "tiny-ps" {
					if baseProfile == "" {
						problems = append(problems, `The root <svg> element is missing the required baseProfile="tiny-ps" attribute`)
					} else {
						problems = append(problems, fmt.Sprintf(`The root <svg> element declares baseProfile=%q, expected baseProfile="tiny-ps"`, baseProfile))
					}
				}
			} else if depth == 1 && local == "title" {
				titleFound = true
			}

			if reason, forbidden := svgTinyPSForbiddenElements[local]; forbidden {
				problems = append(problems, fmt.Sprintf("Element <%s> is not allowed: %s", t.Name.Local, reason))
			}

			for _, attr := range t.Attr {
				attrLocal := strings.ToLower(attr.Name.Local)

				// Event attributes (onclick, onload, ...) enable scripting
				if strings.HasPrefix(attrLocal, "on") && attr.Name.Space == "" {
					problems = append(problems, fmt.Sprintf("Event attribute %q on <%s> is not allowed: scripting/interactivity is prohibited", attr.Name.Local, t.Name.Local))
				}

				// External references are prohibited; only local
				// fragment references (#id) are acceptable.
				if attrLocal == "href" {
					if !strings.HasPrefix(attr.Value, "#") {
						problems = append(problems, fmt.Sprintf("External reference %q on <%s> is not allowed: only references within the document (#id) are permitted", attr.Value, t.Name.Local))
					}
				}

				// External resources pulled in from inline styles
				if attrLocal == "style" && strings.Contains(strings.ToLower(attr.Value), "url(") && strings.Contains(strings.ToLower(attr.Value), "http") {
					problems = append(problems, fmt.Sprintf("Inline style on <%s> references an external URL, which is not allowed", t.Name.Local))
				}
			}

			depth++

		case xml.EndElement:
			depth--
		}
	}

	if rootSeen && !titleFound {
		problems = append(problems, "The <svg> element must contain a <title> child element (it should reflect the company name)")
	}

	if len(problems) > 0 {
		c := bimiCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", model.BIMICheckStatusFail, problems...)
		return &c
	}

	c := bimiCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", model.BIMICheckStatusPass)
	return &c
}

// runBIMIChecks performs the evidence checks (logo download, XML
// well-formedness, SVG P/S profile, VMC analysis) for a syntactically
// valid BIMI record, filling record.Checks and record.Vmc. It returns
// false when at least one mandatory check failed.
func (d *DNSAnalyzer) runBIMIChecks(record *model.BIMIRecord) bool {
	var checks []model.BIMICheck
	allPassed := true

	logoURL := ""
	if record.LogoUrl != nil {
		logoURL = *record.LogoUrl
	}
	vmcURL := ""
	if record.VmcUrl != nil {
		vmcURL = *record.VmcUrl
	}

	var logoContent []byte

	if logoURL == "" {
		checks = append(checks,
			bimiCheck("logo_fetch", "Logo file retrieval", model.BIMICheckStatusSkipped,
				"No logo URL published (declination record)"))
	} else {
		content, contentType, problems := d.fetchBIMIFile(logoURL, maxBIMILogoSize)
		if len(problems) > 0 {
			checks = append(checks, bimiCheck("logo_fetch", "Logo file retrieval", model.BIMICheckStatusFail, problems...))
			allPassed = false
		} else {
			logoContent = content
			if contentType != "image/svg+xml" {
				checks = append(checks, bimiCheck("logo_fetch", "Logo file retrieval", model.BIMICheckStatusWarning,
					fmt.Sprintf("Logo served with Content-Type %q, expected \"image/svg+xml\"", contentType)))
			} else {
				checks = append(checks, bimiCheck("logo_fetch", "Logo file retrieval", model.BIMICheckStatusPass))
			}
		}

		if logoContent == nil {
			checks = append(checks,
				bimiCheck("logo_xml", "Logo XML well-formedness", model.BIMICheckStatusSkipped,
					"Skipped: the logo could not be retrieved"),
				bimiCheck("logo_svg_tiny_ps", "Logo SVG Tiny Portable/Secure profile", model.BIMICheckStatusSkipped,
					"Skipped: the logo could not be retrieved"))
		} else {
			xmlCheck := checkBIMILogoXML(logoContent)
			checks = append(checks, *xmlCheck)
			if xmlCheck.Status == model.BIMICheckStatusFail {
				allPassed = false
			}

			svgCheck := checkBIMILogoSVGTinyPS(logoContent)
			checks = append(checks, *svgCheck)
			if svgCheck.Status == model.BIMICheckStatusFail {
				allPassed = false
			}
		}
	}

	if vmcURL == "" {
		checks = append(checks,
			bimiCheck("vmc", "Verified Mark Certificate", model.BIMICheckStatusSkipped,
				"No VMC published (a= tag absent or empty): VMC is optional but required by some mail providers (e.g. Gmail, Apple Mail)"))
	} else {
		vmcCheck, vmcInfo := d.analyzeBIMIVMC(vmcURL, record.Domain, logoContent)
		checks = append(checks, *vmcCheck)
		record.Vmc = vmcInfo
		if vmcCheck.Status == model.BIMICheckStatusFail {
			allPassed = false
		}
	}

	record.Checks = &checks
	return allPassed
}
