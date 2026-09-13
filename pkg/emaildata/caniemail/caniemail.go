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

// Package caniemail holds what Can I email knows about the email clients: which
// of them render a CSS property, an HTML element or an image format, and which
// drop it.
//
// It answers that question and no more. Which features happyDeliver looks for,
// how grave it counts a client dropping one, and what it advises a sender to do
// instead are a judgement about email, and live with the check that makes it.
package caniemail

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
)

// dataJSON is the Can I email support data by Rémi Parmentier and
// contributors (https://github.com/hteumeuleu/caniemail), embedded verbatim and
// licensed MIT. See THIRD-PARTY-NOTICES.md, and data/caniemail.LICENSE for the
// license text.
//
// It is what lets a finding name the clients that will not render a feature,
// rather than call it risky and leave the sender to find out which of their
// recipients lost the layout.
//
//go:embed data/caniemail.json
var dataJSON []byte

// License is the MIT license text shipped alongside the data, so that
// binary-only recipients of happyDeliver (a release artifact, a container
// image) get the notices the license requires along with the data.
//
//go:embed data/caniemail.LICENSE
var License string

// Attribution is the credit the MIT license asks to be kept with the
// material.
const Attribution = `Email client support data
-------------------------

Copyright (c) 2019 Rémi Parmentier and the Can I email contributors
Source:  https://www.caniemail.com/api/data.json
         https://github.com/hteumeuleu/caniemail
License: MIT
Changes: none, the data is embedded exactly as published upstream. Which of its
         features happyDeliver looks for, and what it advises a sender to do
         instead, live in its own source code, not in this data.`

// document is the shape of data.json, reduced to what is read here.
//
// last_update_date is deliberately left out: nothing reads it, and a field
// whose JSON type we have not pinned is one more way for a refresh to break the
// loader over something it does not need.
type document struct {
	APIVersion string    `json:"api_version"`
	Nicenames  nicenames `json:"nicenames"`
	Features   []feature `json:"data"`
}

// nicenames maps the dataset's own identifiers to the names a reader
// of the report knows a client by: "gmail" is what the data says, "Gmail" is
// what a finding must print.
type nicenames struct {
	Family   map[string]string `json:"family"`
	Platform map[string]string `json:"platform"`
}

// feature is one thing the dataset tracks: a CSS property, an HTML
// element, an image format.
type feature struct {
	Slug     string `json:"slug"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Category string `json:"category"`

	// Stats is the client family, then the platform, then the versions of that
	// platform in the order upstream wrote them.
	Stats map[string]map[string]versions `json:"stats"`
}

// versions is one platform's support history, kept in the order
// upstream wrote it.
//
// The order is the data. Within a platform the version keys are not reliably
// sortable: Outlook on macOS is written "2011", "2016", "16.80", which is
// chronological, while any numeric comparison puts 2016 last and so reads a
// verdict eight years stale (@font-face went from supported to unsupported
// between those two). Upstream writes oldest first, which is the only ordering
// there is, so it is preserved rather than reconstructed.
type versions []version

// version is one tested version and what it did with the feature.
type version struct {
	// Version is the key as written upstream: "16.80", "2016", "2021-05".
	Version string

	// Support is the value as written upstream: "y", "n", "a" or "u",
	// optionally followed by references to the feature's notes, as in "a #4 #5".
	Support string
}

// UnmarshalJSON decodes the version object as a stream of tokens rather than
// into a map, because a map would lose the one thing this type exists to keep.
func (v *versions) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	open, err := dec.Token()
	if err != nil {
		return err
	}
	if open != json.Delim('{') {
		return fmt.Errorf("caniemail: a version list reads %v, which is not an object", open)
	}

	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}

		name, ok := key.(string)
		if !ok {
			return fmt.Errorf("caniemail: a version key reads %v, which is not a string", key)
		}

		var support string
		if err := dec.Decode(&support); err != nil {
			return fmt.Errorf("caniemail: version %q: %w", name, err)
		}

		*v = append(*v, version{Version: name, Support: support})
	}

	// The closing brace, so that anything trailing the object is an error here
	// rather than silence.
	if _, err := dec.Token(); err != nil {
		return err
	}

	return nil
}

// supportLevel is what one version did with a feature.
type supportLevel uint8

const (
	// supportUnknown is the dataset's "u": nobody has tested this. It is the
	// zero value, so a verdict nobody reached reads as one nobody reached.
	supportUnknown supportLevel = iota

	// supportYes is "y": the feature renders.
	supportYes

	// supportPartial is "a": it renders in part, or under conditions the
	// feature's notes spell out.
	supportPartial

	// supportNo is "n": the client drops it.
	supportNo
)

// parseSupport reads a stats value, dropping the note references that
// may follow it ("a #4 #5").
func parseSupport(raw string) supportLevel {
	verdict, _, _ := strings.Cut(strings.TrimSpace(raw), " ")

	switch verdict {
	case "y":
		return supportYes
	case "a":
		return supportPartial
	case "n":
		return supportNo
	default:
		return supportUnknown
	}
}

// current is the verdict for the newest version of this platform that anybody
// tested.
//
// Trailing "u" entries are stepped over: a version nobody has looked at yet
// says nothing about the feature, while the last one somebody did look at still
// stands.
func (v versions) current() supportLevel {
	for i := len(v) - 1; i >= 0; i-- {
		if support := parseSupport(v[i].Support); support != supportUnknown {
			return support
		}
	}

	return supportUnknown
}

// Verdict is what the dataset says about one feature, reduced to the
// only question a finding asks of it: who will not render this.
type Verdict struct {
	// Slug, Title and URL are the feature as upstream names it: the key, the
	// name a finding prints ("display:flex"), and the page whose matrix the
	// reader can check for themselves.
	Slug  string
	Title string
	URL   string

	// Unsupported names the clients that drop the feature, and Partial those
	// that render it in part. A client belongs to at most one of them: dropping
	// a feature somewhere is the graver answer, and the one reported.
	//
	// They are ordered by prominence, so that the clients most senders' lists
	// are made of are named first, and so that the same message is produced
	// twice running.
	Unsupported []string
	Partial     []string
}

// reduced is what is kept of the dataset once it has been read: the verdicts,
// and the names the clients are known by.
//
// Every feature is reduced, not only those a check looks for: the data does not
// need to know which of it we read, and what is retained of 640 KB of JSON is a
// few hundred kilobytes of client names. The document itself is collected once
// the reduction is done.
type reduced struct {
	verdicts    map[string]Verdict
	clientNames []string
}

// read parses and reduces the embedded dataset, once for the life of the
// process.
var read = sync.OnceValue(reduce)

// Verdicts is the support verdict for every feature the dataset holds, keyed by
// slug.
func Verdicts() map[string]Verdict {
	return read().verdicts
}

// ClientNames is every client family the dataset tests, under the name a reader
// of a report knows it by, in alphabetical order.
//
// It is what says a name written elsewhere - a client a check calls major, one
// a message is checked against by hand - is still a client this data knows.
func ClientNames() []string {
	return read().clientNames
}

// prominentClientFamilies are the client families named first, being the ones a
// general-audience list is mostly made of. The rest follow in alphabetical
// order of the name a reader sees.
var prominentClientFamilies = []string{"gmail", "outlook", "apple-mail", "yahoo", "samsung-email", "thunderbird"}

// reduce parses the embedded dataset and reduces it.
//
// A dataset that does not parse is logged and yields no verdicts, so that an
// analysis reports nothing about compatibility rather than failing altogether.
// That it never happens in a release is TestCaniemailDataIsSane's business.
func reduce() reduced {
	doc, err := parseDocument(dataJSON)
	if err != nil {
		log.Printf("caniemail: the embedded support data could not be read, no compatibility verdict will be reported: %v", err)
		return reduced{}
	}

	verdicts := make(map[string]Verdict, len(doc.Features))
	for _, entry := range doc.Features {
		verdicts[entry.Slug] = doc.verdictFor(entry)
	}

	names := make([]string, 0, len(doc.Nicenames.Family))
	for _, name := range doc.Nicenames.Family {
		names = append(names, name)
	}
	slices.Sort(names)

	return reduced{verdicts: verdicts, clientNames: names}
}

// parseDocument decodes the dataset. It is a function of its own so
// that the tests can read the whole of it, where the loader keeps only what it
// reduced.
func parseDocument(data []byte) (*document, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if len(doc.Features) == 0 {
		return nil, fmt.Errorf("caniemail: the data carries no feature at all")
	}

	return &doc, nil
}

// verdictFor reduces one feature's support table to the clients that will not
// render it.
//
// A family is judged on the worst of its platforms: dropping a feature on
// Windows is a defect the sender must hear about, whatever Outlook for Mac
// does with it. Where the platforms disagree, the failing ones are named in
// parentheses, so that "Outlook (Windows)" is not read as all of Outlook.
func (d *document) verdictFor(entry feature) Verdict {
	verdict := Verdict{Slug: entry.Slug, Title: entry.Title, URL: entry.URL}

	type judged struct {
		family  string
		name    string
		support supportLevel
	}

	judgements := make([]judged, 0, len(entry.Stats))
	for family, platforms := range entry.Stats {
		worst := supportUnknown
		// The platforms that reached the worst verdict, which are the ones the
		// name has to account for.
		var failing []string

		for platform, versions := range platforms {
			support := versions.current()
			switch {
			case support > worst:
				worst = support
				failing = []string{platform}
			case support == worst && support != supportUnknown:
				failing = append(failing, platform)
			}
		}

		if worst != supportNo && worst != supportPartial {
			continue
		}

		judgements = append(judgements, judged{
			family:  family,
			name:    d.clientName(family, platforms, failing),
			support: worst,
		})
	}

	slices.SortFunc(judgements, func(a, b judged) int {
		return compareClientProminence(a.family, a.name, b.family, b.name)
	})

	for _, judgement := range judgements {
		if judgement.support == supportNo {
			verdict.Unsupported = append(verdict.Unsupported, judgement.name)
			continue
		}
		verdict.Partial = append(verdict.Partial, judgement.name)
	}

	return verdict
}

// clientName is how a family is named in a finding: alone when the whole of it
// reached the verdict, and with the failing platforms in parentheses when its
// platforms disagreed.
func (d *document) clientName(family string, platforms map[string]versions, failing []string) string {
	name := d.Nicenames.Family[family]
	if name == "" {
		name = family
	}

	// A family whose every tested platform agrees is named alone. Platforms
	// nobody tested do not count as disagreeing: they say nothing.
	tested := 0
	for _, versions := range platforms {
		if versions.current() != supportUnknown {
			tested++
		}
	}
	if len(failing) == 0 || len(failing) == tested {
		return name
	}

	names := make([]string, 0, len(failing))
	for _, platform := range failing {
		platformName := d.Nicenames.Platform[platform]
		if platformName == "" {
			platformName = platform
		}
		names = append(names, platformName)
	}
	slices.Sort(names)

	return name + " (" + strings.Join(names, ", ") + ")"
}

// compareClientProminence orders the clients of a verdict: the prominent
// families in the order prominentClientFamilies lists them, then the rest
// alphabetically by the name a reader sees.
func compareClientProminence(familyA, nameA, familyB, nameB string) int {
	rankA := slices.Index(prominentClientFamilies, familyA)
	rankB := slices.Index(prominentClientFamilies, familyB)

	switch {
	case rankA >= 0 && rankB >= 0 && rankA != rankB:
		return rankA - rankB
	case rankA >= 0 && rankB < 0:
		return -1
	case rankA < 0 && rankB >= 0:
		return 1
	}

	return strings.Compare(nameA, nameB)
}
