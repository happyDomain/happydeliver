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

package caniemail

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestCaniemailDataIsSane guards the embedded support data against the shapes a
// refresh could quietly import: a truncated download, a renamed field, a
// support value in a vocabulary we do not read.
//
// It reads the whole document rather than the reduced verdicts, so that a
// feature nothing looks for still has to be well formed: the day a row is added
// for it, it is the data that must already be trustworthy.
func TestCaniemailDataIsSane(t *testing.T) {
	doc, err := parseDocument(dataJSON)
	if err != nil {
		t.Fatalf("the embedded data does not parse: %v", err)
	}

	if len(doc.Features) < 300 {
		t.Errorf("the data holds %d features, which looks truncated", len(doc.Features))
	}

	if doc.APIVersion == "" {
		t.Error("the data announces no api_version, so a change of shape would go unremarked")
	}

	slug := regexp.MustCompile(`^[a-z0-9-]+$`)
	noteReference := regexp.MustCompile(`^#\d+$`)
	categories := []string{"css", "html", "image", "others"}

	seen := make(map[string]bool, len(doc.Features))
	families := make(map[string]bool)

	for _, feature := range doc.Features {
		if !slug.MatchString(feature.Slug) {
			t.Errorf("feature slug %q is not a bare lowercase identifier", feature.Slug)
			continue
		}
		if seen[feature.Slug] {
			t.Errorf("feature slug %q appears twice, so one of them is unreachable", feature.Slug)
		}
		seen[feature.Slug] = true

		if feature.Title == "" {
			t.Errorf("feature %q has no title, so a finding about it could not name it", feature.Slug)
		}
		if !slices.Contains(categories, feature.Category) {
			t.Errorf("feature %q is categorised %q, which is not one of %v", feature.Slug, feature.Category, categories)
		}

		for family, platforms := range feature.Stats {
			families[family] = true

			for platform, versions := range platforms {
				if len(versions) == 0 {
					t.Errorf("feature %q, %s/%s: no version at all, so nothing can be read off it", feature.Slug, family, platform)
				}

				for _, version := range versions {
					fields := strings.Fields(version.Support)
					if len(fields) == 0 {
						t.Errorf("feature %q, %s/%s/%s: an empty support value", feature.Slug, family, platform, version.Version)
						continue
					}

					if !slices.Contains([]string{"y", "n", "a", "u"}, fields[0]) {
						t.Errorf("feature %q, %s/%s/%s: support reads %q, which is not one of y, n, a, u",
							feature.Slug, family, platform, version.Version, fields[0])
					}

					for _, reference := range fields[1:] {
						if !noteReference.MatchString(reference) {
							t.Errorf("feature %q, %s/%s/%s: %q is not a note reference",
								feature.Slug, family, platform, version.Version, reference)
						}
					}
				}
			}
		}
	}

	// Every family a feature is judged on must have a name a reader knows it
	// by, or a finding would print the dataset's own identifier at them.
	for family := range families {
		if doc.Nicenames.Family[family] == "" {
			t.Errorf("client family %q appears in the stats but has no nicename", family)
		}
	}
}

// TestCaniemailVersionsKeepUpstreamOrder is the regression test for the whole
// reason versions has an UnmarshalJSON of its own.
//
// The keys below are Outlook for macOS, verbatim and in upstream's order. Any
// numeric comparison reads 2016 as the newest of them and so answers that the
// feature is supported, eight years after it stopped being.
func TestCaniemailVersionsKeepUpstreamOrder(t *testing.T) {
	var versions versions
	if err := json.Unmarshal([]byte(`{"2011":"y","2016":"y","16.80":"n"}`), &versions); err != nil {
		t.Fatalf("the version list does not decode: %v", err)
	}

	written := []string{"2011", "2016", "16.80"}
	for i, want := range written {
		if i >= len(versions) {
			t.Fatalf("only %d versions decoded, want %d", len(versions), len(written))
		}
		if versions[i].Version != want {
			t.Errorf("version %d decoded as %q, want %q: the order upstream wrote is not preserved",
				i, versions[i].Version, want)
		}
	}

	if got := versions.current(); got != supportNo {
		t.Errorf("the current verdict reads %v, want %v: the newest version is the last one written, not the largest number",
			got, supportNo)
	}
}

// TestCaniemailVersionsStepOverUntestedVersions holds the reading of a "u": a
// version nobody looked at says nothing, and must not erase the last verdict
// somebody did reach.
func TestCaniemailVersionsStepOverUntestedVersions(t *testing.T) {
	var versions versions
	if err := json.Unmarshal([]byte(`{"2019-07":"n","2024-03":"u"}`), &versions); err != nil {
		t.Fatalf("the version list does not decode: %v", err)
	}

	if got := versions.current(); got != supportNo {
		t.Errorf("the current verdict reads %v, want %v", got, supportNo)
	}
}

// TestCaniemailVersionsAreNotNumericallySorted keeps the comment justifying the
// custom decoder honest against the real data.
//
// It asserts "somewhere, at least once" rather than naming Outlook for macOS:
// upstream is free to retest any platform, and a legitimate change of data must
// not fail this. What would fail it is upstream normalising its keys into
// something sortable, at which point the decoder's reason for existing is worth
// re-examining rather than leaving to rot in a comment.
func TestCaniemailVersionsAreNotNumericallySorted(t *testing.T) {
	doc, err := parseDocument(dataJSON)
	if err != nil {
		t.Fatalf("the embedded data does not parse: %v", err)
	}

	for _, feature := range doc.Features {
		for family, platforms := range feature.Stats {
			for platform, versions := range platforms {
				if !isAscendingByLeadingNumber(versions) {
					t.Logf("%s, %s/%s: versions are written %v, which does not ascend numerically",
						feature.Slug, family, platform, versionKeys(versions))
					return
				}
			}
		}
	}

	t.Error("every platform's versions now ascend numerically: upstream may have normalised its keys, so versions.UnmarshalJSON is worth re-examining")
}

// isAscendingByLeadingNumber says whether a version list would come out in the
// same order under a naive numeric sort of its keys.
func isAscendingByLeadingNumber(versions versions) bool {
	previous := -1
	for _, version := range versions {
		leading, _, _ := strings.Cut(version.Version, ".")
		number, err := strconv.Atoi(leading)
		if err != nil {
			continue
		}
		if number < previous {
			return false
		}
		previous = number
	}

	return true
}

// versionKeys is a version list's keys, for a test's own message.
func versionKeys(versions versions) []string {
	keys := make([]string, 0, len(versions))
	for _, version := range versions {
		keys = append(keys, version.Version)
	}

	return keys
}

// TestNoticeCarriesWhatTheLicenseAsks checks that the notice shipped in the
// binary carries what the MIT license asks to be kept with the material: the
// creators, a link to it, the license text itself, and whether it was modified.
func TestNoticeCarriesWhatTheLicenseAsks(t *testing.T) {
	for _, want := range []string{
		"Rémi Parmentier",
		"https://github.com/hteumeuleu/caniemail",
		"MIT",
		"Changes:",
	} {
		if !strings.Contains(Attribution, want) {
			t.Errorf("the attribution is missing %q", want)
		}
	}

	// The full license text, not just a link to it.
	if !strings.Contains(License, "Permission is hereby granted") {
		t.Error("the license text does not read as MIT")
	}
}

// TestClientNamesAreWhatAReaderSees says the dataset still names the clients a
// report speaks of.
func TestClientNamesAreWhatAReaderSees(t *testing.T) {
	names := ClientNames()

	if len(names) < 10 {
		t.Fatalf("the data knows %d client families, which looks truncated", len(names))
	}

	if !slices.IsSorted(names) {
		t.Error("the names are not sorted, so a caller cannot search them")
	}

	for _, want := range []string{"Gmail", "Outlook", "Apple Mail"} {
		if !slices.Contains(names, want) {
			t.Errorf("the data no longer names %q, which reports are written against", want)
		}
	}
}
