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

import (
	"testing"
)

// TestParseRFC7601Examples reads every Authentication-Results field RFC 7601
// prints, from the trivial one of appendix B.2 to the comment-heavy one of
// appendix B.7 that the RFC itself offers as the proof of what the grammar
// allows.
func TestParseRFC7601Examples(t *testing.T) {
	for _, tt := range []struct {
		name       string
		field      string
		authservID string
		version    string
		none       bool
		methods    []Method
	}{
		{
			// Appendix B.2: service provided, but no authentication done.
			name:       "B.2 no authentication done",
			field:      "example.org 1; none",
			authservID: "example.org",
			version:    "1",
			none:       true,
		},
		{
			// Appendix B.3: one method, one property.
			name:       "B.3 one authentication done",
			field:      "example.com;\n          spf=pass smtp.mailfrom=example.net",
			authservID: "example.com",
			methods: []Method{{
				Name:       "spf",
				Result:     "pass",
				Properties: []Property{{Type: "smtp", Name: "mailfrom", Value: "example.net"}},
			}},
		},
		{
			// Appendix B.4: two methods in one field, the first with a
			// comment between its result and its property.
			name:       "B.4 several authentications, one MTA",
			field:      "example.com;\n          auth=pass (cram-md5) smtp.auth=sender@example.net;\n          spf=pass smtp.mailfrom=example.net",
			authservID: "example.com",
			methods: []Method{
				{
					Name:       "auth",
					Result:     "pass",
					Comments:   []string{"cram-md5"},
					Properties: []Property{{Type: "smtp", Name: "auth", Value: "sender@example.net"}},
				},
				{
					Name:       "spf",
					Result:     "pass",
					Properties: []Property{{Type: "smtp", Name: "mailfrom", Value: "example.net"}},
				},
			},
		},
		{
			// Appendix B.5: a failing method beside a passing one.
			name:       "B.5 several authentications, several MTAs",
			field:      "example.com;\n          sender-id=fail header.from=example.com;\n          dkim=pass (good signature) header.d=example.com",
			authservID: "example.com",
			methods: []Method{
				{
					Name:       "sender-id",
					Result:     "fail",
					Properties: []Property{{Type: "header", Name: "from", Value: "example.com"}},
				},
				{
					Name:       "dkim",
					Result:     "pass",
					Comments:   []string{"good signature"},
					Properties: []Property{{Type: "header", Name: "d", Value: "example.com"}},
				},
			},
		},
		{
			// Appendix B.6: the same method twice, each with a reason
			// written as a quoted string rather than as a comment.
			name:       "B.6 multi-tiered authentication",
			field:      "example.com;\n        dkim=pass reason=\"good signature\"\n          header.i=@mail-router.example.net;\n        dkim=fail reason=\"bad signature\"\n          header.i=@newyork.example.com",
			authservID: "example.com",
			methods: []Method{
				{
					Name:       "dkim",
					Result:     "pass",
					Reason:     "good signature",
					Properties: []Property{{Type: "header", Name: "i", Value: "@mail-router.example.net"}},
				},
				{
					Name:       "dkim",
					Result:     "fail",
					Reason:     "bad signature",
					Properties: []Property{{Type: "header", Name: "i", Value: "@newyork.example.com"}},
				},
			},
		},
		{
			// Appendix B.7: "a very comment-heavy but perfectly legal
			// example", where a comment stands between every two elements
			// the grammar has, the method and its version among them.
			name:       "B.7 comment-heavy",
			field:      "foo.example.net (foobar) 1 (baz);\n    dkim (Because I like it) / 1 (One yay) = (wait for it) fail\n      policy (A dot can go here) . (like that) expired\n      (this surprised me) = (as I wasn't expecting it) 1362471462",
			authservID: "foo.example.net",
			version:    "1",
			methods: []Method{{
				Name:       "dkim",
				Version:    "1",
				Result:     "fail",
				Comments:   []string{"Because I like it", "One yay", "wait for it", "A dot can go here", "like that", "this surprised me", "as I wasn't expecting it"},
				Properties: []Property{{Type: "policy", Name: "expired", Value: "1362471462"}},
			}},
		},
		{
			// Section 2.7.6: an extension method, with the data it was
			// evaluated on written as a comment.
			name:       "2.7.6 extension method",
			field:      "example.com;\n          foo=pass bar.baz=blob (2 of 3 tests OK)",
			authservID: "example.com",
			methods: []Method{{
				Name:       "foo",
				Result:     "pass",
				Comments:   []string{"2 of 3 tests OK"},
				Properties: []Property{{Type: "bar", Name: "baz", Value: "blob"}},
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header, read := Parse(tt.field)
			if !read {
				t.Fatal("the field was not read as one")
			}

			if header.AuthservID != tt.authservID {
				t.Errorf("authserv-id is %q, want %q", header.AuthservID, tt.authservID)
			}
			if header.Version != tt.version {
				t.Errorf("version is %q, want %q", header.Version, tt.version)
			}
			if header.None != tt.none {
				t.Errorf("none is %v, want %v", header.None, tt.none)
			}

			if len(header.Methods) != len(tt.methods) {
				t.Fatalf("the field reports %d methods, want %d: %+v", len(header.Methods), len(tt.methods), header.Methods)
			}

			for i, want := range tt.methods {
				got := header.Methods[i]

				if got.Name != want.Name || got.Version != want.Version || got.Result != want.Result || got.Reason != want.Reason {
					t.Errorf("method %d is %q/%q=%q reason %q, want %q/%q=%q reason %q",
						i, got.Name, got.Version, got.Result, got.Reason,
						want.Name, want.Version, want.Result, want.Reason)
				}

				if len(got.Properties) != len(want.Properties) {
					t.Fatalf("method %d holds %d properties, want %d: %+v", i, len(got.Properties), len(want.Properties), got.Properties)
				}
				for j, wantProperty := range want.Properties {
					if got.Properties[j] != wantProperty {
						t.Errorf("method %d property %d is %+v, want %+v", i, j, got.Properties[j], wantProperty)
					}
				}

				if len(got.Comments) != len(want.Comments) {
					t.Fatalf("method %d carries %d comments, want %d: %q", i, len(got.Comments), len(want.Comments), got.Comments)
				}
				for j, wantComment := range want.Comments {
					if got.Comments[j] != wantComment {
						t.Errorf("method %d comment %d is %q, want %q", i, j, got.Comments[j], wantComment)
					}
				}
			}
		})
	}
}
