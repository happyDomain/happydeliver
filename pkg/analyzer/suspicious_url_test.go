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
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
)

// kindsOf returns the suspicion kinds reported for a URL, in report order.
func kindsOf(suspicions []URLSuspicion) []URLSuspicionKind {
	kinds := make([]URLSuspicionKind, 0, len(suspicions))
	for _, s := range suspicions {
		kinds = append(kinds, s.Kind)
	}
	return kinds
}

// TestAnalyzeURLSuspicions_LegitimateURLs pins the most important property of
// the detector: ordinary URLs found in real, legitimate marketing and
// transactional emails must produce no finding at all. Every entry below is
// modelled on a real-world link; a regression here means users get told their
// perfectly normal tracking links are "obfuscated or shortened".
func TestAnalyzeURLSuspicions_LegitimateURLs(t *testing.T) {
	urls := []struct {
		name string
		url  string
	}{
		{"Plain HTTPS", "https://example.com/page"},
		{"Plain HTTP", "http://example.com/"},
		{"Single subdomain", "https://mail.example.com/page"},
		{"Deep but ordinary subdomains (ESP click tracker)", "https://fr.r.emails.example.com/r/?id=h2f29daf0"},
		{"Very deep subdomains", "https://a.b.c.d.e.example.com/page"},
		{"Long base64 query string", "https://fr.r.emails.example.com/r/?id=h2f29daf0,adcbfc78,95c915a&e=ZW1sLXB1Ymxpc2hlcj1OZW9sYW5lJmVtbC1uYW1lPTIwNTQwNzAzOCZPcmlnaW5DbGljaz1ZRVM&s=JaSedqApLxbMlohm-cs8F8YQ0w55o6EW7zDmw1Gun4Q"},
		{"Percent-encoded query values", "https://track.example.com/c?p1=%40u%2BxgYw8PKqAwBsLJMhTiRw%3D%3D&p2=4EDBDF52"},
		{"Email address in query", "https://example.com/confirm?email=user%40example.org"},
		{"At sign in path (social handle)", "https://example.com/@johndoe"},
		{"At sign in fragment", "https://example.com/page#@top"},
		{"Hyphenated host", "https://my-shop-online.example.com/deals"},
		{"Uppercase host", "https://WWW.EXAMPLE.COM/Page"},
		{"Explicit standard HTTPS port", "https://example.com:443/page"},
		{"Explicit standard HTTP port", "http://example.com:80/page"},
		{"Country second level domain", "https://shop.example.co.uk/basket"},
		{"Australian style com.au domain", "https://www.example.com.au/"},
		{"Mailto", "mailto:support@example.com"},
		{"Mailto with parameters", "mailto:support@example.com?subject=Hello%20there"},
		{"Mailto with several at signs", "mailto:user@sub@example.com"},
		{"Tel", "tel:+33123456789"},
		{"SMS", "sms:+33123456789"},
		{"Relative link", "/preferences/unsubscribe"},
		{"Anchor only", "#content"},
		{"Content ID (inline image)", "cid:logo@example"},
		{"Numeric label in host", "https://s3.example.com/2024/report.pdf"},
		{"All numeric path", "https://example.com/1234567890"},
		{"Digits in host label", "https://mx1.example.com/"},
		{"IDN host in Unicode form", "https://éxample.example/page"},
		{"IDN host in punycode form", "https://xn--xample-9ua.example/page"},
		{"Non-Latin IDN host", "https://пример.example/страница"},
		{"ASCII host under an IDN TLD", "https://example.xn--p1ai/"},
		{"IDN subdomain of an ASCII domain", "https://boutique-café.example.com/"},
	}

	for _, tt := range urls {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeURLSuspicions(tt.url)
			if len(got) != 0 {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no finding", tt.url, kindsOf(got))
			}
		})
	}
}

// TestAnalyzeURLSuspicions_Shortener checks that only hosts that really are
// public URL shorteners are reported as such, matched on the whole host
// (optionally prefixed by "www.") and case-insensitively.
func TestAnalyzeURLSuspicions_Shortener(t *testing.T) {
	shortened := []string{
		"https://bit.ly/abc123",
		"http://bit.ly/abc123",
		"https://www.bit.ly/abc123",
		"https://BIT.LY/abc123",
		"https://tinyurl.com/abc123",
		"https://t.co/abc123",
		"https://is.gd/abc123",
		"https://cutt.ly/abc123",
		"https://rebrand.ly/abc123",
		"https://tiny.cc/abc123",
	}
	for _, u := range shortened {
		t.Run(u, func(t *testing.T) {
			got := analyzeURLSuspicions(u)
			if !slices.Contains(kindsOf(got), URLSuspicionShortener) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", u, kindsOf(got), URLSuspicionShortener)
			}
		})
	}

	// Hosts that merely look like a shortener must not be flagged as one: the
	// match is on the full host, never on a substring. Branded short links,
	// which can only lead to their own service, are not shorteners either.
	notShortened := []string{
		"https://bit.ly.example.com/abc",
		"https://mybit.ly.example.org/abc",
		"https://example.com/bit.ly/abc",
		"https://links.example.com/t.co",
		"https://youtu.be/dQw4w9WgXcQ",
		"https://www.youtu.be/dQw4w9WgXcQ",
		"https://amzn.to/abc123",
		"https://wa.me/33123456789",
		"https://t.me/example",
	}
	for _, u := range notShortened {
		t.Run("not/"+u, func(t *testing.T) {
			got := analyzeURLSuspicions(u)
			if slices.Contains(kindsOf(got), URLSuspicionShortener) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, kindsOf(got), URLSuspicionShortener)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_IPHost checks literal IP hosts, which are a strong
// phishing signal in email since legitimate senders use domain names.
func TestAnalyzeURLSuspicions_IPHost(t *testing.T) {
	tests := []struct {
		url  string
		want URLSuspicionKind
	}{
		{"https://192.0.2.10/page", URLSuspicionIPHost},
		{"http://192.0.2.10:8080/page", URLSuspicionIPHost},
		{"https://[2001:db8::1]/page", URLSuspicionIPHost},
		{"http://[2001:db8::1]:8080/page", URLSuspicionIPHost},
		{"http://198.51.100.7/page", URLSuspicionIPHost},
		// Obfuscated forms of an IPv4 address: every notation inet_aton
		// accepts resolves to a host but hides it.
		{"http://3221225994/page", URLSuspicionObfuscatedIPHost},
		{"http://0xC000020A/page", URLSuspicionObfuscatedIPHost},
		{"http://0300.0000.0002.0012/page", URLSuspicionObfuscatedIPHost},
		// Hexadecimal groups, and notations mixing bases inside one address.
		{"http://0xc0.0x00.0x02.0x0a/page", URLSuspicionObfuscatedIPHost},
		{"http://192.0x00.2.10/page", URLSuspicionObfuscatedIPHost},
		{"http://192.0.0x20a/page", URLSuspicionObfuscatedIPHost},
		{"http://0X10/page", URLSuspicionObfuscatedIPHost},
		{"http://0xff.0xff.0xff.0xff/page", URLSuspicionObfuscatedIPHost},
		{"http://1.0x2.3/page", URLSuspicionObfuscatedIPHost},
		// Octal, both as a whole and per group.
		{"http://037777777777/page", URLSuspicionObfuscatedIPHost},
		{"http://0377.0377.0377.0377/page", URLSuspicionObfuscatedIPHost},
		{"http://192.168.001.1/page", URLSuspicionObfuscatedIPHost},
		// Fewer than four parts: the last one absorbs the missing bytes.
		{"http://192.11.1/page", URLSuspicionObfuscatedIPHost},
		{"http://192.526/page", URLSuspicionObfuscatedIPHost},
		{"http://0/page", URLSuspicionObfuscatedIPHost},
		// An unbracketed IPv6 literal is a host, not a "host:port".
		{"http://2001:db8::1/page", URLSuspicionIPHost},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(tt.url))
			if !slices.Contains(got, tt.want) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", tt.url, got, tt.want)
			}
		})
	}

	// Hosts that contain digits or look numeric but are not addresses: an
	// address claim must be true, so a number no address can hold, or a part
	// larger than its slot, is not reported as an IP.
	notIP := []string{
		"https://192.0.2.10.example.com/page",
		"https://1.2.3.4.wildcard-dns.example.org/page",
		"https://123.example.com/page",
		"http://99999999999999/page",
		"http://192.0.2.999/page",
		"http://1.2.3.4.5/page",
		"http://0x/page",
		// "08" and "09" are not octal, so these parse as nothing at all.
		"http://08.0.0.1/page",
		"http://09/page",
		// A part wider than 32 bits, and one that overflows its own slot.
		"http://0xfffffffff/page",
		"http://1.16843009/page",
		"http://4294967296/page",
	}
	for _, u := range notIP {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionIPHost) || slices.Contains(got, URLSuspicionObfuscatedIPHost) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no IP finding", u, got)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_UserInfo covers the classic "https://bank.example@evil"
// trick: everything before the "@" in the authority is credentials, not the
// destination. Only an "@" inside the authority counts — one in the path,
// query or fragment is perfectly ordinary.
func TestAnalyzeURLSuspicions_UserInfo(t *testing.T) {
	flagged := []string{
		"https://bank.example.com@evil.example.net/login",
		"https://user:password@evil.example.net/",
		"https://user@example.com/page",
	}
	for _, u := range flagged {
		t.Run(u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if !slices.Contains(got, URLSuspicionUserInfo) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", u, got, URLSuspicionUserInfo)
			}
		})
	}

	clean := []string{
		"https://example.com/users/@alice",
		"https://example.com/?reply=alice@example.org",
		"https://example.com/page#mail@example.org",
		"mailto:alice@example.org",
	}
	for _, u := range clean {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionUserInfo) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, got, URLSuspicionUserInfo)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_DangerousScheme checks schemes that execute code or
// inline a document instead of pointing at a destination.
func TestAnalyzeURLSuspicions_DangerousScheme(t *testing.T) {
	dangerous := []string{
		"javascript:alert(1)",
		"JavaScript:void(0)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
	}
	for _, u := range dangerous {
		t.Run(u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if !slices.Contains(got, URLSuspicionDangerousScheme) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", u, got, URLSuspicionDangerousScheme)
			}
		})
	}

	for _, u := range []string{"mailto:a@example.com", "tel:+3312", "https://example.com/", "cid:img@example"} {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionDangerousScheme) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, got, URLSuspicionDangerousScheme)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_HostObfuscation covers hosts written in a way that
// hides what they really are: percent-escapes and characters that have no
// business in a hostname.
func TestAnalyzeURLSuspicions_HostObfuscation(t *testing.T) {
	tests := []struct {
		url  string
		want URLSuspicionKind
	}{
		{"http://exa%6dple.com/page", URLSuspicionEncodedHost},
		{"http://%65xample.com/", URLSuspicionEncodedHost},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(tt.url))
			if !slices.Contains(got, tt.want) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", tt.url, got, tt.want)
			}
		})
	}

	// Percent-escapes elsewhere in the URL are normal and must stay silent.
	for _, u := range []string{
		"https://example.com/a%20b/c?x=%C3%A9",
		"https://example.com/?redirect=https%3A%2F%2Fother.example.org%2F",
	} {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionEncodedHost) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, got, URLSuspicionEncodedHost)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_NonStandardPort: web links in email are served on
// 80/443; anything else is worth a low-severity note.
func TestAnalyzeURLSuspicions_NonStandardPort(t *testing.T) {
	for _, u := range []string{"https://example.com:8443/page", "http://example.com:8080/page"} {
		t.Run(u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if !slices.Contains(got, URLSuspicionNonStandardPort) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", u, got, URLSuspicionNonStandardPort)
			}
		})
	}
	for _, u := range []string{
		"https://example.com/page",
		"https://example.com:443/",
		"http://example.com:80/",
		// Nothing here is a port, so nothing may be reported as one: the
		// last group of an IPv6 literal, and a value no port can take.
		"http://2001:db8::1/page",
		"https://example.com:70000/",
		"https://example.com:abc/",
	} {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionNonStandardPort) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, got, URLSuspicionNonStandardPort)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_DeceptiveHost covers hosts that embed a generic TLD
// label to make the beginning of the name look like the real domain, e.g.
// "bank.example.com.login.example". Legitimate hierarchical suffixes such
// as "com.au", and registrable domains that legitimately contain a generic
// label ("gov.bc.ca"), must not trip it.
func TestAnalyzeURLSuspicions_DeceptiveHost(t *testing.T) {
	for _, u := range []string{
		"https://bank.example.com.secure-login.example/",
		"https://example.net.account-verify.example/",
		"https://secure.bank.example.com.login.example/",
	} {
		t.Run(u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if !slices.Contains(got, URLSuspicionDeceptiveHost) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want a %q finding", u, got, URLSuspicionDeceptiveHost)
			}
		})
	}
	for _, u := range []string{
		"https://www.example.com.au/",
		"https://shop.example.co.uk/",
		"https://mail.example.com/",
		"https://fr.r.emails.example.com/r/?id=x",
		// A generic label opening the name pretends to be nothing: what
		// precedes the real domain is just a subdomain.
		"https://int.example.com/",
		"https://org.example.com/",
		"https://net.example.com/",
		// "gov", "edu" and friends are ordinary subdomain names.
		"https://my.gov.example.com/",
		"https://email.int.example.com/",
		// No reserved domain exercises a three-level suffix whose registrable
		// label is generic, so this uses the real "bc.ca" public suffix: here
		// "gov" belongs to the registrable domain "gov.bc.ca".
		"https://www2.gov.bc.ca/",
	} {
		t.Run("not/"+u, func(t *testing.T) {
			got := kindsOf(analyzeURLSuspicions(u))
			if slices.Contains(got, URLSuspicionDeceptiveHost) {
				t.Errorf("analyzeURLSuspicions(%q) = %v, want no %q finding", u, got, URLSuspicionDeceptiveHost)
			}
		})
	}
}

// TestAnalyzeURLSuspicions_MultipleFindings: a URL can be wrong in several
// ways at once, and each reason must be reported separately (no deduplication
// into a single vague "suspicious" verdict) and only once each.
func TestAnalyzeURLSuspicions_MultipleFindings(t *testing.T) {
	got := analyzeURLSuspicions("http://bank.example.com@192.0.2.10:8080/login")

	kinds := kindsOf(got)
	for _, want := range []URLSuspicionKind{URLSuspicionUserInfo, URLSuspicionIPHost, URLSuspicionNonStandardPort} {
		if !slices.Contains(kinds, want) {
			t.Errorf("kinds = %v, want to contain %q", kinds, want)
		}
	}

	seen := map[URLSuspicionKind]int{}
	for _, k := range kinds {
		seen[k]++
		if seen[k] > 1 {
			t.Errorf("kind %q reported %d times, want once", k, seen[k])
		}
	}
}

// TestAnalyzeURLSuspicions_FindingsAreActionable: every finding must carry a
// specific message and advice — the old code reported the same "obfuscated,
// shortened, or unusual" sentence whatever the actual reason was.
func TestAnalyzeURLSuspicions_FindingsAreActionable(t *testing.T) {
	samples := []string{
		"https://bit.ly/abc",
		"https://192.0.2.10/",
		"http://3221225994/",
		"https://user@evil.example.net/",
		"javascript:alert(1)",
		"http://exa%6dple.com/",
		"https://example.com:8443/",
		"https://bank.example.com.login.example/",
	}

	genericMessage := "obfuscated, shortened, or unusual"

	for _, u := range samples {
		t.Run(u, func(t *testing.T) {
			got := analyzeURLSuspicions(u)
			if len(got) == 0 {
				t.Fatalf("analyzeURLSuspicions(%q) returned no finding", u)
			}
			for _, s := range got {
				if s.Kind == "" {
					t.Errorf("finding %+v has an empty Kind", s)
				}
				if strings.TrimSpace(s.Message) == "" {
					t.Errorf("finding %q has an empty Message", s.Kind)
				}
				if strings.Contains(s.Message, genericMessage) {
					t.Errorf("finding %q uses the old catch-all message %q", s.Kind, s.Message)
				}
				if strings.TrimSpace(s.Advice) == "" {
					t.Errorf("finding %q has an empty Advice", s.Kind)
				}
				if !s.Severity.Valid() {
					t.Errorf("finding %q has an invalid severity %q", s.Kind, s.Severity)
				}
				if s.Severity == model.ContentIssueSeverityInfo {
					t.Errorf("finding %q reported with severity info, want low or above", s.Kind)
				}
			}
		})
	}
}

// TestAnalyzeURLSuspicions_Unparseable: a URL that cannot be parsed is a
// broken-link problem, handled elsewhere; it must not crash the detector.
func TestAnalyzeURLSuspicions_Unparseable(t *testing.T) {
	for _, u := range []string{"", "http://%zz/", "://nope", "ht tp://example.com"} {
		t.Run(u, func(t *testing.T) {
			_ = analyzeURLSuspicions(u) // must not panic
		})
	}
}

// TestIsURLShortener documents the finding backing the API's is_shortened
// flag: it means "this host is a public URL shortener", nothing else.
func TestIsURLShortener(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://bit.ly/abc", true},
		{"https://www.tinyurl.com/abc", true},
		{"https://example.com/abc", false},
		{"https://fr.r.emails.example.com/r/?id=x", false},
		{"https://192.0.2.10/abc", false},
		{"mailto:a@example.com", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := slices.ContainsFunc(analyzeURLSuspicions(tt.url), func(s URLSuspicion) bool {
				return s.Kind == URLSuspicionShortener
			})
			if got != tt.want {
				t.Errorf("isURLShortener(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// TestGenerateContentAnalysis_SuspiciousLinkIssues checks how findings surface
// in the API payload: one issue per reason, each with its own message, its own
// severity and the offending URL as location.
func TestGenerateContentAnalysis_SuspiciousLinkIssues(t *testing.T) {
	analyzer := NewContentAnalyzer(5 * time.Second)

	badURL := "http://bank.example.com@192.0.2.10/login"
	results := &ContentResults{
		HTMLContent: "<html><body></body></html>",
		Links: []LinkCheck{
			{URL: "https://fr.r.emails.example.com/r/?id=x", Valid: true, IsSafe: true, Status: 200},
			{URL: badURL, Valid: true, IsSafe: false, Status: 200, Suspicions: analyzeURLSuspicions(badURL)},
		},
	}

	analysis := analyzer.GenerateContentAnalysis(results)

	if analysis.HtmlIssues == nil {
		t.Fatal("expected suspicious_link issues, got none")
	}

	var suspicious []model.ContentIssue
	for _, issue := range *analysis.HtmlIssues {
		if issue.Type == model.ContentIssueTypeSuspiciousLink {
			suspicious = append(suspicious, issue)
		}
	}

	wantCount := len(results.Links[1].Suspicions)
	if len(suspicious) != wantCount {
		t.Fatalf("got %d suspicious_link issues, want %d (one per finding)", len(suspicious), wantCount)
	}

	messages := map[string]bool{}
	for _, issue := range suspicious {
		if issue.Location == nil || *issue.Location != badURL {
			t.Errorf("issue location = %v, want %q", issue.Location, badURL)
		}
		if issue.Advice == nil || strings.TrimSpace(*issue.Advice) == "" {
			t.Errorf("issue %q has no advice", issue.Message)
		}
		if messages[issue.Message] {
			t.Errorf("duplicate issue message %q", issue.Message)
		}
		messages[issue.Message] = true
	}
}

// TestGenerateContentAnalysis_CleanLinkHasNoIssue guards the regression that
// started all this: a legitimate ESP tracking link with several subdomains and
// a long encoded query must be reported as a plain valid link.
func TestGenerateContentAnalysis_CleanLinkHasNoIssue(t *testing.T) {
	analyzer := NewContentAnalyzer(5 * time.Second)

	cleanURL := "https://fr.r.emails.example.com/r/?id=h2f29daf0,adcbfc78,95c915a&e=ZW1sLXB1Ymxpc2hlcj1OZW9sYW5l&s=JaSedqApLxbMlohm"
	results := &ContentResults{
		HTMLContent: "<html><body></body></html>",
		Links:       []LinkCheck{{URL: cleanURL, Valid: true, IsSafe: true, Status: 200}},
	}

	analysis := analyzer.GenerateContentAnalysis(results)

	if analysis.HtmlIssues != nil {
		for _, issue := range *analysis.HtmlIssues {
			if issue.Type == model.ContentIssueTypeSuspiciousLink {
				t.Errorf("unexpected suspicious_link issue: %s", issue.Message)
			}
		}
	}

	if analysis.Links == nil || len(*analysis.Links) != 1 {
		t.Fatalf("expected 1 link, got %v", analysis.Links)
	}
	link := (*analysis.Links)[0]
	if link.Status != model.LinkCheckStatusValid {
		t.Errorf("link status = %q, want %q", link.Status, model.LinkCheckStatusValid)
	}
	if link.IsShortened == nil || *link.IsShortened {
		t.Errorf("is_shortened = %v, want false", link.IsShortened)
	}
}

// TestGenerateContentAnalysis_IsShortenedOnlyForShorteners: the API's
// is_shortened flag used to be set for any suspicious URL, which is how a long
// tracking link ended up advertised as a shortened one.
func TestGenerateContentAnalysis_IsShortenedOnlyForShorteners(t *testing.T) {
	analyzer := NewContentAnalyzer(5 * time.Second)

	tests := []struct {
		url  string
		want bool
	}{
		{"https://bit.ly/abc123", true},
		{"https://a.b.c.d.e.example.com/page", false},
		{"https://192.0.2.10/page", false},
		{"https://example.com/page", false},
	}

	links := make([]LinkCheck, 0, len(tests))
	for _, tt := range tests {
		suspicions := analyzeURLSuspicions(tt.url)
		links = append(links, LinkCheck{URL: tt.url, Valid: true, Status: 200, IsSafe: len(suspicions) == 0, Suspicions: suspicions})
	}

	analysis := analyzer.GenerateContentAnalysis(&ContentResults{HTMLContent: "<html></html>", Links: links})
	if analysis.Links == nil || len(*analysis.Links) != len(tests) {
		t.Fatalf("expected %d links, got %v", len(tests), analysis.Links)
	}

	for i, tt := range tests {
		got := (*analysis.Links)[i].IsShortened
		if got == nil || *got != tt.want {
			t.Errorf("is_shortened(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

// TestCalculateContentScore_SuspiciousLinksPenalty: suspicious links cost
// points, more for severe findings, and the penalty stays bounded.
func TestCalculateContentScore_SuspiciousLinksPenalty(t *testing.T) {
	analyzer := NewContentAnalyzer(5 * time.Second)

	base := func(links []LinkCheck) *ContentResults {
		return &ContentResults{
			IsMultipart:    true,
			HTMLValid:      true,
			HTMLContent:    "<html><body>Hello</body></html>",
			TextContent:    "Hello",
			HasUnsubscribe: true,
			TextPlainRatio: 1,
			Links:          links,
		}
	}

	cleanScore, _ := analyzer.CalculateContentScore(base([]LinkCheck{{URL: "https://example.com/", Valid: true, IsSafe: true}}))

	lowURL := "https://example.com:8443/"
	lowScore, _ := analyzer.CalculateContentScore(base([]LinkCheck{
		{URL: lowURL, Valid: true, Suspicions: analyzeURLSuspicions(lowURL)},
	}))

	highURL := "https://bank.example.com@192.0.2.10/login"
	highScore, _ := analyzer.CalculateContentScore(base([]LinkCheck{
		{URL: highURL, Valid: true, Suspicions: analyzeURLSuspicions(highURL)},
	}))

	if lowScore >= cleanScore {
		t.Errorf("score with a low-severity suspicious link = %d, want below the clean score %d", lowScore, cleanScore)
	}
	if highScore >= lowScore {
		t.Errorf("score with a high-severity suspicious link = %d, want below the low-severity score %d", highScore, lowScore)
	}
	if cleanScore-highScore > 10 {
		t.Errorf("penalty of %d points is unbounded, want at most 10", cleanScore-highScore)
	}
}

// TestURLShortenersDataIsSane guards the embedded shortener list against the
// malformed entries such a list tends to accumulate, and against a refresh
// silently importing junk: every key must be a plausible, lowercase, bare
// hostname (no scheme, no path, no port, no wildcard) with a real TLD, and the
// comment header must not leak into the data.
func TestURLShortenersDataIsSane(t *testing.T) {
	hostRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

	shorteners := urlShorteners()

	if len(shorteners) < 1000 {
		t.Errorf("only %d shorteners known, the embedded list looks truncated", len(shorteners))
	}

	for host := range shorteners {
		if !hostRegex.MatchString(host) {
			t.Errorf("shortener entry %q is not a plain lowercase hostname", host)
		}
		if strings.HasPrefix(host, "www.") {
			t.Errorf("shortener entry %q carries a www. prefix, which isShortenerHost strips before matching", host)
		}
	}

	// The overlay applied on top of the embedded list must take effect.
	for _, host := range extraShorteners {
		if _, ok := shorteners[host]; !ok {
			t.Errorf("locally added shortener %q is missing from the loaded list", host)
		}
	}
}

// TestThirdPartyNotices checks that the notices shipped in the binary carry
// everything CC-BY-SA-4.0 section 3(a)(1) asks for: the creators, a link to
// the licensed material, the license itself, and whether it was modified.
// Binary-only recipients get attribution through this text alone.
func TestThirdPartyNotices(t *testing.T) {
	notices := ThirdPartyNotices()

	required := []string{
		"PeterDave Hello",
		"https://github.com/PeterDaveHello/url-shorteners",
		"CC-BY-SA-4.0",
		"https://creativecommons.org/licenses/by-sa/4.0/",
		"Changes:",
		"Attribution-ShareAlike 4.0 International",
	}
	for _, want := range required {
		if !strings.Contains(notices, want) {
			t.Errorf("third-party notices are missing %q", want)
		}
	}

	// The full license text must be included, not just a link to it.
	if len(notices) < 5000 {
		t.Errorf("notices are only %d bytes long, the license text looks truncated", len(notices))
	}
}
