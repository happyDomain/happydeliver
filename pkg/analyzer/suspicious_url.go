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
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"

	"git.happydns.org/happyDeliver/internal/model"
)

// URLSuspicionKind identifies why a URL was flagged. Each kind describes one
// precise, explainable problem.
type URLSuspicionKind string

const (
	// URLSuspicionShortener: the host is a public URL shortening service, so
	// the real destination is invisible to the recipient (and to filters).
	URLSuspicionShortener URLSuspicionKind = "shortener"
	// URLSuspicionIPHost: the host is a literal IP address instead of a name.
	URLSuspicionIPHost URLSuspicionKind = "ip_host"
	// URLSuspicionObfuscatedIPHost: the host is an IP address written in a
	// non-dotted-quad notation (decimal, hexadecimal, zero-padded octal, or
	// fewer than four parts).
	URLSuspicionObfuscatedIPHost URLSuspicionKind = "obfuscated_ip_host"
	// URLSuspicionUserInfo: the authority carries a "user[:password]@" part,
	// which pushes the real host out of sight behind the "@".
	URLSuspicionUserInfo URLSuspicionKind = "userinfo"
	// URLSuspicionDangerousScheme: the scheme executes code or inlines a
	// document (javascript:, data:, vbscript:, file:).
	URLSuspicionDangerousScheme URLSuspicionKind = "dangerous_scheme"
	// URLSuspicionEncodedHost: the hostname itself contains percent-escapes,
	// characters that cannot appear in a hostname, or a stray colon.
	URLSuspicionEncodedHost URLSuspicionKind = "encoded_host"
	// URLSuspicionNonStandardPort: the URL targets a port other than 80/443.
	URLSuspicionNonStandardPort URLSuspicionKind = "non_standard_port"
	// URLSuspicionDeceptiveHost: the host embeds a generic TLD label in the
	// middle ("bank.example.com.login.example") so that its beginning reads
	// like another domain.
	URLSuspicionDeceptiveHost URLSuspicionKind = "deceptive_host"
	// URLSuspicionDomainMisalignment: the link text advertises a domain that
	// is not the one the link actually goes to.
	URLSuspicionDomainMisalignment URLSuspicionKind = "domain_misalignment"
)

// URLSuspicion is one specific reason a URL was flagged, with the message and
// the advice shown to the user.
type URLSuspicion struct {
	Kind     URLSuspicionKind
	Severity model.ContentIssueSeverity
	Message  string
	Advice   string
}

// dangerousSchemes are URL schemes that do not designate a destination but run
// code or inline a document in the mail client or browser.
var dangerousSchemes = []string{"javascript", "data", "vbscript", "file"}

// genericTLDLabels are the TLD labels a phishing host typically embeds in the
// middle of its name to make its beginning look like a legitimate domain.
var genericTLDLabels = []string{"com", "net", "org"}

// analyzeURLSuspicions reports every concrete reason the given URL should be
// considered suspicious in an email. It returns nil for the overwhelming
// majority of URLs: an ordinary link, however long its query string or however
// many subdomains its host has, is not suspicious.
//
// The URL is examined textually rather than through net/url alone, because the
// obfuscation techniques worth catching (percent-escaped hostnames especially)
// make the URL unparseable in the first place.
func analyzeURLSuspicions(rawURL string) []URLSuspicion {
	var suspicions []URLSuspicion

	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}

	scheme, rest := splitScheme(rawURL)

	if slices.Contains(dangerousSchemes, scheme) {
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionDangerousScheme,
			Severity: model.ContentIssueSeverityCritical,
			Message:  fmt.Sprintf("Link uses the %q scheme, which runs code or inlines content instead of pointing to a destination", scheme+":"),
			Advice:   "Only use http: or https: links (plus mailto: and tel:) in emails; active schemes are blocked by mail clients and treated as an attack",
		})
	}

	// Everything below inspects the authority, which only exists for
	// "scheme://authority/..." URLs. Opaque URLs (mailto:, tel:, cid:, ...)
	// and relative links have none, and nothing else about them is suspicious.
	//
	// http: and https: are an exception: browsers and mail clients accept any
	// number of slashes after them, so "https:evil.example/login" and
	// "https:/evil.example/login" both go to evil.example. Dropping a slash
	// must not be a way to slip past every host check below.
	switch {
	case strings.HasPrefix(rest, "//"), scheme == "http", scheme == "https":
	default:
		return suspicions
	}
	authority := strings.TrimLeft(rest, "/")
	if idx := strings.IndexAny(authority, "/?#"); idx != -1 {
		authority = authority[:idx]
	}
	if authority == "" {
		return suspicions
	}

	hostPort := authority
	if idx := strings.LastIndex(authority, "@"); idx != -1 {
		hostPort = authority[idx+1:]
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionUserInfo,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Link hides its real destination behind credentials: everything before the \"@\" is ignored, the browser goes to %q", hostName(hostPort)),
			Advice:   "Remove the \"user@\" part from the URL: it is a classic phishing trick and mail filters treat it as one",
		})
	}

	host, port := splitHostPort(hostPort)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return suspicions
	}

	switch {
	case strings.Contains(host, "%"):
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionEncodedHost,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Hostname %q contains percent-escapes, which hide the domain the link really goes to", host),
			Advice:   "Write the hostname in plain form; percent-escaping a hostname has no legitimate use and is a well-known obfuscation technique",
		})
	case strings.ContainsAny(host, `()[]<>"'\ `):
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionEncodedHost,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Hostname %q contains characters that cannot appear in a domain name", host),
			Advice:   "Check the link: a hostname is made of letters, digits, hyphens and dots only",
		})
	case strings.Contains(host, ":") && net.ParseIP(host) == nil:
		// A colon left in the host means the authority is neither "host:port"
		// (the port would be numeric) nor a bracketed IPv6 literal.
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionEncodedHost,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Hostname %q is malformed: the \":\" is neither a port separator nor part of a bracketed IPv6 address", host),
			Advice:   "Write the authority as \"host\", \"host:port\" with a numeric port, or \"[ipv6]:port\" with brackets around the address",
		})
	}

	switch {
	case isObfuscatedIPHost(host):
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionObfuscatedIPHost,
			Severity: model.ContentIssueSeverityHigh,
			Message:  fmt.Sprintf("Hostname %q is an IP address written in a notation that hides it (decimal, hexadecimal, octal, or fewer than four parts)", host),
			Advice:   "Link to a domain name; an IP address disguised this way is used to evade filters and has no place in a legitimate email",
		})
	case net.ParseIP(host) != nil:
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionIPHost,
			Severity: model.ContentIssueSeverityMedium,
			Message:  fmt.Sprintf("Link points to the IP address %s instead of a domain name", host),
			Advice:   "Use a domain name covered by your TLS certificate: links to raw IP addresses are a strong spam and phishing signal",
		})
	}

	if isShortenerHost(host) {
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionShortener,
			Severity: model.ContentIssueSeverityLow,
			Message:  fmt.Sprintf("Link goes through the URL shortener %q, so the recipient cannot see where it leads", host),
			Advice:   "Link directly to your own domain (a branded click-tracking domain is fine); public shorteners are heavily abused and penalised by filters",
		})
	}

	if isDeceptiveHost(host) {
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionDeceptiveHost,
			Severity: model.ContentIssueSeverityMedium,
			Message:  fmt.Sprintf("Hostname %q embeds a top-level domain in the middle of its name, making it read like a different domain than the one it belongs to", host),
			Advice:   "Avoid host names containing labels such as \".com.\" or \".net.\" before the real domain: they are typical of phishing look-alikes",
		})
	}

	if port != "" && port != "80" && port != "443" {
		suspicions = append(suspicions, URLSuspicion{
			Kind:     URLSuspicionNonStandardPort,
			Severity: model.ContentIssueSeverityLow,
			Message:  fmt.Sprintf("Link targets the non-standard port %s", port),
			Advice:   "Serve email links on the standard ports 80/443: other ports are unusual, blocked on many networks and flagged by filters",
		})
	}

	return suspicions
}

// splitScheme splits "scheme:rest" into its lowercased scheme and the rest of
// the URL. It returns an empty scheme when the URL has none (relative links,
// fragments), leaving the whole input as the rest.
func splitScheme(rawURL string) (scheme, rest string) {
	idx := strings.Index(rawURL, ":")
	if idx <= 0 {
		return "", rawURL
	}
	for i, r := range rawURL[:idx] {
		valid := unicode.IsLetter(r) || (i > 0 && (unicode.IsDigit(r) || r == '+' || r == '-' || r == '.'))
		if !valid {
			return "", rawURL
		}
	}
	return strings.ToLower(rawURL[:idx]), rawURL[idx+1:]
}

// splitHostPort splits a "host:port" authority, handling bracketed IPv6
// literals. The port is empty when none is given, and what follows the colon
// is only taken for a port when it is numeric or empty ("example.com:" is a
// valid URL meaning the default port): everything else belongs to the host, so
// that an unbracketed IPv6 literal ("2001:db8::1") is not cut into a
// nonsensical host and port.
func splitHostPort(hostPort string) (host, port string) {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end != -1 {
			host = hostPort[1:end]
			if rest := hostPort[end+1:]; strings.HasPrefix(rest, ":") && isPort(rest[1:]) {
				port = rest[1:]
			}
			return host, port
		}
	}
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 && (hostPort[idx+1:] == "" || isPort(hostPort[idx+1:])) {
		// More than one colon: an unbracketed IPv6 literal, whose last group
		// happens to look like a port. It is the whole host.
		if strings.Contains(hostPort[:idx], ":") {
			return hostPort, ""
		}
		return hostPort[:idx], hostPort[idx+1:]
	}
	return hostPort, ""
}

// isPort reports whether s is a syntactically valid, non-empty port number.
func isPort(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

// hostName returns the host part of an authority, for use in messages.
func hostName(hostPort string) string {
	host, _ := splitHostPort(hostPort)
	return strings.ToLower(host)
}

// isShortenerHost reports whether a bare (lowercased) host is a known public
// shortener, allowing an optional "www." prefix.
func isShortenerHost(host string) bool {
	_, ok := urlShorteners()[normalizeShortenerHost(host)]
	return ok
}

// isObfuscatedIPHost reports whether a host is an IPv4 address written in one
// of the notations browsers and resolvers accept but humans do not read as an
// address: a single decimal integer ("3221225994"), a hexadecimal literal
// ("0xC000020A" or "0xc0.0x00.0x02.0x0a"), zero-padded octal groups
// ("0300.0000.0002.0012"), a mix of them ("192.0x00.2.10"), or fewer than four
// parts ("192.11.1"). The plain dotted-quad is excluded: it is a legible
// address, reported as a literal IP host instead.
func isObfuscatedIPHost(host string) bool {
	if !isLegacyIPv4(host) {
		return false
	}
	// A dotted-quad in plain decimal reads as an address to anyone; anything
	// else parsing as an address does not.
	return net.ParseIP(host) == nil
}

// isLegacyIPv4 reports whether the host is an IPv4 address in any of the
// notations inet_aton accepts, which is what browsers implement: one to four
// parts, each in decimal, hexadecimal ("0x2a") or octal ("052"), the last part
// absorbing every byte the earlier parts did not cover.
func isLegacyIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return false
	}

	for i, part := range parts {
		value, ok := parseIPv4Part(part)
		if !ok {
			return false
		}

		// Only the last part absorbs the remaining bytes; the others are one
		// byte each. A value too large for its slot means this is not an
		// address at all ("99999999999999" is nobody's host).
		bits := 8
		if i == len(parts)-1 {
			bits = 8 * (5 - len(parts))
		}
		if value >= 1<<bits {
			return false
		}
	}

	return true
}

// parseIPv4Part parses one part of a legacy IPv4 address, in the base its
// prefix announces: "0x" for hexadecimal, a leading "0" for octal, decimal
// otherwise. The prefix is matched case-insensitively, as inet_aton does: the
// caller happens to lowercase the host first, but the base a part is written in
// must not depend on that.
func parseIPv4Part(part string) (uint64, bool) {
	base := 10
	digits := part

	switch {
	case len(part) > 1 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
		base, digits = 16, part[2:]
	case len(part) > 1 && part[0] == '0':
		base, digits = 8, part[1:]
	}

	if digits == "" {
		return 0, false
	}

	value, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// isDeceptiveHost reports whether the host reads like another domain because a
// generic TLD label sits inside its subdomains, as in
// "bank.example.com.login.example": the name begins with what looks like a
// complete domain, while the domain it really belongs to is further right.
//
// The public suffix list decides where the subdomains stop, because the label
// alone cannot: in "www2.gov.bc.ca" the "gov" is part of the registrable
// domain "gov.bc.ca", not a decoy. The generic label must also be preceded by
// another subdomain label, since a host merely starting with "org." or "net."
// ("org.example.com") pretends to be nothing.
func isDeceptiveHost(host string) bool {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// No registrable domain: an IP address or a single label, both
		// reported by other checks when they deserve it.
		return false
	}

	subdomains := strings.TrimSuffix(host, registrable)
	labels := strings.Split(strings.TrimSuffix(subdomains, "."), ".")

	for i, label := range labels {
		if i > 0 && slices.Contains(genericTLDLabels, label) {
			return true
		}
	}
	return false
}
