// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
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
	"context"
	"errors"
	"net"
	"strings"
)

// formatDNSError renders a resolution error without exposing the upstream
// resolver address that net.DNSError.Error() normally appends as " on <addr>".
func formatDNSError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		sanitized := *dnsErr
		sanitized.Server = ""
		return sanitized.Error()
	}
	return err.Error()
}

// leadingVersion returns the value of a record's leading "v=" tag (up to the
// first ';' or whitespace), or "" if the record does not start with one. It
// handles both ';'-delimited records (BIMI/DKIM/DMARC) and space-delimited
// ones (SPF).
func leadingVersion(record string) string {
	r := strings.TrimSpace(record)
	if !strings.HasPrefix(r, "v=") {
		return ""
	}
	v := r[len("v="):]
	if i := strings.IndexAny(v, "; \t"); i >= 0 {
		v = v[:i]
	}
	return v
}

// describeMisplacedRecord returns a human-readable description ("a DMARC
// record", "an SPF record", …) of a record identified by its "v=" version
// value, or "" when the version is unknown. It is used to explain the common
// misconfiguration (or misbehaving resolver) where a record of the wrong type
// is served at a BIMI/DKIM/SPF location.
//
// ownFamily names the record type expected at the caller's location (e.g.
// "DKIM" for a DKIM lookup). A record whose version belongs to that family
// (an unsupported-version record of the location's own type, such as a
// "v=DKIM2" at the DKIM location) is not "misplaced", so "" is returned and
// the caller falls back to its generic message.
func describeMisplacedRecord(version, ownFamily string) string {
	v := strings.ToUpper(version)
	if ownFamily != "" && strings.HasPrefix(v, strings.ToUpper(ownFamily)) {
		return ""
	}
	switch {
	case strings.HasPrefix(v, "DMARC"):
		return "a DMARC record"
	case strings.HasPrefix(v, "SPF"):
		return "an SPF record"
	case strings.HasPrefix(v, "DKIM"):
		return "a DKIM record"
	case strings.HasPrefix(v, "BIMI"):
		return "a BIMI record"
	default:
		return ""
	}
}

// DNSResolver defines the interface for DNS resolution operations.
// This interface abstracts DNS lookups to allow for custom implementations,
// such as mock resolvers for testing or caching resolvers for performance.
type DNSResolver interface {
	// LookupMX returns the DNS MX records for the given domain.
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)

	// LookupTXT returns the DNS TXT records for the given domain.
	LookupTXT(ctx context.Context, name string) ([]string, error)

	// LookupAddr performs a reverse lookup for the given IP address,
	// returning a list of hostnames mapping to that address.
	LookupAddr(ctx context.Context, addr string) ([]string, error)

	// LookupHost looks up the given hostname using the local resolver.
	// It returns a slice of that host's addresses (IPv4 and IPv6).
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// StandardDNSResolver is the default DNS resolver implementation that uses net.Resolver.
type StandardDNSResolver struct {
	resolver *net.Resolver
}

// NewStandardDNSResolver creates a new StandardDNSResolver with default settings.
func NewStandardDNSResolver() DNSResolver {
	return &StandardDNSResolver{
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// LookupMX implements DNSResolver.LookupMX using net.Resolver.
func (r *StandardDNSResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, name)
}

// LookupTXT implements DNSResolver.LookupTXT using net.Resolver.
func (r *StandardDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}

// LookupAddr implements DNSResolver.LookupAddr using net.Resolver.
func (r *StandardDNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return r.resolver.LookupAddr(ctx, addr)
}

// LookupHost implements DNSResolver.LookupHost using net.Resolver.
func (r *StandardDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.resolver.LookupHost(ctx, host)
}
