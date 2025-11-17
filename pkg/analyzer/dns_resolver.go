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
	"net"
)

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
