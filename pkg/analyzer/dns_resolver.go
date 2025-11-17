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
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"
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

// StandardDNSResolver is the default DNS resolver implementation that uses goresolver with DNSSEC validation.
type StandardDNSResolver struct {
	resolver *goresolver.Resolver
}

// NewStandardDNSResolver creates a new StandardDNSResolver with DNSSEC validation support.
func NewStandardDNSResolver() DNSResolver {
	// Pass /etc/resolv.conf to load default DNS configuration
	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	if err != nil {
		panic(fmt.Sprintf("failed to initialize goresolver: %v", err))
	}

	return &StandardDNSResolver{
		resolver: resolver,
	}
}

// LookupMX implements DNSResolver.LookupMX using goresolver with DNSSEC validation.
func (r *StandardDNSResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	// Ensure the name ends with a dot for DNS queries
	queryName := name
	if !strings.HasSuffix(queryName, ".") {
		queryName = queryName + "."
	}

	rrs, err := r.resolver.StrictNSQuery(queryName, dns.TypeMX)
	if err != nil {
		return nil, err
	}

	mxRecords := make([]*net.MX, 0, len(rrs))
	for _, rr := range rrs {
		if mx, ok := rr.(*dns.MX); ok {
			mxRecords = append(mxRecords, &net.MX{
				Host: strings.TrimSuffix(mx.Mx, "."),
				Pref: mx.Preference,
			})
		}
	}

	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no MX records found for %s", name)
	}

	return mxRecords, nil
}

// LookupTXT implements DNSResolver.LookupTXT using goresolver with DNSSEC validation.
func (r *StandardDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	// Ensure the name ends with a dot for DNS queries
	queryName := name
	if !strings.HasSuffix(queryName, ".") {
		queryName = queryName + "."
	}

	rrs, err := r.resolver.StrictNSQuery(queryName, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	txtRecords := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			// Join all TXT strings (a single TXT record can have multiple strings)
			txtRecords = append(txtRecords, strings.Join(txt.Txt, ""))
		}
	}

	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no TXT records found for %s", name)
	}

	return txtRecords, nil
}

// LookupAddr implements DNSResolver.LookupAddr using goresolver with DNSSEC validation.
func (r *StandardDNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	// Convert IP address to reverse DNS name (e.g., 1.0.0.127.in-addr.arpa.)
	arpa, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	rrs, err := r.resolver.StrictNSQuery(arpa, dns.TypePTR)
	if err != nil {
		return nil, err
	}

	ptrRecords := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if ptr, ok := rr.(*dns.PTR); ok {
			ptrRecords = append(ptrRecords, strings.TrimSuffix(ptr.Ptr, "."))
		}
	}

	if len(ptrRecords) == 0 {
		return nil, fmt.Errorf("no PTR records found for %s", addr)
	}

	return ptrRecords, nil
}

// LookupHost implements DNSResolver.LookupHost using goresolver with DNSSEC validation.
func (r *StandardDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// Ensure the host ends with a dot for DNS queries
	queryName := host
	if !strings.HasSuffix(queryName, ".") {
		queryName = queryName + "."
	}

	var allAddrs []string

	// Query A records (IPv4)
	rrsA, errA := r.resolver.StrictNSQuery(queryName, dns.TypeA)
	if errA == nil {
		for _, rr := range rrsA {
			if a, ok := rr.(*dns.A); ok {
				allAddrs = append(allAddrs, a.A.String())
			}
		}
	}

	// Query AAAA records (IPv6)
	rrsAAAA, errAAAA := r.resolver.StrictNSQuery(queryName, dns.TypeAAAA)
	if errAAAA == nil {
		for _, rr := range rrsAAAA {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				allAddrs = append(allAddrs, aaaa.AAAA.String())
			}
		}
	}

	// Return error only if both queries failed
	if errA != nil && errAAAA != nil {
		return nil, fmt.Errorf("failed to resolve host: IPv4 error: %v, IPv6 error: %v", errA, errAAAA)
	}

	if len(allAddrs) == 0 {
		return nil, fmt.Errorf("no A or AAAA records found for %s", host)
	}

	return allAddrs, nil
}
