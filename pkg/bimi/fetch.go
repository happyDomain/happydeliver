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

package bimi

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultFetchTimeout bounds a single asset download. It is deliberately
// unrelated to the DNS lookup budget: pulling a file from a slow host is not
// the same wait as a TXT query.
const DefaultFetchTimeout = 30 * time.Second

// NewHTTPClient returns the HTTP client BIMI assets must be fetched with. The
// URLs come from the l= and a= tags of a TXT record the analysed domain
// controls, so the client refuses to connect to a non-public address and to
// follow a redirect away from HTTPS. A timeout of zero or less means
// DefaultFetchTimeout.
//
// It is exported because Validator.HTTPClient is: a caller that needs its own
// transport settings should start from this client rather than from a bare one,
// which would leave the fetches unguarded.
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}

	// Cloned rather than built from scratch: a bare Transport would drop the
	// idle connection reaping and the handshake deadlines DefaultTransport
	// configures, which a long-lived client contacting one host per analysed
	// domain needs.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = safeDialContext

	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: rejectInsecureRedirect,
	}
}

// nonPublicNets lists the address ranges that are not routable on the public
// Internet but that the net.IP predicates used by isPublicIP do not report:
// IsPrivate only covers RFC 1918 and the IPv6 unique local addresses.
var nonPublicNets = parseCIDRs(
	"100.64.0.0/10", // shared address space (CGNAT), RFC 6598
	"192.0.0.0/24",  // IETF protocol assignments, RFC 6890
	"198.18.0.0/15", // benchmarking, RFC 2544
	"240.0.0.0/4",   // reserved for future use, RFC 1112
	"64:ff9b::/96",  // NAT64: the last 32 bits are an arbitrary IPv4 address
)

// parseCIDRs turns the prefixes into networks, panicking on a malformed one.
// It is only ever called with the constants above, so a failure is a typo the
// package must not start with.
func parseCIDRs(prefixes ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		_, n, err := net.ParseCIDR(prefix)
		if err != nil {
			panic("bimi: malformed non-public prefix " + prefix + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}

// isPublicIP reports whether ip is routable on the public Internet. Everything
// else is refused: loopback, link-local, multicast, broadcast and unspecified
// addresses through IsGlobalUnicast, private ones through IsPrivate, and the
// ranges net.IP has no predicate for through nonPublicNets. The CGNAT range
// matters as much as the RFC 1918 ones here: hosts behind a carrier-grade NAT,
// or on a Tailscale tailnet, reach their internal services through it.
func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// safeDialContext is used as the Transport's DialContext for BIMI asset
// fetches. The URLs fetched (l= and a= tags) are attacker-controlled via DNS,
// so every resolved address is checked against isPublicIP before connecting,
// preventing SSRF against internal/link-local/loopback services. The check is
// done at dial time, on the addresses actually connected to, so it also
// covers redirect targets and is not subject to a DNS-rebinding TOCTOU gap.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	var lastErr error
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			lastErr = fmt.Errorf("refusing to connect to non-public address %s", ip.IP)
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses found for %s", host)
	}
	return nil, lastErr
}

// maxRedirects mirrors the cap the net/http package applies by default. That
// default lives in its own CheckRedirect function, which setting ours replaces,
// so the cap has to be restored here.
const maxRedirects = 10

// rejectInsecureRedirect stops the HTTP client from following a redirect to
// a non-HTTPS URL. fetchFile only checks the scheme of the initial URL; the
// client otherwise follows redirects transparently, which would let a
// malicious https:// URL bounce the request to a plain http:// (or
// internal-only) target. It also bounds the redirect chain, so a URL redirecting
// to itself cannot keep a report waiting until the client timeout fires.
func rejectInsecureRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("refusing to follow redirect to non-HTTPS URL %q", req.URL)
	}
	return nil
}

func (v *Validator) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return http.DefaultClient
}

// fetchedFile is what a fetchFile call returned, so that a download started
// ahead of time can be carried to the code that consumes it.
type fetchedFile struct {
	content     []byte
	contentType string
	problems    []string
}

// fetchAsync starts a fetchFile in the background and hands back the channel
// its single result will arrive on. The channel is buffered: the fetch
// completes and the goroutine exits even if nobody ever reads it.
func (v *Validator) fetchAsync(ctx context.Context, fileURL string, maxSize int64) <-chan fetchedFile {
	done := make(chan fetchedFile, 1)
	go func() {
		content, contentType, problems := v.fetchFile(ctx, fileURL, maxSize)
		done <- fetchedFile{content: content, contentType: contentType, problems: problems}
	}()
	return done
}

// fetchFile downloads a file referenced by a BIMI record and validates
// transport requirements (HTTPS, reachability, size). It returns the file
// content, the media type announced by the server and the list of problems
// encountered (empty when the fetch is acceptable).
func (v *Validator) fetchFile(ctx context.Context, fileURL string, maxSize int64) (content []byte, contentType string, problems []string) {
	u, err := url.Parse(fileURL)
	if err != nil {
		return nil, "", []string{fmt.Sprintf("Invalid URL: %s", err)}
	}

	if !strings.EqualFold(u.Scheme, "https") {
		problems = append(problems, fmt.Sprintf("URL uses %q scheme: BIMI requires files to be served over HTTPS", u.Scheme))
		return nil, "", problems
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, "", []string{fmt.Sprintf("Invalid URL: %s", err)}
	}

	resp, err := v.httpClient().Do(req)
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
