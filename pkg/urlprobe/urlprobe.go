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

// Package urlprobe fetches the URLs a message carries and reports what came
// back: the status, where the chain of redirections ended, and what went wrong
// when nothing did.
//
// It observes and it judges nothing. Whether a 404 on a link matters more than
// one on an image, how long a chain of redirections may be before it is worth
// reporting, and what a sender should do about either are readings of an
// email, and belong to whoever makes them.
//
// It refuses to fetch anything that is not on the public internet. The
// messages analysed are supplied by whoever asks for the analysis, so without
// that refusal this is a port scanner anyone can point at the network it runs
// in.
package urlprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.happydns.org/happyDeliver/internal/utils"
)

const (
	// userAgent identifies the analyzer to the servers it probes.
	userAgent = "happyDeliver/1.0 (Email Deliverability Tester)"
	// MaxRedirects is how many redirections a URL may walk through before
	// the probe gives up on it.
	MaxRedirects = 10
	// concurrency bounds the probes running at the same time. A
	// message carrying thirty links must not open thirty connections at once,
	// nor check them one after the other.
	concurrency = 6
	// bodyLimit caps what a probe reads of a response body. A server
	// that ignores the Range header answers with the whole document, which the
	// probe has no use for.
	bodyLimit = 4096
	// MaxURLs caps how many distinct URLs one message may have fetched.
	// The messages analysed are supplied by whoever wants them analysed, so the
	// work they can ask for has to be bounded; what is left out is reported
	// rather than passed off as checked.
	MaxURLs = 100
	// budget caps how long the whole fetching pass may take, however
	// many URLs it has left. Without it, a message full of links pointing at
	// servers that never answer holds an analysis for as long as they care to
	// stall it.
	budget = 60 * time.Second
)

// ErrPrivateTarget refuses a destination that is not on the public
// internet.
var ErrPrivateTarget = errors.New("destination address is not a public one")

// redirectTraceKey addresses the redirection trace carried by a probe's
// context.
type redirectTraceKey struct{}

// redirectTrace collects the URLs a single request was redirected through.
// One trace belongs to one Do call: net/http passes the original request's
// context to every follow-up request and calls CheckRedirect sequentially, so
// the slice is only ever touched by the goroutine that started the probe.
type redirectTrace struct {
	chain []string
}

var (
	errRedirectLoop     = errors.New("redirect loop: the destination sends the request back to a URL already visited")
	errTooManyRedirects = errors.New("too many redirects")
)

// withRedirectTrace attaches a fresh trace to ctx and returns both.
func withRedirectTrace(ctx context.Context) (context.Context, *redirectTrace) {
	trace := &redirectTrace{}
	return context.WithValue(ctx, redirectTraceKey{}, trace), trace
}

// traceRedirect is the http.Client CheckRedirect of the content analyzer. It
// records where each redirection leads before following it, and stops the
// request when the chain loops or runs too long. A request carrying no trace
// (anything else built on the same client) is simply followed as before.
func traceRedirect(req *http.Request, via []*http.Request) error {
	if trace, ok := req.Context().Value(redirectTraceKey{}).(*redirectTrace); ok {
		target := req.URL.String()
		if slices.Contains(trace.chain, target) {
			return errRedirectLoop
		}
		trace.chain = append(trace.chain, target)
	}

	if len(via) >= MaxRedirects {
		return errTooManyRedirects
	}

	return nil
}

// RedirectExhausted reports whether an error ends a chain of redirections
// rather than a connection. http.Client wraps CheckRedirect errors in a
// *url.Error, which unwraps to the sentinel.
func RedirectExhausted(err error) bool {
	return errors.Is(err, errRedirectLoop) || errors.Is(err, errTooManyRedirects)
}

// Answer is what one URL answered. It says nothing about what the URL was
// found as: the same result describes a link, an image source or an
// unsubscribe endpoint, which is what lets a URL appearing as several of them
// be fetched once.
type Answer struct {
	// Status is the code of the final response, or 0 when none was received.
	Status int
	// Method is the HTTP method that produced Status.
	Method string
	// FinalURL is where the chain ended, redirections included.
	FinalURL string
	// RedirectChain lists the URLs walked through, in order, excluding the one
	// the probe started from.
	RedirectChain []string
	// Err is the transport or redirection error, if any.
	Err error
}

// Prober fetches URLs, one message's worth at a time.
//
// It is safe for concurrent use and holds nothing about any particular
// message: one prober serves every analysis running at once, as the
// http.Client inside it is meant to be.
type Prober struct {
	// Timeout bounds one request, redirections included.
	Timeout time.Duration

	// AllowPrivateTargets lifts the refusal to fetch an address that is not on
	// the public internet. It exists for the tests, which serve their fixtures
	// from a loopback address; nothing else sets it.
	AllowPrivateTargets bool

	client *http.Client
}

// New returns a prober whose every request is bounded by timeout.
func New(timeout time.Duration) *Prober {
	prober := &Prober{Timeout: timeout}
	prober.client = &http.Client{
		Timeout:       timeout,
		CheckRedirect: traceRedirect,
		Transport:     prober.transport(),
	}

	return prober
}

// UseTransport replaces what the prober dials through. It exists for the tests
// that must confine a probe to one host, the refusal to leave the public
// internet being what they are there to exercise; nothing else calls it.
func (p *Prober) UseTransport(transport http.RoundTripper) {
	p.client.Transport = transport
}

// Options tunes a probe for what the URL is.
type Options struct {
	// NoGETFallback keeps the probe to a single HEAD. It is set for
	// unsubscribe endpoints: a GET on one of them may unsubscribe the
	// recipient for real, which the analyzer must never do.
	NoGETFallback bool
}

// Request pairs a URL with the options it must be probed under.
type Request struct {
	URL  string
	Opts Options
}

// transport builds the transport the analyzer fetches URLs with. Its
// dialer refuses any address that is not on the public internet.
//
// The check sits on the dial rather than on the URL because the URL cannot be
// trusted to name what it resolves to: a hostname whose A record answers
// 127.0.0.1 reads as an ordinary domain. Dialing is also the only place that
// sees every hop of a redirection chain, and the cloud metadata services a
// redirection would otherwise reach (169.254.169.254 and its kin) are
// link-local addresses that never survive it.
//
// Messages are supplied by whoever asks for an analysis, so without this the
// analyzer is a port scanner anyone can point at the network it runs in, with
// the status codes handed back in the report.
func (p *Prober) transport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if p.AllowPrivateTargets {
				return nil
			}

			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrPrivateTarget, address)
			}

			// Control runs once the name has been resolved, so host is the
			// literal address about to be connected to.
			if !utils.IsPublicIPAddr(host) {
				return fmt.Errorf("%w: %s", ErrPrivateTarget, host)
			}

			return nil
		},
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext

	// The cloned transport reads HTTP_PROXY and friends. A proxy would be the
	// address dialled, so the guard above would vet the proxy instead of the
	// target, and the proxy would happily fetch the private address for us.
	transport.Proxy = nil

	return transport
}

// Probeable reports whether a URL designates something the analyzer can
// fetch. Opaque schemes (mailto:, tel:), inline images (data:), attached ones
// (cid:) and relative links designate no destination to reach.
func Probeable(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}

	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

// Probe fetches every request concurrently, bounded by
// concurrency, and returns the result of each URL. Callers hand it
// distinct URLs, so a URL written twenty times in a message is fetched once.
func (p *Prober) Probe(ctx context.Context, requests []Request) map[string]Answer {
	probes := make([]Answer, len(requests))

	slots := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, request := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()

			slots <- struct{}{}
			defer func() { <-slots }()

			probes[i] = p.probeOne(ctx, request.URL, request.Opts)
		}()
	}
	wg.Wait()

	results := make(map[string]Answer, len(requests))
	for i, request := range requests {
		results[request.URL] = probes[i]
	}

	return results
}

// probeOne fetches one URL. It asks for the headers alone, and only falls back
// to a GET when the server refuses the HEAD itself: a fair number of them
// answer 403, 405 or 501 to a method they simply do not implement, and
// reporting those as a dead link would blame the sender for a page that works.
func (p *Prober) probeOne(ctx context.Context, urlStr string, opts Options) Answer {
	probe := p.probeOnce(ctx, http.MethodHead, urlStr, false)

	if probe.Err != nil || opts.NoGETFallback {
		return probe
	}

	switch probe.Status {
	case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		fallback := p.probeOnce(ctx, http.MethodGet, urlStr, true)

		// A server may refuse the byte range instead of the document. The
		// resource is there; only the way it was asked for was not, so the
		// question is put again without the range rather than recorded as a
		// dead link.
		if fallback.Status == http.StatusRequestedRangeNotSatisfiable {
			fallback = p.probeOnce(ctx, http.MethodGet, urlStr, false)
		}

		if fallback.Err == nil {
			return fallback
		}
	}

	return probe
}

// probeOnce issues a single request and reports what came back.
func (p *Prober) probeOnce(ctx context.Context, method, urlStr string, byteRange bool) Answer {
	probe := Answer{Method: method}

	// Each probe gets its own budget: a slow HEAD must not leave the GET
	// fallback with nothing to spend. The budget of the whole pass still
	// applies, since ctx carries its deadline.
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	ctx, trace := withRedirectTrace(ctx)

	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		probe.Err = err
		return probe
	}

	req.Header.Set("User-Agent", userAgent)
	if byteRange {
		// The probe needs the status line, not the document.
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := p.client.Do(req)

	// The chain is worth keeping even when the request ended in an error: it
	// is what says the redirections looped.
	probe.RedirectChain = trace.chain

	if err != nil {
		probe.Err = err
		return probe
	}
	defer resp.Body.Close()

	// A server ignoring the Range header answers with the whole document.
	// Reading a bounded prefix lets the connection go back to the pool without
	// downloading it.
	io.Copy(io.Discard, io.LimitReader(resp.Body, bodyLimit))

	probe.Status = resp.StatusCode
	probe.FinalURL = resp.Request.URL.String()

	return probe
}
