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

// Package relay proxies SMTP from an MTA that already owns port 25 to the
// local MTA bundled with happyDeliver, translating the XFORWARD command the
// upstream Postfix knows how to send into the XCLIENT command the local
// Postfix needs in order to *impersonate* the original client. That
// distinction is the whole point of this package: XFORWARD only fixes
// logging, while XCLIENT also fixes what the authentication milters see, so
// SPF, IPRev, PTR and DMARC keep being evaluated against the real sender.
//
// The tests below drive a relay whose upstream is a scripted fake MTA that
// records every command it receives, so each test asserts on the exact
// command sequence the local MTA would have seen.
package relay

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/config"
)

// fakeUpstream is a scripted SMTP server standing in for the local Postfix.
// It records every command line it receives (DATA payload excluded, which
// goes to messages instead).
type fakeUpstream struct {
	addr string
	ln   net.Listener

	// refuseXCLIENT makes the fake MTA reject impersonation, standing in
	// for a local Postfix without smtpd_authorized_xclient_hosts.
	refuseXCLIENT bool

	mu       sync.Mutex
	commands []string
	messages []string
}

// upstreamEHLO is the capability set the fake local MTA advertises. It
// deliberately contains both STARTTLS (which the relay must not pass on,
// since the relay itself speaks plaintext) and XCLIENT (which the relay
// consumes rather than exposing to its own client).
var upstreamEHLO = []string{
	"250-upstream.example.com",
	"250-PIPELINING",
	"250-SIZE 10485760",
	"250-STARTTLS",
	"250-XCLIENT NAME ADDR PORT PROTO HELO",
	"250 8BITMIME",
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}

	u := &fakeUpstream{addr: ln.Addr().String(), ln: ln}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go u.handle(conn)
		}
	}()

	return u
}

func (u *fakeUpstream) record(line string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.commands = append(u.commands, line)
}

// Commands returns a copy of the recorded command lines.
func (u *fakeUpstream) Commands() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.commands...)
}

// Verbs returns the recorded commands reduced to their first word, uppercased.
func (u *fakeUpstream) Verbs() []string {
	verbs := []string{}
	for _, cmd := range u.Commands() {
		verbs = append(verbs, strings.ToUpper(strings.Fields(cmd + " ")[0]))
	}
	return verbs
}

// LastCommandWithVerb returns the most recent recorded command starting with
// verb, and whether one was found.
func (u *fakeUpstream) LastCommandWithVerb(verb string) (string, bool) {
	cmds := u.Commands()
	for i := len(cmds) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.ToUpper(cmds[i]), verb) {
			return cmds[i], true
		}
	}
	return "", false
}

func (u *fakeUpstream) handle(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	write := func(lines ...string) {
		for _, line := range lines {
			fmt.Fprintf(w, "%s\r\n", line)
		}
		w.Flush()
	}

	write("220 upstream.example.com ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		u.record(line)

		verb := strings.ToUpper(strings.Fields(line + " ")[0])
		switch verb {
		case "EHLO":
			write(upstreamEHLO...)
		case "HELO":
			write("250 upstream.example.com")
		case "XCLIENT":
			if u.refuseXCLIENT {
				write("550 5.7.0 XCLIENT command rejected")
				break
			}
			// XCLIENT resets the session: the server replies with a
			// fresh greeting and expects a new EHLO.
			write("220 upstream.example.com ESMTP")
		case "MAIL", "RCPT", "RSET", "NOOP":
			write("250 2.0.0 Ok")
		case "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				body.WriteString(dl)
			}
			u.mu.Lock()
			u.messages = append(u.messages, body.String())
			u.mu.Unlock()
			write("250 2.0.0 Ok: queued")
		case "QUIT":
			write("221 2.0.0 Bye")
			return
		default:
			write("502 5.5.2 Error: command not recognized")
		}
	}
}

// startRelay boots a relay in front of a fake upstream and returns its
// address. trustedNets is passed through to the configuration as-is.
func startRelay(t *testing.T, trustedNets []string) (string, *fakeUpstream) {
	t.Helper()

	upstream := newFakeUpstream(t)

	cfg := config.DefaultConfig()
	cfg.Email.RelayAddr = "127.0.0.1:0"
	cfg.Email.RelayUpstream = upstream.addr
	cfg.Email.RelayTrustedNets = trustedNets

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go srv.Serve(ln)

	return ln.Addr().String(), upstream
}

// client is a tiny raw SMTP client, so tests can send verbs (XFORWARD,
// XCLIENT) that no Go SMTP library exposes.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialRelay(t *testing.T, addr string) *client {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("cannot dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	c := &client{t: t, conn: conn, r: bufio.NewReader(conn)}
	c.expect("220")

	return c
}

// readReply reads a possibly multiline SMTP reply and returns its lines.
func (c *client) readReply() []string {
	c.t.Helper()

	lines := []string{}
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read reply: %v (got %v)", err, lines)
		}

		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)

		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

// cmd sends a command and returns the reply lines.
func (c *client) cmd(format string, args ...any) []string {
	c.t.Helper()

	fmt.Fprintf(c.conn, format+"\r\n", args...)

	return c.readReply()
}

// expect reads a reply and fails unless its last line starts with code.
func (c *client) expect(code string) []string {
	c.t.Helper()

	lines := c.readReply()
	if !strings.HasPrefix(lines[len(lines)-1], code) {
		c.t.Fatalf("got reply %v, want a %s", lines, code)
	}

	return lines
}

// cmdExpect sends a command and fails unless the reply code matches.
func (c *client) cmdExpect(code, format string, args ...any) []string {
	c.t.Helper()

	lines := c.cmd(format, args...)
	if !strings.HasPrefix(lines[len(lines)-1], code) {
		c.t.Fatalf("%q: got reply %v, want a %s", fmt.Sprintf(format, args...), lines, code)
	}

	return lines
}

// sendMessage plays a complete MAIL/RCPT/DATA transaction.
func (c *client) sendMessage() {
	c.t.Helper()

	c.cmdExpect("250", "MAIL FROM:<sender@example.com>")
	c.cmdExpect("250", "RCPT TO:<test-abc@example.com>")
	c.cmdExpect("354", "DATA")
	fmt.Fprintf(c.conn, "Subject: test\r\n\r\nbody\r\n.\r\n")
	c.expect("250")
}

// TestRelayPassesThroughWithoutXFORWARD checks the baseline: with no
// XFORWARD in the session, the relay is a transparent proxy and must not
// invent an XCLIENT command.
func TestRelayPassesThroughWithoutXFORWARD(t *testing.T) {
	addr, upstream := startRelay(t, []string{"127.0.0.0/8"})

	c := dialRelay(t, addr)
	c.cmdExpect("250", "EHLO mta.example.com")
	c.sendMessage()
	c.cmdExpect("221", "QUIT")

	want := []string{"EHLO", "MAIL", "RCPT", "DATA", "QUIT"}
	if got := upstream.Verbs(); !equalStrings(got, want) {
		t.Errorf("upstream saw %v, want %v", got, want)
	}

	if len(upstream.messages) != 1 || !strings.Contains(upstream.messages[0], "Subject: test") {
		t.Errorf("upstream messages = %q, want the relayed message", upstream.messages)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// capabilities extracts the advertised keywords from an EHLO reply.
func capabilities(lines []string) []string {
	caps := []string{}
	for _, line := range lines[1:] {
		caps = append(caps, strings.ToUpper(strings.Fields(line[4:] + " ")[0]))
	}
	return caps
}

func hasCapability(lines []string, name string) bool {
	for _, c := range capabilities(lines) {
		if c == name {
			return true
		}
	}
	return false
}

// TestRelayFiltersEHLOCapabilities checks that the relay advertises XFORWARD
// only to a trusted peer, never re-advertises the upstream's XCLIENT (which
// it consumes itself), and never offers STARTTLS it cannot honour.
func TestRelayFiltersEHLOCapabilities(t *testing.T) {
	t.Run("trusted peer", func(t *testing.T) {
		addr, _ := startRelay(t, []string{"127.0.0.0/8"})

		c := dialRelay(t, addr)
		reply := c.cmdExpect("250", "EHLO mta.example.com")

		if hasCapability(reply, "STARTTLS") {
			t.Errorf("EHLO reply %v must not advertise STARTTLS: the relay speaks plaintext", reply)
		}
		for _, wanted := range []string{"XFORWARD", "XCLIENT", "PIPELINING", "SIZE", "8BITMIME"} {
			if !hasCapability(reply, wanted) {
				t.Errorf("EHLO reply %v dropped the upstream capability %s", reply, wanted)
			}
		}

		last := reply[len(reply)-1]
		if len(last) < 4 || last[3] != ' ' {
			t.Errorf("last EHLO line %q must not be a continuation line", last)
		}
	})

	t.Run("untrusted peer", func(t *testing.T) {
		addr, _ := startRelay(t, []string{"192.0.2.0/24"})

		c := dialRelay(t, addr)
		reply := c.cmdExpect("250", "EHLO mta.example.com")

		for _, unwanted := range []string{"XFORWARD", "XCLIENT", "STARTTLS"} {
			if hasCapability(reply, unwanted) {
				t.Errorf("EHLO reply %v advertises %s to an untrusted peer", reply, unwanted)
			}
		}
	})
}

// TestRelayTranslatesXFORWARDIntoXCLIENT is the core of the package: what the
// front MTA states about the original client with XFORWARD (which only fixes
// logging) must reach the local MTA as XCLIENT (which also fixes what the
// authentication milters see), before the transaction starts.
func TestRelayTranslatesXFORWARDIntoXCLIENT(t *testing.T) {
	tests := []struct {
		name     string
		xforward []string
		want     string
	}{
		{
			name:     "all attributes in one command",
			xforward: []string{"XFORWARD NAME=mail.example.com ADDR=192.0.2.10 PORT=48512 PROTO=ESMTP HELO=mail.example.com"},
			want:     "XCLIENT NAME=mail.example.com ADDR=192.0.2.10 PORT=48512 PROTO=ESMTP HELO=mail.example.com",
		},
		{
			name: "attributes split across commands, as Postfix sends them",
			xforward: []string{
				"XFORWARD NAME=mail.example.com ADDR=192.0.2.10",
				"XFORWARD PORT=48512 PROTO=ESMTP HELO=mail.example.com",
			},
			want: "XCLIENT NAME=mail.example.com ADDR=192.0.2.10 PORT=48512 PROTO=ESMTP HELO=mail.example.com",
		},
		{
			name:     "missing attributes are reported unavailable, never guessed",
			xforward: []string{"XFORWARD ADDR=192.0.2.10"},
			want:     "XCLIENT NAME=[UNAVAILABLE] ADDR=192.0.2.10 PORT=[UNAVAILABLE] PROTO=[UNAVAILABLE] HELO=[UNAVAILABLE]",
		},
		{
			name:     "unavailable attributes are passed through",
			xforward: []string{"XFORWARD NAME=[UNAVAILABLE] ADDR=192.0.2.10 PROTO=SMTP HELO=[TEMPUNAVAIL]"},
			want:     "XCLIENT NAME=[UNAVAILABLE] ADDR=192.0.2.10 PORT=[UNAVAILABLE] PROTO=SMTP HELO=[TEMPUNAVAIL]",
		},
		{
			name:     "IPv6 addresses get the mandatory IPV6: prefix",
			xforward: []string{"XFORWARD ADDR=2001:db8::1 NAME=mail.example.com"},
			want:     "XCLIENT NAME=mail.example.com ADDR=IPV6:2001:db8::1 PORT=[UNAVAILABLE] PROTO=[UNAVAILABLE] HELO=[UNAVAILABLE]",
		},
		{
			name:     "an already prefixed IPv6 address is not prefixed twice",
			xforward: []string{"XFORWARD ADDR=IPV6:2001:db8::1"},
			want:     "XCLIENT NAME=[UNAVAILABLE] ADDR=IPV6:2001:db8::1 PORT=[UNAVAILABLE] PROTO=[UNAVAILABLE] HELO=[UNAVAILABLE]",
		},
		{
			name:     "attribute names are case insensitive",
			xforward: []string{"xforward addr=192.0.2.10 helo=mail.example.com"},
			want:     "XCLIENT NAME=[UNAVAILABLE] ADDR=192.0.2.10 PORT=[UNAVAILABLE] PROTO=[UNAVAILABLE] HELO=mail.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, upstream := startRelay(t, []string{"127.0.0.0/8"})

			c := dialRelay(t, addr)
			c.cmdExpect("250", "EHLO mta.example.com")
			for _, line := range tc.xforward {
				c.cmdExpect("250", "%s", line)
			}
			c.sendMessage()
			c.cmdExpect("221", "QUIT")

			// XCLIENT resets the upstream session, so a second EHLO
			// must follow it before the transaction resumes.
			wantVerbs := []string{"EHLO", "XCLIENT", "EHLO", "MAIL", "RCPT", "DATA", "QUIT"}
			if got := upstream.Verbs(); !equalStrings(got, wantVerbs) {
				t.Errorf("upstream saw %v, want %v", got, wantVerbs)
			}

			got, ok := upstream.LastCommandWithVerb("XCLIENT")
			if !ok {
				t.Fatal("upstream never received an XCLIENT command")
			}
			if got != tc.want {
				t.Errorf("upstream got %q,\n                  want %q", got, tc.want)
			}
		})
	}
}

// TestRelayReplaysHELOAfterXCLIENT checks that the EHLO replayed after the
// session reset carries the client's own greeting, not ours.
func TestRelayReplaysHELOAfterXCLIENT(t *testing.T) {
	addr, upstream := startRelay(t, []string{"127.0.0.0/8"})

	c := dialRelay(t, addr)
	c.cmdExpect("250", "EHLO mta.example.com")
	c.cmdExpect("250", "XFORWARD ADDR=192.0.2.10")
	c.sendMessage()

	cmds := upstream.Commands()
	if len(cmds) < 3 || cmds[2] != "EHLO mta.example.com" {
		t.Errorf("upstream commands = %v, want EHLO mta.example.com replayed in third position", cmds)
	}
}

// TestRelayRefusesIdentityRewriteFromUntrustedPeer is the security test of
// the package: anyone able to restate the client identity can forge an
// spf=pass, so a peer outside the trusted networks must be refused, and no
// identity of its choosing must ever reach the local MTA.
func TestRelayRefusesIdentityRewriteFromUntrustedPeer(t *testing.T) {
	for _, verb := range []string{"XFORWARD", "XCLIENT"} {
		t.Run(verb, func(t *testing.T) {
			addr, upstream := startRelay(t, []string{"192.0.2.0/24"})

			c := dialRelay(t, addr)
			c.cmdExpect("250", "EHLO mta.example.com")
			c.cmdExpect("550", "%s ADDR=192.0.2.10 NAME=spoofed.example.com", verb)

			// The refusal must not break the session: the message is
			// still relayed, simply with the peer's real identity.
			c.sendMessage()
			c.cmdExpect("221", "QUIT")

			for _, cmd := range upstream.Commands() {
				if strings.HasPrefix(strings.ToUpper(cmd), "XCLIENT") {
					t.Errorf("untrusted peer managed to get %q sent upstream", cmd)
				}
			}

			want := []string{"EHLO", "MAIL", "RCPT", "DATA", "QUIT"}
			if got := upstream.Verbs(); !equalStrings(got, want) {
				t.Errorf("upstream saw %v, want %v", got, want)
			}
		})
	}
}

// TestRelayPassesXCLIENTFromTrustedPeer covers front-ends that already speak
// XCLIENT themselves, such as an nginx mail proxy: the relay has nothing to
// translate and must simply get out of the way.
func TestRelayPassesXCLIENTFromTrustedPeer(t *testing.T) {
	addr, upstream := startRelay(t, []string{"127.0.0.0/8"})

	c := dialRelay(t, addr)
	c.cmdExpect("250", "EHLO mta.example.com")
	c.cmdExpect("220", "XCLIENT ADDR=192.0.2.10 NAME=mail.example.com")
	c.cmdExpect("250", "EHLO mta.example.com")
	c.sendMessage()
	c.cmdExpect("221", "QUIT")

	got, ok := upstream.LastCommandWithVerb("XCLIENT")
	if !ok {
		t.Fatal("upstream never received the XCLIENT command")
	}
	if got != "XCLIENT ADDR=192.0.2.10 NAME=mail.example.com" {
		t.Errorf("upstream got %q, want the client's XCLIENT verbatim", got)
	}

	want := []string{"EHLO", "XCLIENT", "EHLO", "MAIL", "RCPT", "DATA", "QUIT"}
	if verbs := upstream.Verbs(); !equalStrings(verbs, want) {
		t.Errorf("upstream saw %v, want %v", verbs, want)
	}
}

// TestRelayRejectsMalformedXFORWARD checks that a syntactically broken or
// unknown attribute is reported rather than silently dropped.
func TestRelayRejectsMalformedXFORWARD(t *testing.T) {
	addr, _ := startRelay(t, []string{"127.0.0.0/8"})

	c := dialRelay(t, addr)
	c.cmdExpect("250", "EHLO mta.example.com")
	c.cmdExpect("501", "XFORWARD ADDR")
	c.cmdExpect("501", "XFORWARD SOURCE=REMOTE")
}

// TestRelayRefusesWhenUpstreamCannotImpersonate checks the failure mode that
// matters most: if the local MTA will not accept XCLIENT, the relay must not
// quietly deliver the message with the wrong client identity, since every
// authentication verdict in the report would then be wrong. It answers with a
// temporary failure so the front MTA queues and retries.
func TestRelayRefusesWhenUpstreamCannotImpersonate(t *testing.T) {
	addr, upstream := startRelay(t, []string{"127.0.0.0/8"})
	upstream.refuseXCLIENT = true

	c := dialRelay(t, addr)
	c.cmdExpect("250", "EHLO mta.example.com")
	c.cmdExpect("250", "XFORWARD ADDR=192.0.2.10")
	c.cmdExpect("421", "MAIL FROM:<sender@example.com>")

	for _, cmd := range upstream.Commands() {
		if strings.HasPrefix(strings.ToUpper(cmd), "MAIL") {
			t.Errorf("message started to be relayed despite the failed impersonation: %q", cmd)
		}
	}
}

// TestRelayReportsUnreachableUpstream checks the client gets a temporary
// failure rather than a silently dropped connection.
func TestRelayReportsUnreachableUpstream(t *testing.T) {
	// Pick a port nothing listens on by closing a listener right away.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	cfg := config.DefaultConfig()
	cfg.Email.RelayUpstream = deadAddr
	cfg.Email.RelayTrustedNets = []string{"127.0.0.0/8"}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("cannot dial relay: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(line, "421") {
		t.Errorf("greeting = %q, want a 421", line)
	}
}

func TestNewRejectsInvalidTrustedNets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Email.RelayTrustedNets = []string{"not-a-cidr"}

	if _, err := New(cfg); err == nil {
		t.Error("New() accepted an invalid trusted network")
	}
}

func TestStartServerListenError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Email.RelayAddr = "127.0.0.1:-1"
	cfg.Email.RelayTrustedNets = []string{"127.0.0.0/8"}

	if err := StartServer(cfg); err == nil {
		t.Error("StartServer() accepted an invalid listen address")
	}
}
