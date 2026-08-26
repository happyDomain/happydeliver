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

package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// unavailable is the XCLIENT/XFORWARD placeholder for a value the front MTA
// could not provide.
const unavailable = "[UNAVAILABLE]"

// ipv6Prefix is mandatory in front of an IPv6 address in XCLIENT ADDR.
const ipv6Prefix = "IPV6:"

// maxLineLength caps a single SMTP line. RFC 5321 allows 512 bytes for
// commands and 1000 for message lines; we are generous but still bounded so
// that a peer cannot make us buffer without end.
const maxLineLength = 65536

// errLineTooLong is returned when a peer sends an unterminated or oversized line.
var errLineTooLong = errors.New("relay: line too long")

// session carries one client conversation and its upstream counterpart.
type session struct {
	server *Server

	client  net.Conn
	clientR *bufio.Reader

	upstream  net.Conn
	upstreamR *bufio.Reader

	// trusted records whether the client may rewrite the client identity.
	trusted bool
	// helo is the last EHLO/HELO argument the client sent, replayed after
	// XCLIENT resets the upstream session.
	helo string
	// esmtp records whether the client greeted with EHLO rather than HELO.
	esmtp bool
	// forwarded holds the client identity announced with XFORWARD, keyed by
	// attribute name. Postfix may spread the attributes over several
	// commands, so they are accumulated until the transaction starts.
	forwarded map[string]string
	// impersonated records that XCLIENT was already issued upstream for the
	// current identity, so a second transaction does not repeat it.
	impersonated bool
}

// handle proxies one client connection to the upstream MTA.
func (s *Server) handle(client net.Conn) error {
	defer client.Close()

	upstream, err := net.Dial("tcp", s.Upstream)
	if err != nil {
		s.deadline(client)
		fmt.Fprintf(client, "421 4.3.2 Upstream MTA unavailable\r\n")
		return fmt.Errorf("cannot reach upstream %s: %w", s.Upstream, err)
	}
	defer upstream.Close()

	sess := &session{
		server:    s,
		client:    client,
		clientR:   bufio.NewReader(client),
		upstream:  upstream,
		upstreamR: bufio.NewReader(upstream),
		trusted:   s.isTrusted(client.RemoteAddr()),
	}

	return sess.run()
}

// deadline arms the read/write deadline for the next exchange.
func (s *Server) deadline(conn net.Conn) {
	if s.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(s.Timeout))
	}
}

// readLine reads one CRLF-terminated line, without its line ending.
func readLine(r *bufio.Reader) (string, error) {
	var buf strings.Builder

	for {
		chunk, err := r.ReadSlice('\n')
		buf.Write(chunk)

		if errors.Is(err, bufio.ErrBufferFull) {
			if buf.Len() > maxLineLength {
				return "", errLineTooLong
			}
			continue
		}
		if err != nil {
			return "", err
		}

		return strings.TrimRight(buf.String(), "\r\n"), nil
	}
}

// readReply reads a possibly multiline SMTP reply.
func readReply(r *bufio.Reader) ([]string, error) {
	lines := []string{}

	for {
		line, err := readLine(r)
		if err != nil {
			return nil, err
		}

		lines = append(lines, line)

		// A continuation line has a hyphen right after the 3-digit code.
		if len(line) < 4 || line[3] != '-' {
			return lines, nil
		}
	}
}

// writeLines sends CRLF-terminated lines to a connection.
func writeLines(w io.Writer, lines []string) error {
	var buf strings.Builder

	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}

	_, err := io.WriteString(w, buf.String())

	return err
}

// toUpstream sends one command line to the upstream MTA and returns its reply.
func (s *session) toUpstream(line string) ([]string, error) {
	s.server.deadline(s.upstream)

	if err := writeLines(s.upstream, []string{line}); err != nil {
		return nil, err
	}

	return readReply(s.upstreamR)
}

// toClient forwards reply lines to the client.
func (s *session) toClient(lines []string) error {
	s.server.deadline(s.client)

	return writeLines(s.client, lines)
}

// reply sends a single-line reply to the client.
func (s *session) reply(line string) error {
	return s.toClient([]string{line})
}

// run drives the proxied conversation.
func (s *session) run() error {
	s.server.deadline(s.upstream)
	greeting, err := readReply(s.upstreamR)
	if err != nil {
		return fmt.Errorf("no greeting from upstream: %w", err)
	}

	// An upstream refusing the connection is passed on as-is.
	if len(greeting) == 0 || !strings.HasPrefix(greeting[len(greeting)-1], "220") {
		return s.toClient(greeting)
	}

	if err := s.reply(fmt.Sprintf("220 %s ESMTP happyDeliver relay", s.server.Hostname)); err != nil {
		return err
	}

	for {
		s.server.deadline(s.client)
		line, err := readLine(s.clientR)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		done, err := s.command(line)
		if err != nil || done {
			return err
		}
	}
}

// command handles one client command. It reports whether the session is over.
func (s *session) command(line string) (bool, error) {
	verb, args := splitCommand(line)

	switch verb {
	case "EHLO", "HELO":
		s.helo = args
		s.esmtp = verb == "EHLO"
		return false, s.greet(line)

	case "XFORWARD":
		return false, s.xforward(args)

	case "XCLIENT":
		// A front-end that speaks XCLIENT itself needs no translation,
		// but restating the client identity stays a trusted operation.
		if !s.trusted {
			return false, s.reply("550 5.7.1 XCLIENT not available to you")
		}

	case "MAIL":
		if err := s.impersonate(); err != nil {
			// Delivering now would attribute the message to the front
			// MTA and make every authentication verdict in the report
			// wrong: ask for a retry instead.
			s.reply("421 4.7.0 Cannot restate the original client to the local MTA")
			return true, err
		}

	case "DATA":
		return false, s.data(line)

	case "QUIT":
		reply, err := s.toUpstream(line)
		if err != nil {
			return true, err
		}
		return true, s.toClient(reply)
	}

	reply, err := s.toUpstream(line)
	if err != nil {
		return true, err
	}

	return false, s.toClient(reply)
}

// xforwardAttributes are the XFORWARD attributes we accept and translate.
var xforwardAttributes = []string{"NAME", "ADDR", "PORT", "PROTO", "HELO"}

// hiddenCapabilities are never passed on to our client: the relay speaks
// plaintext to a local MTA, so it cannot honour STARTTLS.
var hiddenCapabilities = map[string]bool{"STARTTLS": true}

// trustedCapabilities are only offered to a peer allowed to restate the
// client identity. Announcing them to anyone else would invite a forgery
// that the authentication milters would then treat as genuine.
var trustedCapabilities = map[string]bool{"XCLIENT": true}

// greet forwards EHLO/HELO and filters the advertised capabilities.
func (s *session) greet(line string) error {
	reply, err := s.toUpstream(line)
	if err != nil {
		return err
	}

	if !s.esmtp || len(reply) == 0 || !strings.HasPrefix(reply[len(reply)-1], "250") {
		return s.toClient(reply)
	}

	// The first line carries the upstream identity, not a capability.
	kept := []string{reply[0]}

	for _, capability := range reply[1:] {
		name, _ := splitCommand(capability[4:])
		if hiddenCapabilities[name] || (trustedCapabilities[name] && !s.trusted) {
			continue
		}
		kept = append(kept, capability)
	}

	if s.trusted {
		kept = append(kept, "250 XFORWARD "+strings.Join(xforwardAttributes, " "))
	}

	return s.toClient(renumberReply(kept))
}

// renumberReply rewrites the code separators so that exactly the last line is
// a final one, after capabilities have been added or removed.
func renumberReply(lines []string) []string {
	out := make([]string, 0, len(lines))

	for i, line := range lines {
		if len(line) < 4 {
			out = append(out, line)
			continue
		}

		separator := "-"
		if i == len(lines)-1 {
			separator = " "
		}

		out = append(out, line[:3]+separator+line[4:])
	}

	return out
}

// xforward records the identity the front MTA announces for the original
// client. Accepting it from an untrusted peer would let anyone forge the IP
// the authentication milters check, hence an outright refusal.
func (s *session) xforward(args string) error {
	if !s.trusted {
		return s.reply("550 5.7.1 XFORWARD not available to you")
	}

	attributes, err := parseAttributes(args)
	if err != nil {
		return s.reply("501 5.5.4 " + err.Error())
	}

	if s.forwarded == nil {
		s.forwarded = map[string]string{}
	}

	for name, value := range attributes {
		s.forwarded[name] = value
	}

	// A new identity supersedes whatever was already impersonated.
	s.impersonated = false

	return s.reply("250 2.0.0 Ok")
}

// parseAttributes splits "NAME=value ADDR=value" into a map keyed by
// uppercased attribute name.
func parseAttributes(args string) (map[string]string, error) {
	attributes := map[string]string{}

	for _, field := range strings.Fields(args) {
		name, value, found := strings.Cut(field, "=")
		if !found {
			return nil, fmt.Errorf("malformed attribute %q", field)
		}

		name = strings.ToUpper(name)
		if !isKnownAttribute(name) {
			return nil, fmt.Errorf("unsupported attribute %q", name)
		}

		attributes[name] = value
	}

	return attributes, nil
}

func isKnownAttribute(name string) bool {
	for _, known := range xforwardAttributes {
		if known == name {
			return true
		}
	}

	return false
}

// impersonate issues the XCLIENT command derived from the XFORWARD data. As
// XCLIENT resets the upstream session to its initial state, the client's own
// greeting is replayed right after.
func (s *session) impersonate() error {
	if s.impersonated || len(s.forwarded) == 0 {
		return nil
	}

	reply, err := s.toUpstream(s.xclientCommand())
	if err != nil {
		return err
	}

	if len(reply) == 0 || !strings.HasPrefix(reply[len(reply)-1], "220") {
		return fmt.Errorf("upstream refused XCLIENT: %s", strings.Join(reply, " / "))
	}

	greeting := "EHLO " + s.helo
	if !s.esmtp {
		greeting = "HELO " + s.helo
	}

	if reply, err = s.toUpstream(greeting); err != nil {
		return err
	}

	if len(reply) == 0 || !strings.HasPrefix(reply[len(reply)-1], "250") {
		return fmt.Errorf("upstream refused the greeting replayed after XCLIENT: %s", strings.Join(reply, " / "))
	}

	s.impersonated = true

	return nil
}

// xclientCommand renders the collected attributes as an XCLIENT command. All
// attributes are always sent: an attribute the front MTA did not provide is
// explicitly reported as unavailable, so that the relay's own identity never
// silently stands in for the original client's.
func (s *session) xclientCommand() string {
	var command strings.Builder

	command.WriteString("XCLIENT")

	for _, name := range xforwardAttributes {
		value, ok := s.forwarded[name]
		if !ok || value == "" {
			value = unavailable
		} else if name == "ADDR" {
			value = xclientAddr(value)
		}

		fmt.Fprintf(&command, " %s=%s", name, value)
	}

	return command.String()
}

// xclientAddr formats a network address the way XCLIENT requires: an IPv6
// address must carry the IPV6: prefix, an IPv4 one must not.
func xclientAddr(value string) string {
	if strings.HasPrefix(strings.ToUpper(value), ipv6Prefix) {
		return ipv6Prefix + value[len(ipv6Prefix):]
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}

	if ip.To4() != nil {
		return value
	}

	return ipv6Prefix + value
}

// data forwards the DATA command then streams the message verbatim.
func (s *session) data(line string) error {
	reply, err := s.toUpstream(line)
	if err != nil {
		return err
	}

	if err := s.toClient(reply); err != nil {
		return err
	}

	// Anything other than the 354 go-ahead means there is no payload.
	if len(reply) == 0 || !strings.HasPrefix(reply[len(reply)-1], "354") {
		return nil
	}

	for {
		s.server.deadline(s.client)
		payload, err := readLine(s.clientR)
		if err != nil {
			return err
		}

		s.server.deadline(s.upstream)
		if err := writeLines(s.upstream, []string{payload}); err != nil {
			return err
		}

		if payload == "." {
			break
		}
	}

	s.server.deadline(s.upstream)
	reply, err = readReply(s.upstreamR)
	if err != nil {
		return err
	}

	return s.toClient(reply)
}

// splitCommand separates the uppercased verb from the rest of the line.
func splitCommand(line string) (string, string) {
	verb, args, _ := strings.Cut(strings.TrimLeft(line, " "), " ")

	return strings.ToUpper(verb), strings.TrimSpace(args)
}
