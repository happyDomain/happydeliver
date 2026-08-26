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
	"log"
	"net"
	"time"

	"git.happydns.org/happyDeliver/internal/config"
)

// Server is an SMTP proxy that lets happyDeliver run on a host whose port 25
// is already taken. The front MTA relays test messages to this server with
// XFORWARD; the server replays them to the local MTA with XCLIENT, so the
// authentication milters behind it still evaluate SPF, IPRev, PTR and DMARC
// against the original client rather than against the front MTA.
type Server struct {
	// Upstream is the local MTA to forward to.
	Upstream string
	// TrustedNets are the peers allowed to use XFORWARD or XCLIENT.
	TrustedNets []*net.IPNet
	// Hostname is announced in our own greeting.
	Hostname string
	// Timeout bounds every read and write on both connections.
	Timeout time.Duration
}

// New builds a Server from the configuration, rejecting unusable trusted
// networks up front rather than at connection time.
func New(cfg *config.Config) (*Server, error) {
	nets, err := config.ParseTrustedNets(cfg.Email.RelayTrustedNets)
	if err != nil {
		return nil, err
	}

	return &Server{
		Upstream:    cfg.Email.RelayUpstream,
		TrustedNets: nets,
		Hostname:    cfg.Email.ReceiverHostname,
		Timeout:     5 * time.Minute,
	}, nil
}

// StartServer runs the relay front-end. It blocks until the listener fails.
func StartServer(cfg *config.Config) error {
	srv, err := New(cfg)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Email.RelayAddr)
	if err != nil {
		return err
	}

	log.Printf("SMTP relay listening on %s, forwarding to %s", cfg.Email.RelayAddr, srv.Upstream)

	return srv.Serve(ln)
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func() {
			if err := s.handle(conn); err != nil {
				log.Printf("relay session with %s ended: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

// isTrusted reports whether a peer may rewrite the client identity.
func (s *Server) isTrusted(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, n := range s.TrustedNets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}
