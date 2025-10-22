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

package lmtp

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/emersion/go-smtp"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/receiver"
	"git.happydns.org/happyDeliver/internal/storage"
)

// Backend implements smtp.Backend for LMTP server
type Backend struct {
	receiver *receiver.EmailReceiver
	config   *config.Config
}

// NewBackend creates a new LMTP backend
func NewBackend(store storage.Storage, cfg *config.Config) *Backend {
	return &Backend{
		receiver: receiver.NewEmailReceiver(store, cfg),
		config:   cfg,
	}
}

// NewSession creates a new SMTP/LMTP session
func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{backend: b}, nil
}

// Session implements smtp.Session for handling LMTP connections
type Session struct {
	backend    *Backend
	from       string
	recipients []string
}

// AuthPlain implements PLAIN authentication (not used for local LMTP)
func (s *Session) AuthPlain(username, password string) error {
	// No authentication required for local LMTP
	return nil
}

// Mail is called when MAIL FROM command is received
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Printf("LMTP: MAIL FROM: %s", from)
	s.from = from
	return nil
}

// Rcpt is called when RCPT TO command is received
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Printf("LMTP: RCPT TO: %s", to)
	s.recipients = append(s.recipients, to)
	return nil
}

// Data is called when DATA command is received and email content is being transferred
func (s *Session) Data(r io.Reader) error {
	log.Printf("LMTP: Receiving message data for %d recipient(s)", len(s.recipients))

	// Read the entire email
	emailData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read email data: %w", err)
	}

	log.Printf("LMTP: Received %d bytes", len(emailData))

	// Prepend Return-Path header from envelope sender
	returnPath := fmt.Sprintf("Return-Path: <%s>\r\n", s.from)
	emailData = append([]byte(returnPath), emailData...)

	// Process email for each recipient
	// LMTP requires per-recipient status, but go-smtp handles this internally
	for _, recipient := range s.recipients {
		if err := s.backend.receiver.ProcessEmailBytes(emailData, recipient); err != nil {
			log.Printf("LMTP: Failed to process email for %s: %v", recipient, err)
			return fmt.Errorf("failed to process email for %s: %w", recipient, err)
		}
		log.Printf("LMTP: Successfully processed email for %s", recipient)
	}

	return nil
}

// Reset is called when RSET command is received
func (s *Session) Reset() {
	log.Printf("LMTP: Session reset")
	s.from = ""
	s.recipients = nil
}

// Logout is called when the session is closed
func (s *Session) Logout() error {
	log.Printf("LMTP: Session logout")
	return nil
}

// StartServer starts an LMTP server on the specified address
func StartServer(addr string, store storage.Storage, cfg *config.Config) error {
	backend := NewBackend(store, cfg)

	server := smtp.NewServer(backend)
	server.Addr = addr
	server.Domain = cfg.Email.Domain
	server.AllowInsecureAuth = true
	server.LMTP = true // Enable LMTP mode

	log.Printf("Starting LMTP server on %s", addr)

	// Create TCP listener explicitly
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create LMTP listener: %w", err)
	}

	if err := server.Serve(listener); err != nil {
		return fmt.Errorf("LMTP server error: %w", err)
	}

	return nil
}
