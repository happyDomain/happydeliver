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
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// clamdChunkSize is the size of INSTREAM chunks sent to clamd
const clamdChunkSize = 64 * 1024

// ClamAVClient talks to a clamd daemon using its native protocol
type ClamAVClient struct {
	network string // "tcp" or "unix"
	address string
	timeout time.Duration
}

// ClamAVScan is the outcome of scanning one payload with clamd
type ClamAVScan struct {
	Status    string // clean, infected, error, too_large
	Signature string // malware signature name when infected
	Error     string // error detail when status is error
}

// NewClamAVClient creates a client for the given clamd address.
// Accepted forms: "tcp://host:port", "unix:///path/to/clamd.sock" or a bare
// "host:port" (assumed TCP). Returns nil for an empty address (disabled).
func NewClamAVClient(address string, timeout time.Duration) *ClamAVClient {
	if address == "" {
		return nil
	}

	network := "tcp"
	switch {
	case strings.HasPrefix(address, "tcp://"):
		address = strings.TrimPrefix(address, "tcp://")
	case strings.HasPrefix(address, "unix://"):
		network = "unix"
		address = strings.TrimPrefix(address, "unix://")
	case strings.HasPrefix(address, "/"):
		network = "unix"
	}

	return &ClamAVClient{
		network: network,
		address: address,
		timeout: timeout,
	}
}

// ScanBytes streams data to clamd using the INSTREAM command and returns the
// scan verdict
func (c *ClamAVClient) ScanBytes(ctx context.Context, data []byte) *ClamAVScan {
	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, c.network, c.address)
	if err != nil {
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to connect to clamd: %v", err)}
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to set deadline: %v", err)}
	}

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to send INSTREAM command: %v", err)}
	}

	var sizeBuf [4]byte
	for offset := 0; offset < len(data); offset += clamdChunkSize {
		end := min(offset+clamdChunkSize, len(data))
		binary.BigEndian.PutUint32(sizeBuf[:], uint32(end-offset))
		if _, err := conn.Write(sizeBuf[:]); err != nil {
			return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to stream data to clamd: %v", err)}
		}
		if _, err := conn.Write(data[offset:end]); err != nil {
			return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to stream data to clamd: %v", err)}
		}
	}

	// Zero-length chunk terminates the stream
	binary.BigEndian.PutUint32(sizeBuf[:], 0)
	if _, err := conn.Write(sizeBuf[:]); err != nil {
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to terminate stream: %v", err)}
	}

	reply, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && reply == "" {
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("failed to read clamd reply: %v", err)}
	}

	return parseClamdReply(strings.TrimRight(reply, "\x00\n"))
}

// parseClamdReply interprets a clamd INSTREAM reply such as
// "stream: OK", "stream: Eicar-Signature FOUND" or "INSTREAM size limit exceeded. ERROR"
func parseClamdReply(reply string) *ClamAVScan {
	reply = strings.TrimSpace(reply)

	switch {
	case strings.HasSuffix(reply, " OK") || reply == "stream: OK":
		return &ClamAVScan{Status: "clean"}
	case strings.HasSuffix(reply, " FOUND"):
		signature := strings.TrimSuffix(reply, " FOUND")
		if idx := strings.Index(signature, ": "); idx >= 0 {
			signature = signature[idx+2:]
		}
		return &ClamAVScan{Status: "infected", Signature: signature}
	case strings.HasSuffix(reply, "ERROR"):
		if strings.Contains(strings.ToLower(reply), "size limit") {
			return &ClamAVScan{Status: "too_large", Error: reply}
		}
		return &ClamAVScan{Status: "error", Error: reply}
	default:
		return &ClamAVScan{Status: "error", Error: fmt.Sprintf("unexpected clamd reply: %q", reply)}
	}
}
