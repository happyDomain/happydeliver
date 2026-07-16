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
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// EICAR test string, only ever used against the fake clamd server below
const eicarTestString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// fakeClamd starts an in-process clamd simulator and returns its address.
// It answers FOUND when the streamed payload contains the EICAR string,
// ERROR when it contains "trigger-error", OK otherwise.
func fakeClamd(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake clamd: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				reader := bufio.NewReader(conn)
				command, err := reader.ReadString('\x00')
				if err != nil || strings.TrimRight(command, "\x00") != "zINSTREAM" {
					return
				}

				var payload bytes.Buffer
				for {
					var sizeBuf [4]byte
					if _, err := io.ReadFull(reader, sizeBuf[:]); err != nil {
						return
					}
					size := binary.BigEndian.Uint32(sizeBuf[:])
					if size == 0 {
						break
					}
					if _, err := io.CopyN(&payload, reader, int64(size)); err != nil {
						return
					}
				}

				switch {
				case bytes.Contains(payload.Bytes(), []byte(eicarTestString)):
					conn.Write([]byte("stream: Eicar-Signature FOUND\x00"))
				case bytes.Contains(payload.Bytes(), []byte("trigger-error")):
					conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
				default:
					conn.Write([]byte("stream: OK\x00"))
				}
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func TestClamAVScanClean(t *testing.T) {
	client := NewClamAVClient(fakeClamd(t), 5*time.Second)

	scan := client.ScanBytes(context.Background(), []byte("hello, harmless world"))
	if scan.Status != "clean" {
		t.Errorf("Expected status clean, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestClamAVScanInfected(t *testing.T) {
	client := NewClamAVClient("tcp://"+fakeClamd(t), 5*time.Second)

	scan := client.ScanBytes(context.Background(), []byte(eicarTestString))
	if scan.Status != "infected" {
		t.Fatalf("Expected status infected, got %q (%s)", scan.Status, scan.Error)
	}
	if scan.Signature != "Eicar-Signature" {
		t.Errorf("Expected signature Eicar-Signature, got %q", scan.Signature)
	}
}

func TestClamAVScanSizeLimitError(t *testing.T) {
	client := NewClamAVClient(fakeClamd(t), 5*time.Second)

	scan := client.ScanBytes(context.Background(), []byte("trigger-error"))
	if scan.Status != "too_large" {
		t.Errorf("Expected status too_large, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestClamAVScanLargePayloadChunking(t *testing.T) {
	client := NewClamAVClient(fakeClamd(t), 5*time.Second)

	// Larger than one 64KB chunk, EICAR at the end to prove full streaming
	payload := append(bytes.Repeat([]byte("A"), 3*clamdChunkSize), []byte(eicarTestString)...)
	scan := client.ScanBytes(context.Background(), payload)
	if scan.Status != "infected" {
		t.Errorf("Expected status infected, got %q (%s)", scan.Status, scan.Error)
	}
}

func TestClamAVScanConnectionRefused(t *testing.T) {
	// Reserve a port then close it so nothing listens there
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()

	client := NewClamAVClient(address, 1*time.Second)
	scan := client.ScanBytes(context.Background(), []byte("data"))
	if scan.Status != "error" {
		t.Errorf("Expected status error, got %q", scan.Status)
	}
}

func TestClamAVScanContextTimeout(t *testing.T) {
	// A listener that accepts but never replies
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}
	}()

	client := NewClamAVClient(listener.Addr().String(), 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	scan := client.ScanBytes(ctx, []byte("data"))
	if scan.Status != "error" {
		t.Errorf("Expected status error on timeout, got %q", scan.Status)
	}
}

func TestNewClamAVClientDisabled(t *testing.T) {
	if client := NewClamAVClient("", time.Second); client != nil {
		t.Error("Expected nil client for empty address")
	}
}

func TestNewClamAVClientUnixSocket(t *testing.T) {
	client := NewClamAVClient("unix:///run/clamav/clamd.sock", time.Second)
	if client.network != "unix" || client.address != "/run/clamav/clamd.sock" {
		t.Errorf("Unexpected client: network=%q address=%q", client.network, client.address)
	}

	client = NewClamAVClient("/run/clamav/clamd.sock", time.Second)
	if client.network != "unix" {
		t.Errorf("Bare socket path should imply unix network, got %q", client.network)
	}
}
