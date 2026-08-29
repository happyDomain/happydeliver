// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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
	"strings"
	"testing"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// hop builds a ReceivedHop with the fields InboundHop looks at. An empty ip
// leaves Ip nil, which is how parseReceivedHeader reports a hop whose Received
// header carried no bracketed address (or an unparsable one).
func hop(from, ip string) model.ReceivedHop {
	h := model.ReceivedHop{}
	if from != "" {
		h.From = utils.PtrTo(from)
	}
	if ip != "" {
		h.Ip = utils.PtrTo(ip)
	}
	return h
}

// TestInboundHop covers the selection of the hop used as the message's point of
// entry (sender IP, HELO name, PTR/FCrDNS verification).
//
// The detection is deliberately narrow: it only fires for uploaded EMLs, and
// only on the exact shape "one or more contiguous hops with an explicitly
// non-public IP at the top of the chain, followed by a hop with a public IP".
// Anything else — a message we received ourselves, a hop we cannot classify, a
// fully internal chain — falls back to chain[0], the historical behaviour.
func TestInboundHop(t *testing.T) {
	tests := []struct {
		name   string
		chain  []model.ReceivedHop
		source model.ReportSource
		// wantIndex is the index of the expected hop in chain, or -1 for nil.
		wantIndex int
	}{
		// --- Detection must fire ---
		{
			// Anonymised shape of a real ESP message: two internal LMTP hops of
			// the recipient's provider on top of the actual external delivery.
			name: "uploaded: two internal hops then the public sender",
			chain: []model.ReceivedHop{
				hop("mx-dir04.internal.example", "10.0.0.1"),
				hop("scott18", "10.0.0.1"),
				hop("mta2.mail.example.com", "192.0.2.10"),
				hop("", ""),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 2,
		},
		{
			name: "uploaded: one internal hop then the public sender",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "172.16.5.4"),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 1,
		},
		{
			name: "uploaded: IPv6 unique-local hop then the public sender",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "fd00::1"),
				hop("mta2.mail.example.com", "2001:db8::1"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 1,
		},
		{
			name: "uploaded: CGNAT hop counts as internal",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "100.64.0.1"),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 1,
		},

		// --- Detection must NOT fire: fall back to chain[0] ---
		{
			name: "received: the same chain keeps the topmost hop",
			chain: []model.ReceivedHop{
				hop("mx-dir04.internal.example", "10.0.0.1"),
				hop("scott18", "10.0.0.1"),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceReceived,
			wantIndex: 0,
		},
		{
			name: "empty source is treated as received",
			chain: []model.ReceivedHop{
				hop("mx-dir04.internal.example", "10.0.0.1"),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    "",
			wantIndex: 0,
		},
		{
			name: "uploaded: topmost hop is already public",
			chain: []model.ReceivedHop{
				hop("mta2.mail.example.com", "192.0.2.10"),
				hop("mta1.mail.example.com", "192.0.2.11"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name: "uploaded: topmost hop has no IP",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", ""),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name: "uploaded: unclassifiable hop interrupts the walk",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "10.0.0.1"),
				hop("relay.example.test", ""),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name: "uploaded: unparsable IP interrupts the walk",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "10.0.0.1"),
				hop("relay.example.test", "not-an-ip"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name: "uploaded: fully internal chain",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "10.0.0.1"),
				hop("scott18", "192.168.1.10"),
				hop("localhost", "127.0.0.1"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name:      "uploaded: single internal hop",
			chain:     []model.ReceivedHop{hop("mx.internal.example", "10.0.0.1")},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			name:      "uploaded: empty chain",
			chain:     []model.ReceivedHop{},
			source:    model.ReportSourceUploaded,
			wantIndex: -1,
		},
		{
			name:      "uploaded: nil chain",
			chain:     nil,
			source:    model.ReportSourceUploaded,
			wantIndex: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InboundHop(tt.chain, tt.source)

			if tt.wantIndex < 0 {
				if got != nil {
					t.Fatalf("InboundHop() = %+v, want nil", *got)
				}
				return
			}

			if got == nil {
				t.Fatalf("InboundHop() = nil, want hop %d", tt.wantIndex)
			}

			want := &tt.chain[tt.wantIndex]
			if got != want {
				t.Errorf("InboundHop() = %+v, want hop %d (%+v)", *got, tt.wantIndex, *want)
			}
		})
	}
}

// TestClassifyHopIP checks the three-state classification the selection relies
// on: a hop we cannot classify must never be mistaken for an internal one, as
// only internal hops are skipped.
func TestClassifyHopIP(t *testing.T) {
	tests := []struct {
		name string
		hop  model.ReceivedHop
		want hopIPClass
	}{
		{"no IP", hop("mx.example.test", ""), hopIPUnknown},
		{"empty IP", model.ReceivedHop{Ip: utils.PtrTo("")}, hopIPUnknown},
		{"unparsable IP", hop("", "not-an-ip"), hopIPUnknown},
		{"RFC1918 10/8", hop("", "10.0.0.1"), hopIPInternal},
		{"RFC1918 172.16/12", hop("", "172.16.5.4"), hopIPInternal},
		{"RFC1918 192.168/16", hop("", "192.168.1.10"), hopIPInternal},
		{"CGNAT 100.64/10", hop("", "100.64.0.1"), hopIPInternal},
		{"loopback", hop("", "127.0.0.1"), hopIPInternal},
		{"link-local", hop("", "169.254.1.1"), hopIPInternal},
		{"unspecified", hop("", "0.0.0.0"), hopIPInternal},
		{"IPv6 unique-local", hop("", "fd00::1"), hopIPInternal},
		{"IPv6 loopback", hop("", "::1"), hopIPInternal},
		{"public IPv4", hop("", "192.0.2.10"), hopIPPublic},
		{"public IPv6", hop("", "2001:db8::1"), hopIPPublic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHopIP(tt.hop); got != tt.want {
				t.Errorf("classifyHopIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInboundHopFromParsedChain runs the selection on a chain built by the real
// Received parser, on the shape that motivated it: an ESP message whose two
// topmost hops are private-addressed LMTP handoffs inside the recipient's
// infrastructure, with the actual external delivery one hop below.
func TestInboundHopFromParsedChain(t *testing.T) {
	rawEmail := "Received: from mx-dir04.internal.example ([10.0.0.1])\r\n" +
		"\tby mx-be09.internal.example with LMTP\r\n" +
		"\tid AAAAAAAAAAAAAAAAAAAAAA:T4904:P1\r\n" +
		"\tfor <recipient@example.test>; Sat, 29 Aug 2026 09:33:07 +0200\r\n" +
		"Received: from scott18 ([10.0.0.1])\r\n" +
		"\tby mx-dir04.internal.example with LMTP\r\n" +
		"\tid AAAAAAAAAAAAAAAAAAAAAA:T4904\r\n" +
		"\tfor <recipient@example.test>; Sat, 29 Aug 2026 09:33:07 +0200\r\n" +
		"Received: from mta2.mail.example.com ([192.0.2.10])\r\n" +
		"\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))\r\n" +
		"\tby cmsmtp with ESMTPS\r\n" +
		"\tid 0DYoxwN21y5KT0DYoxpko8; Sat, 29 Aug 2026 09:33:07 +0200\r\n" +
		"Received: by mta2.mail.example.com id hia5j439mjco\r\n" +
		"\tfor <recipient@example.test>; Sat, 29 Aug 2026 07:33:05 +0000\r\n" +
		"From: Sender <sender@mail.example.com>\r\n" +
		"To: recipient@example.test\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"body\r\n"

	email, err := ParseEmail(strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	chain := NewHeaderAnalyzer().parseReceivedChain(email)
	if len(chain) != 4 {
		t.Fatalf("parseReceivedChain() returned %d hops, want 4", len(chain))
	}

	uploaded := InboundHop(chain, model.ReportSourceUploaded)
	if uploaded == nil || uploaded.From == nil || *uploaded.From != "mta2.mail.example.com" {
		t.Errorf("InboundHop(uploaded) = %+v, want the mta2.mail.example.com hop", uploaded)
	}
	if uploaded == nil || uploaded.Ip == nil || *uploaded.Ip != "192.0.2.10" {
		t.Errorf("InboundHop(uploaded) IP = %+v, want 192.0.2.10", uploaded)
	}

	// The very same message received by this instance keeps the topmost hop:
	// there, our own MTA wrote it.
	received := InboundHop(chain, model.ReportSourceReceived)
	if received == nil || received.From == nil || *received.From != "mx-dir04.internal.example" {
		t.Errorf("InboundHop(received) = %+v, want the topmost hop", received)
	}
}
