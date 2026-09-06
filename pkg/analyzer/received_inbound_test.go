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

package analyzer

import (
	"testing"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// hop builds a ReceivedHop with the fields InboundHopIndex looks at. An empty ip
// leaves Ip nil, as parseReceivedHeader does for a header without a usable
// bracketed address.
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

// lmtpHop builds a hop delivered over LMTP, as the local handoffs of a
// recipient's infrastructure write it. Such a header often carries no bracketed
// address at all, hence the ip-less variant.
func lmtpHop(from, ip string) model.ReceivedHop {
	h := hop(from, ip)
	h.With = utils.PtrTo("LMTP")
	return h
}

// TestInboundHopIndex covers the selection of the point-of-entry hop (sender IP,
// HELO name, PTR/FCrDNS verification).
//
// The detection is deliberately narrow: uploaded EMLs only, and only on the
// shape "contiguous explicitly non-public hops at the top, then a public one".
// Anything else — received messages, an unclassifiable hop, a fully internal
// chain — falls back to chain[0].
func TestInboundHopIndex(t *testing.T) {
	tests := []struct {
		name   string
		chain  []model.ReceivedHop
		source model.ReportSource
		// wantIndex is the index of the expected hop in chain, or -1 when the
		// chain is empty.
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
		{
			// Other families no Internet sender can use, skipped like RFC 1918.
			name: "uploaded: link-local, unspecified and IPv6 loopback count as internal",
			chain: []model.ReceivedHop{
				hop("mx1.internal.example", "169.254.1.1"),
				hop("mx2.internal.example", "0.0.0.0"),
				hop("mx3.internal.example", "::1"),
				hop("mta2.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 3,
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
			// An Ip pointing to an empty string is as unclassifiable as a nil
			// one, and must not pass for an internal hop.
			name: "uploaded: empty IP interrupts the walk",
			chain: []model.ReceivedHop{
				hop("mx.internal.example", "10.0.0.1"),
				{From: utils.PtrTo("relay.example.test"), Ip: utils.PtrTo("")},
				hop("mta2.mail.example.com", "192.0.2.10"),
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
			// The shape that motivated skipping on the LMTP keyword: the local
			// handoff on top carries no address, which used to abort the scan
			// before it could reach the external delivery two hops below.
			name: "uploaded: ip-less LMTP hop, then a private hop, then the public sender",
			chain: []model.ReceivedHop{
				lmtpHop("toaster-e2-01.internal.example", ""),
				hop("relay.mail.example.com", "172.20.243.94"),
				hop("relay.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 2,
		},
		{
			// LMTP is skipped whatever its address: a local delivery is never
			// where the message entered.
			name: "uploaded: publicly-addressed LMTP hop is still skipped",
			chain: []model.ReceivedHop{
				lmtpHop("toaster-e2-01.internal.example", "192.0.2.99"),
				hop("relay.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 1,
		},
		{
			name: "uploaded: fully LMTP chain falls back to the topmost hop",
			chain: []model.ReceivedHop{
				lmtpHop("toaster-e2-01.internal.example", ""),
				lmtpHop("toaster-e2-02.internal.example", "10.0.0.1"),
			},
			source:    model.ReportSourceUploaded,
			wantIndex: 0,
		},
		{
			// Our own MTA wrote the topmost header; the keyword changes nothing.
			name: "received: an LMTP topmost hop is still the selected one",
			chain: []model.ReceivedHop{
				lmtpHop("toaster-e2-01.internal.example", ""),
				hop("relay.mail.example.com", "192.0.2.10"),
			},
			source:    model.ReportSourceReceived,
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
			if got := InboundHopIndex(tt.chain, tt.source); got != tt.wantIndex {
				t.Errorf("InboundHopIndex() = %d, want %d", got, tt.wantIndex)
			}
		})
	}
}

// TestInboundHopIndexFromParsedChain runs the selection on a chain built by the
// real Received parser, on the shape that motivated it: an ESP message opening
// on two private-addressed LMTP handoffs of the recipient's infrastructure,
// the external delivery one hop below.
func TestInboundHopIndexFromParsedChain(t *testing.T) {
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

	email, err := ParseEmail([]byte(rawEmail))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	chain := NewHeaderAnalyzer().parseReceivedChain(email)
	if len(chain) != 4 {
		t.Fatalf("parseReceivedChain() returned %d hops, want 4", len(chain))
	}

	uploaded := chain[InboundHopIndex(chain, model.ReportSourceUploaded)]
	if uploaded.From == nil || *uploaded.From != "mta2.mail.example.com" {
		t.Errorf("InboundHopIndex(uploaded) = %+v, want the mta2.mail.example.com hop", uploaded)
	}
	if uploaded.Ip == nil || *uploaded.Ip != "192.0.2.10" {
		t.Errorf("InboundHopIndex(uploaded) IP = %+v, want 192.0.2.10", uploaded)
	}

	// The same message received by this instance keeps the topmost hop, the one
	// our own MTA wrote.
	received := chain[InboundHopIndex(chain, model.ReportSourceReceived)]
	if received.From == nil || *received.From != "mx-dir04.internal.example" {
		t.Errorf("InboundHopIndex(received) = %+v, want the topmost hop", received)
	}

	// The analysis flags the selected hop in the published chain, so clients read
	// the selection instead of reconstructing it. Exactly one hop carries the
	// flag: an IP repeated across internal hops (10.0.0.1 above) makes matching
	// on the sender IP alone ambiguous.
	gen := NewReportGenerator("", time.Second, time.Second, nil, nil, false, "")
	results := gen.AnalyzeEmail(email, AnalysisOptions{Source: model.ReportSourceUploaded})

	var flagged []int
	for i, hop := range *results.Headers.ReceivedChain {
		if hop.Inbound != nil && *hop.Inbound {
			flagged = append(flagged, i)
		}
	}
	if len(flagged) != 1 || flagged[0] != 2 {
		t.Errorf("AnalyzeEmail() flagged hops %v as inbound, want only hop 2", flagged)
	}
}

// TestInboundHopIndexAddresslessLMTP runs the selection on a chain built by the
// real Received parser, on the shape that motivated skipping the LMTP keyword:
// an address-less local handoff on top, an internally-addressed relay below it,
// and the external delivery only on the third hop.
func TestInboundHopIndexAddresslessLMTP(t *testing.T) {
	rawEmail := "Received: from toaster-e2-01.internal.example\r\n" +
		"\tby toaster-e2-01.internal.example with LMTP\r\n" +
		"\tid WONnDO4VmWoNixcAiQPY2A\r\n" +
		"\t(envelope-from <sender@mail.example.com>)\r\n" +
		"\tfor <recipient@example.test>; Thu, 03 Sep 2026 08:38:38 +0200\r\n" +
		"Received: from relay.mail.example.com (mx24-g26.internal.example [172.20.243.94])\r\n" +
		"\tby toaster-e2-01.internal.example (Postfix) with ESMTP id D58B229E0872\r\n" +
		"\tfor <recipient@example.test>; Thu,  3 Sep 2026 08:38:37 +0200 (CEST)\r\n" +
		"Received: from relay.mail.example.com ([192.0.2.10])\r\n" +
		"\tby mx1-g20.example.test (MXproxy) with ESMTPS for recipient@example.test\r\n" +
		"\t(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256);\r\n" +
		"\tThu,  3 Sep 2026 08:38:38 +0200 (CEST)\r\n" +
		"From: Sender <sender@mail.example.com>\r\n" +
		"To: recipient@example.test\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"body\r\n"

	email, err := ParseEmail([]byte(rawEmail))
	if err != nil {
		t.Fatalf("ParseEmail() error = %v", err)
	}

	chain := NewHeaderAnalyzer().parseReceivedChain(email)
	if len(chain) != 3 {
		t.Fatalf("parseReceivedChain() returned %d hops, want 3", len(chain))
	}

	// The parser must have picked the LMTP keyword up for the skip to apply.
	if chain[0].With == nil || *chain[0].With != "LMTP" {
		t.Fatalf("parseReceivedChain() hop 0 With = %+v, want LMTP", chain[0].With)
	}

	uploaded := chain[InboundHopIndex(chain, model.ReportSourceUploaded)]
	if uploaded.Ip == nil || *uploaded.Ip != "192.0.2.10" {
		t.Errorf("InboundHopIndex(uploaded) = %+v, want the 192.0.2.10 hop", uploaded)
	}
}
