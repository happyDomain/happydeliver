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

// Package uuencode implements decoding of uuencoded data as used in email
// (Content-Transfer-Encoding: uuencode / x-uuencode / uue).
package uuencode

import "bytes"

// Decode decodes a uuencoded stream. The input must include the
// "begin <mode> <filename>" header and the trailing "end" line as produced
// by classic uuencode(1).
func Decode(data []byte) []byte {
	out := make([]byte, 0, len(data)*3/4)

	started := false
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")

		if !started {
			if bytes.HasPrefix(line, []byte("begin ")) {
				started = true
			}
			continue
		}

		if len(line) == 0 || bytes.Equal(line, []byte("end")) {
			break
		}

		// First byte encodes the number of decoded bytes on this line.
		// Both space (0x20) and backtick (0x60, the terminating
		// backtick-only line) represent 0, ending the block.
		n := int(line[0]-0x20) & 0x3f
		if n == 0 {
			break
		}

		chunk := line[1:]
		for len(chunk) >= 4 && n > 0 {
			a := (chunk[0] - 0x20) & 0x3f
			b := (chunk[1] - 0x20) & 0x3f
			c := (chunk[2] - 0x20) & 0x3f
			d := (chunk[3] - 0x20) & 0x3f

			decoded := [3]byte{(a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d}
			take := min(n, 3)
			out = append(out, decoded[:take]...)
			n -= take
			chunk = chunk[4:]
		}
	}

	return out
}
