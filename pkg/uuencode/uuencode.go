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

import (
	"bytes"
	"fmt"
	"io"
)

// NewDecoder returns a reader that decodes the uuencoded stream from r.
// The stream must include the "begin <mode> <filename>" header and the
// trailing "end" line as produced by classic uuencode(1).
func NewDecoder(r io.Reader) io.Reader {
	return &decoder{r: r}
}

type decoder struct {
	r    io.Reader
	buf  []byte // decoded but not yet read
	rest []byte // undecoded input remainder
	done bool
	err  error
}

func (d *decoder) Read(p []byte) (int, error) {
	for len(d.buf) == 0 && !d.done {
		if err := d.decode(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	if len(d.buf) == 0 && d.done {
		return n, io.EOF
	}
	return n, nil
}

func (d *decoder) decode() error {
	// Read all remaining input on the first call.
	if d.rest == nil {
		raw, err := io.ReadAll(d.r)
		if err != nil {
			return fmt.Errorf("uuencode: read error: %w", err)
		}
		d.rest = raw
	}

	lines := bytes.Split(d.rest, []byte("\n"))
	d.rest = nil

	started := false
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")

		if !started {
			if bytes.HasPrefix(line, []byte("begin ")) {
				started = true
			}
			continue
		}

		// A backtick-only line or "end" terminates the block.
		if len(line) == 0 || bytes.Equal(line, []byte("end")) || bytes.Equal(line, []byte("`")) {
			d.done = true
			return nil
		}

		// First byte encodes the number of decoded bytes on this line.
		// Both space (0x20) and backtick (0x60) represent 0.
		n := int(line[0]-0x20) & 0x3f
		if n == 0 {
			d.done = true
			return nil
		}

		data := line[1:]
		for len(data) >= 4 && n > 0 {
			a := (data[0] - 0x20) & 0x3f
			b := (data[1] - 0x20) & 0x3f
			c := (data[2] - 0x20) & 0x3f
			dd := (data[3] - 0x20) & 0x3f

			if n > 0 {
				d.buf = append(d.buf, (a<<2)|(b>>4))
				n--
			}
			if n > 0 {
				d.buf = append(d.buf, (b<<4)|(c>>2))
				n--
			}
			if n > 0 {
				d.buf = append(d.buf, (c<<6)|dd)
				n--
			}
			data = data[4:]
		}
	}

	d.done = true
	return nil
}
