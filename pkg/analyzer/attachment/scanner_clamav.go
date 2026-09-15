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
package attachment

import (
	"context"
	"flag"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/clamav"
)

// clamavAddress is the clamd instance attachments are submitted to. Empty
// leaves them unscanned.
var clamavAddress string

func init() {
	flag.StringVar(&clamavAddress, "clamav-address", clamavAddress, "clamd address for attachment scanning (tcp://host:port, unix:///path or host:port; empty = disabled)")
}

// clamavDef is ClamAV as the registry knows it.
var clamavDef = scannerDef{
	scannerInfo: scannerInfo{Name: "clamav", Label: "ClamAV"},
	build: func(timeout time.Duration) scanner {
		if client := clamav.New(clamavAddress, timeout); client != nil {
			return clamavScanner{client: client}
		}
		return nil
	},
}

// clamavScanner hands the bytes to the local daemon.
type clamavScanner struct{ client *clamav.Client }

func (s clamavScanner) info() scannerInfo { return clamavDef.scannerInfo }

func (s clamavScanner) scan(ctx context.Context, attachment *Attachment) Scan {
	scan := Scan{Scanner: s.info().Name}
	result := s.client.ScanBytes(ctx, attachment.Data)

	switch result.Status {
	case "clean":
		scan.Status = model.ScanResultStatusClean

	case "infected":
		scan.Status = model.ScanResultStatusMalicious
		scan.Verdict = result.Signature

	case "too_large":
		// A file the daemon refuses for its size was not looked at: a skip,
		// not an error.
		scan.Status = model.ScanResultStatusSkipped
		scan.Detail = result.Error

	default:
		scan.Status = model.ScanResultStatusError
		scan.Detail = result.Error
	}

	return scan
}
