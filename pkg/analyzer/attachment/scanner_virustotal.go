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
	"fmt"
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/pkg/virustotal"
)

var (
	// virustotalAPIKey is the key the attachment hashes are looked up with.
	// Empty leaves them unqueried.
	virustotalAPIKey string

	// virustotalUpload allows submitting an attachment VirusTotal does not
	// already know the hash of. Off by default: it hands the file over to a
	// third party.
	virustotalUpload bool
)

func init() {
	flag.StringVar(&virustotalAPIKey, "virustotal-api-key", virustotalAPIKey, "VirusTotal API key for attachment hash lookups (empty = disabled)")
	flag.BoolVar(&virustotalUpload, "virustotal-upload", virustotalUpload, "Upload attachments unknown to VirusTotal for analysis (warning: shares file content with VirusTotal)")
}

// virustotalDef is VirusTotal as the registry knows it.
var virustotalDef = scannerDef{
	scannerInfo: scannerInfo{Name: "virustotal", Label: "VirusTotal"},
	build: func(timeout time.Duration) scanner {
		if client := virustotal.New(virustotalAPIKey, virustotalUpload, timeout); client != nil {
			return virustotalScanner{client: client}
		}
		return nil
	},
}

// hashChecker is what the scanner needs of the VirusTotal client, so that a
// test can answer in its place.
type hashChecker interface {
	CheckHash(ctx context.Context, sha256 string, content []byte) *virustotal.Scan
}

// virustotalMaliciousEngines is how many of VirusTotal's engines have to call
// a file malicious before the report does. VirusTotal itself says a file is
// malicious as soon as one engine does, but a single engine out of some
// seventy is, more often than not, a heuristic firing on a packed installer or
// an unusual PDF: it is worth a warning, not a failing grade. Three engines
// agreeing is the customary bar past which a detection stops being one vendor's
// opinion.
const virustotalMaliciousEngines = 3

// virustotalScanner asks what the aggregator already knows about the hash.
type virustotalScanner struct{ client hashChecker }

func (s virustotalScanner) info() scannerInfo { return virustotalDef.scannerInfo }

func (s virustotalScanner) scan(ctx context.Context, attachment *Attachment) Scan {
	scan := Scan{Scanner: s.info().Name}
	result := s.client.CheckHash(ctx, attachment.SHA256, attachment.Data)

	scan.Status = model.ScanResultStatus(result.Status)
	if scan.Status == model.ScanResultStatusMalicious && result.Malicious < virustotalMaliciousEngines {
		scan.Status = model.ScanResultStatusSuspicious
	}
	if !scan.Status.Valid() {
		// A status the report has no word for is an error.
		scan.Status = model.ScanResultStatusError
		scan.Detail = fmt.Sprintf("unexpected VirusTotal status %q", result.Status)
		return scan
	}

	if result.Total > 0 {
		scan.EnginesFlagged = result.Positives
		scan.EnginesTotal = result.Total
	}
	scan.Link = result.Permalink
	if scan.Detail == "" {
		scan.Detail = result.Error
	}

	return scan
}
