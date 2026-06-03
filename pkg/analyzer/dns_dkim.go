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
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// DKIMHeader holds the domain, selector and signing algorithm from a DKIM-Signature header.
type DKIMHeader struct {
	Domain    string
	Selector  string
	Algorithm string // from a= tag (e.g. rsa-sha256, ed25519-sha256)
}

// parseDKIMSignatures extracts domain, selector and algorithm from DKIM-Signature header values.
func parseDKIMSignatures(signatures []string) []DKIMHeader {
	var results []DKIMHeader
	for _, sig := range signatures {
		var domain, selector, algorithm string
		for _, part := range strings.Split(sig, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch key {
			case "d":
				domain = val
			case "s":
				selector = val
			case "a":
				algorithm = val
			}
		}
		if domain != "" && selector != "" {
			results = append(results, DKIMHeader{Domain: domain, Selector: selector, Algorithm: algorithm})
		}
	}
	return results
}

// parseDKIMTags splits a DKIM DNS record into a tag→value map.
func parseDKIMTags(record string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return tags
}

// parseKeySize derives the public key bit length from a base64-encoded DER public key.
// For RSA keys it parses the PKIX structure; for Ed25519 it always returns 256.
func parseKeySize(keyType, p string) *int {
	switch strings.ToLower(keyType) {
	case "ed25519":
		return utils.PtrTo(256)
	case "rsa", "":
		der, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			// Try without padding
			der, err = base64.RawStdEncoding.DecodeString(p)
			if err != nil {
				return nil
			}
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil
		}
		if rsaPub, ok := pub.(interface{ Size() int }); ok {
			bits := rsaPub.Size() * 8
			return &bits
		}
		return nil
	}
	return nil
}

// checkDKIMRecord looks up and validates DKIM record for a domain and selector.
func (d *DNSAnalyzer) checkDKIMRecord(h DKIMHeader) *model.DKIMRecord {
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", h.Selector, h.Domain)

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, dkimDomain)
	if err != nil {
		return &model.DKIMRecord{
			Selector:         h.Selector,
			Domain:           h.Domain,
			SigningAlgorithm: signingAlgorithmPtr(h.Algorithm),
			Valid:            false,
			Error:            utils.PtrTo(fmt.Sprintf("Failed to lookup DKIM record: %s", formatDNSError(err))),
		}
	}

	if len(txtRecords) == 0 {
		return &model.DKIMRecord{
			Selector:         h.Selector,
			Domain:           h.Domain,
			SigningAlgorithm: signingAlgorithmPtr(h.Algorithm),
			Valid:            false,
			Error:            utils.PtrTo("No DKIM record found"),
		}
	}

	// Concatenate all TXT record parts (DKIM can be split)
	dkimRecord := strings.Join(txtRecords, "")

	if !d.validateDKIM(dkimRecord) {
		return &model.DKIMRecord{
			Selector:         h.Selector,
			Domain:           h.Domain,
			Record:           utils.PtrTo(dkimRecord),
			SigningAlgorithm: signingAlgorithmPtr(h.Algorithm),
			Valid:            false,
			Error:            utils.PtrTo("DKIM record appears malformed"),
		}
	}

	tags := parseDKIMTags(dkimRecord)

	keyType := tags["k"]
	if keyType == "" {
		keyType = "rsa" // RFC 6376 default
	}

	var hashAlgorithms []string
	if h, ok := tags["h"]; ok && h != "" {
		for _, alg := range strings.Split(h, ":") {
			if a := strings.TrimSpace(alg); a != "" {
				hashAlgorithms = append(hashAlgorithms, a)
			}
		}
	}
	if hashAlgorithms == nil {
		hashAlgorithms = []string{}
	}

	return &model.DKIMRecord{
		Selector:         h.Selector,
		Domain:           h.Domain,
		Record:           &dkimRecord,
		KeyType:          utils.PtrTo(keyType),
		HashAlgorithms:   &hashAlgorithms,
		SigningAlgorithm: signingAlgorithmPtr(h.Algorithm),
		KeySize:          parseKeySize(keyType, tags["p"]),
		Valid:            true,
	}
}

func signingAlgorithmPtr(a string) *string {
	if a == "" {
		return nil
	}
	return &a
}

// validateDKIM performs basic DKIM record validation.
func (d *DNSAnalyzer) validateDKIM(record string) bool {
	if !strings.Contains(record, "p=") {
		return false
	}

	// If v= is present, it must be DKIM1
	if strings.Contains(record, "v=") && !strings.Contains(record, "v=DKIM1") {
		return false
	}

	return true
}

func (d *DNSAnalyzer) calculateDKIMScore(results *model.DNSResults) (score int) {
	if results.DkimRecords == nil || len(*results.DkimRecords) == 0 {
		return 0
	}

	hasValid := false
	for _, dkim := range *results.DkimRecords {
		if dkim.Valid {
			hasValid = true
			break
		}
	}

	if !hasValid {
		return 25
	}

	score = 100

	// Apply security penalties on the best valid record
	for _, dkim := range *results.DkimRecords {
		if !dkim.Valid {
			continue
		}

		// SHA-1 signing is deprecated (RFC 8301)
		if dkim.SigningAlgorithm != nil && strings.HasSuffix(*dkim.SigningAlgorithm, "-sha1") {
			if score > 60 {
				score = 60
			}
		}

		// Key size penalties apply only to RSA
		keyType := ""
		if dkim.KeyType != nil {
			keyType = strings.ToLower(*dkim.KeyType)
		}
		if keyType == "rsa" || keyType == "" {
			if dkim.KeySize != nil {
				switch {
				case *dkim.KeySize < 1024:
					if score > 25 {
						score = 25
					}
				case *dkim.KeySize < 2048:
					if score > 75 {
						score = 75
					}
				}
			}
		}
		// Ed25519 keys (256-bit curve, ~3000-bit RSA equivalent) need no penalty.
	}

	return
}
