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

package bimi

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
	"sync"
)

// embeddedVMCRoots holds the roots of the Mark Verifying Authorities the BIMI
// Group recognises, as gathered by roots/update.sh. They are absent from the
// system trust store, and no authority publishes an aggregated bundle, so the
// set travels with the binary; roots/update.sh refreshes it when an authority
// is added or rolls its root.
//
//go:embed roots/vmc-roots.pem
var embeddedVMCRoots []byte

// DisableVMCRoots is the sentinel LoadVMCRoots understands as "do not anchor
// the chain at all". Which authorities to recognise is receiver policy, and
// recognising none of them is a policy too: it leaves the issuer unexamined
// rather than silently trusted, which AnalyzeVMC reports as such.
const DisableVMCRoots = "none"

var (
	embeddedVMCRootsOnce sync.Once
	embeddedVMCRootsPool *x509.CertPool
	embeddedVMCRootsErr  error
)

// EmbeddedVMCRoots returns the pool built from the roots bundled with the
// binary. The pool is built once and shared: it is immutable, and every
// analysis would otherwise re-parse the same certificates.
func EmbeddedVMCRoots() (*x509.CertPool, error) {
	embeddedVMCRootsOnce.Do(func() {
		embeddedVMCRootsPool, embeddedVMCRootsErr = parseVMCRoots(embeddedVMCRoots, "embedded BIMI root bundle")
	})

	return embeddedVMCRootsPool, embeddedVMCRootsErr
}

// LoadVMCRoots resolves the configured trust anchors into a pool for
// Validator.VMCRoots: an empty path selects the embedded bundle,
// DisableVMCRoots skips the anchoring check and returns a nil pool without
// error, and any other value names a PEM file to read.
func LoadVMCRoots(path string) (*x509.CertPool, error) {
	switch path {
	case DisableVMCRoots:
		return nil, nil
	case "":
		return EmbeddedVMCRoots()
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read BIMI root certificates: %w", err)
	}

	return parseVMCRoots(content, path)
}

// parseVMCRoots builds a pool from PEM content, origin naming where it came
// from in errors.
//
// A pool that ends up empty is an error rather than a permissive default:
// AppendCertsFromPEM ignores what it cannot parse, so a truncated or
// mistakenly-formatted file would otherwise pass for a configured policy and
// leave every chain unanchored without anyone noticing.
func parseVMCRoots(content []byte, origin string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("no valid certificate found in %s", origin)
	}

	return pool, nil
}
