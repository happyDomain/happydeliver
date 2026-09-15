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
	"time"

	"git.happydns.org/happyDeliver/internal/model"
)

// Scan is what one engine said about one file, in the terms every engine
// answers in.
//
// The engines do not agree on their own vocabulary: one says "infected" where
// another says "malicious". What is written here is the report's vocabulary,
// and each adapter is the one place its engine's words are translated into
// it. So a scanner added tomorrow is one file, holding its
// flags, its scannerDef and its adapter, plus a line in knownScanners, and
// touches neither the checks, nor the score, nor the schema.
type Scan struct {
	// Scanner names the engine that answered. It is the name its findings are
	// attributed to, and the name the report shows.
	Scanner string

	// Status is what the engine made of the file, or why it has no verdict:
	// "not asked" is a status of its own, so that a reader never has to read
	// silence as a clean bill.
	Status model.ScanResultStatus

	// Verdict is what the engine called what it recognised, when it named it.
	Verdict string

	// Detail is what the scanner said beyond its status, and the only place an
	// error or a skip explains itself.
	Detail string

	// Metadata is whatever else this engine reports and no field above holds.
	Metadata map[string]string
}

// scannerInfo is an engine as the analysis knows of it, whether or not this
// instance runs it.
type scannerInfo struct {
	Name  string
	Label string
}

// scannerDef is an engine as the registry lists it. Each engine declares its
// own flags next to its build, in its own file.
type scannerDef struct {
	scannerInfo

	// build is the engine as this instance runs it, or nil when the operator
	// did not configure it. timeout bounds each of its scans.
	build func(timeout time.Duration) scanner
}

// knownScanners is every engine the analysis knows how to ask. This is the one
// list to grow to add a scanner: the checks are read off it, so is what a
// report says about a file nobody scanned, and so are the engines New runs.
//
// It is written out rather than filled by each file's init: the order is
// meaningful, and the order Go runs init functions in is the order of the
// file names.
var knownScanners = []scannerDef{
	clamavDef,
}

// scanner is an engine an attachment may be handed to.
//
// It answers a Scan rather than an error: an engine that could not be reached
// has said something about the file, namely that nothing is known about it,
// and that is a line of the report rather than a failure of the analysis.
type scanner interface {
	info() scannerInfo
	scan(ctx context.Context, attachment *Attachment) Scan
}
