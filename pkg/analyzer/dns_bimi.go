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
	"errors"
	"fmt"
	"net/http"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
)

// newBIMIHTTPClient builds the HTTP client used to fetch BIMI logo and VMC
// assets. The only files DNSAnalyzer downloads are published by the domain
// under analysis, so they go through the guarded client of pkg/bimi rather
// than a bare one, with its own timeout: the DNS budget is no measure of a
// file download.
func newBIMIHTTPClient() *http.Client {
	return bimi.NewHTTPClient(0)
}

// checkBIMIRecord looks up and validates the BIMI record for a domain and
// selector. The actual validation lives in the reusable pkg/bimi package;
// this method adapts its result to the API model.
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector string) *model.BIMIRecord {
	validator := &bimi.Validator{
		HTTPClient: d.bimiHTTPClient,
		Resolver:   d.resolver,
	}

	// Bound only the DNS lookup by d.Timeout. Asset validation runs with a
	// deadline-free context so each logo download gets its own independent
	// budget from d.bimiHTTPClient.Timeout, rather than sharing a single deadline
	// with the DNS lookup.
	lookupCtx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	rec, err := validator.Lookup(lookupCtx, domain, selector)
	if err != nil {
		msg := "No BIMI record found"
		if !errors.Is(err, bimi.ErrNoRecord) {
			msg = fmt.Sprintf("Failed to lookup BIMI record: %s", formatDNSError(err))
		}
		return &model.BIMIRecord{
			Selector: selector,
			Domain:   domain,
			Valid:    false,
			Error:    utils.PtrTo(msg),
		}
	}

	if rec.Valid {
		validator.ValidateAssets(context.Background(), rec)
	}

	return bimiRecordToModel(rec)
}

// bimiRecordToModel converts a *bimi.Record into the API *model.BIMIRecord.
func bimiRecordToModel(r *bimi.Record) *model.BIMIRecord {
	m := &model.BIMIRecord{
		Selector: r.Selector,
		Domain:   r.Domain,
		Valid:    r.Valid,
		LogoUrl:  utils.PtrTo(r.LogoURL),
		VmcUrl:   utils.PtrTo(r.VMCURL),
	}
	if r.Record != "" {
		m.Record = utils.PtrTo(r.Record)
	}
	if r.Error != "" {
		m.Error = utils.PtrTo(r.Error)
	}
	if len(r.Checks) > 0 {
		m.Checks = utils.PtrTo(bimiChecksToModel(r.Checks))
	}
	return m
}

func bimiChecksToModel(checks []bimi.Check) []model.BIMICheck {
	out := make([]model.BIMICheck, len(checks))
	for i, c := range checks {
		out[i] = model.BIMICheck{
			Name:        c.Name,
			Description: c.Description,
			Status:      model.BIMICheckStatus(c.Status),
		}
		if len(c.Messages) > 0 {
			messages := make([]model.BIMICheckMessage, len(c.Messages))
			for j, m := range c.Messages {
				messages[j] = model.BIMICheckMessage{
					Text:     m.Text,
					Severity: model.BIMICheckMessageSeverity(m.Severity),
				}
			}
			out[i].Messages = &messages
		}
	}
	return out
}
