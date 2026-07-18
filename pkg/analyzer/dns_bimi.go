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

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
)

// checkBIMIRecord looks up and validates the BIMI record for a domain and
// selector. The actual validation lives in the reusable pkg/bimi package;
// this method adapts its result to the API model.
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector string) *model.BIMIRecord {
	validator := &bimi.Validator{
		HTTPClient: d.httpClient,
		Resolver:   d.resolver,
	}

	// Bound only the DNS lookup by d.Timeout. Asset validation runs with a
	// deadline-free context so each logo/VMC download gets its own independent
	// budget from d.httpClient.Timeout, rather than sharing a single deadline
	// across the DNS lookup and both fetches (a slow-but-valid VMC would
	// otherwise fail once the logo download consumed most of the budget).
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
	if r.VMC != nil {
		m.Vmc = bimiVMCToModel(r.VMC)
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
			messages := c.Messages
			out[i].Messages = &messages
		}
	}
	return out
}

func bimiVMCToModel(v *bimi.VMCInfo) *model.VMCInfo {
	m := &model.VMCInfo{
		Valid:       v.Valid,
		HasBimiEku:  v.HasBimiEku,
		HasLogotype: v.HasLogotype,
		LogoMatches: v.LogoMatches,
	}
	if v.Issuer != "" {
		m.Issuer = utils.PtrTo(v.Issuer)
	}
	if v.Subject != "" {
		m.Subject = utils.PtrTo(v.Subject)
	}
	if v.SerialNumber != "" {
		m.SerialNumber = utils.PtrTo(v.SerialNumber)
	}
	if !v.NotBefore.IsZero() {
		m.NotBefore = utils.PtrTo(v.NotBefore)
	}
	if !v.NotAfter.IsZero() {
		m.NotAfter = utils.PtrTo(v.NotAfter)
	}
	if v.ChainLength > 0 {
		m.ChainLength = utils.PtrTo(v.ChainLength)
	}
	if len(v.SanDomains) > 0 {
		m.SanDomains = utils.PtrTo(v.SanDomains)
	}
	if v.Error != "" {
		m.Error = utils.PtrTo(v.Error)
	}
	return m
}
