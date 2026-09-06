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
	"time"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/bimi"
)

// DefaultBIMIAssetsTimeout caps the wall time the logo and VMC downloads may
// together add to a report. Each fetch keeps its own budget
// (bimi.DefaultFetchTimeout), but the report is generated synchronously on the
// delivery path: without an overall ceiling, two dead URLs published in a
// single TXT record stall a delivery for the sum of the per-fetch timeouts.
const DefaultBIMIAssetsTimeout = 45 * time.Second

func (d *DNSAnalyzer) bimiAssetsTimeout() time.Duration {
	if d.BIMIAssetsTimeout > 0 {
		return d.BIMIAssetsTimeout
	}
	return DefaultBIMIAssetsTimeout
}

// checkBIMIRecord looks up and validates the BIMI record for a domain and
// selector. The actual validation lives in the reusable pkg/bimi package;
// this method adapts its result to the API model.
//
// localPart is the local-part of the sending address, empty when the analysis
// has no message to take one from. A record publishing an lps= tag serves a
// different Indicator per mailbox, so without it the record reported is the
// one the selector alone leads to, which is not necessarily the one a receiver
// would act on for a given sender.
func (d *DNSAnalyzer) checkBIMIRecord(domain, selector, localPart string) *model.BIMIRecord {
	validator := &bimi.Validator{
		HTTPClient: d.bimiHTTPClient,
		Resolver:   d.resolver,
		// Discovery falls back to the organizational domain, and the VMC
		// is allowed to name it rather than the exact sender: both must
		// agree with the notion DMARC alignment uses elsewhere in the
		// report, including for the names the PSL cannot resolve.
		OrganizationalDomain: getOrganizationalDomain,
		VMCRoots:             d.VMCRoots,
	}

	// Bound Assertion Record discovery by d.Timeout, however many queries it
	// takes (a domain with no record of its own also queries its
	// organizational domain), and the asset downloads by their own, larger
	// budget: pulling a file from a slow host is not the same wait as a TXT
	// query, and sharing a single deadline would fail a slow-but-valid VMC
	// once the logo download consumed most of it.
	lookupCtx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	rec, err := validator.LookupForLocalPart(lookupCtx, domain, selector, localPart)
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
		assetsCtx, cancelAssets := context.WithTimeout(context.Background(), d.bimiAssetsTimeout())
		defer cancelAssets()
		validator.ValidateAssets(assetsCtx, rec)
	}

	return bimiRecordToModel(rec)
}

// bimiRecordToModel converts a *bimi.Record into the API *model.BIMIRecord.
func bimiRecordToModel(r *bimi.Record) *model.BIMIRecord {
	m := &model.BIMIRecord{
		Selector:    r.Selector,
		Domain:      r.Domain,
		RecordValid: utils.PtrTo(r.RecordValid),
		Valid:       r.Valid,
		LogoUrl:     utils.PtrTo(r.LogoURL),
		VmcUrl:      utils.PtrTo(r.VMCURL),
	}
	m.RecordDomain = utils.PtrToNonZero(r.RecordDomain)
	m.RequestedSelector = utils.PtrToNonZero(r.RequestedSelector)
	m.AvatarPreference = utils.PtrToNonZero(r.AvatarPreference)
	m.Record = utils.PtrToNonZero(r.Record)
	m.Error = utils.PtrToNonZero(r.Error)

	if r.LocalPartSelector {
		m.LocalPartSelector = utils.PtrTo(true)
		// An lps= tag published without a prefix matches every
		// local-part, so the empty list is meaningful: send it rather
		// than omitting the field, which would read as no list at all.
		prefixes := r.LocalPartPrefixes
		if prefixes == nil {
			prefixes = []string{}
		}
		m.LocalPartPrefixes = &prefixes
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

func bimiVMCToModel(v *bimi.VMCInfo) *model.VMCInfo {
	m := &model.VMCInfo{
		Valid:                    v.Valid,
		HasBimiEku:               v.HasBimiEku,
		IssuerHasBimiEku:         v.IssuerHasBimiEku,
		HasLogotype:              v.HasLogotype,
		HasCrlDistributionPoints: v.HasCRLDistributionPoints,
		SctCount:                 v.SCTCount,
		ChainTrusted:             v.ChainTrusted,
		LogoMatches:              v.LogoMatches,
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
