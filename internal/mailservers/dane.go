// This file is part of the happyDeliver (R) project.
// Copyright (c) 2026 happyDomain
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

package mailservers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	dane "git.happydns.org/checker-dane/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"
	tlschecker "git.happydns.org/checker-tls/checker"
	"github.com/miekg/dns"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
)

// checkDANE looks up the TLSA records of every probed MX host, and has the
// rules of checker-dane tell whether the certificate each of its addresses
// presented matches them.
func (p *Prober) checkDANE(ctx context.Context, targets []*target) {
	for _, t := range targets {
		if !t.safe {
			continue
		}
		records, validated := p.lookupTLSA(ctx, t.host)
		if len(records) == 0 {
			continue
		}
		t.server.TlsaRecords = utils.PtrTo(len(records))
		t.server.TlsaDnssec = utils.PtrTo(validated)

		data, err := collectDANE(ctx, t.host, records, validated)
		for _, ep := range t.addrs {
			if !ep.Probed || ep.SkipReason != nil {
				continue
			}
			verdict, message := model.MailServerEndpointDaneUnverified, ""
			probe, hasProbe := t.certs[canonicalIP(ep.Ip)]
			switch {
			case err != nil:
				message = fmt.Sprintf("The TLSA records could not be read: %s.", err)
			case !validated:
				message = "The TLSA records were not validated with DNSSEC, so senders ignore them."
			case !hasProbe || !probe.TLSHandshakeOK:
				message = "No certificate was obtained from this address to compare with the TLSA records."
			default:
				verdict, message = evaluateDANE(ctx, data, probe)
			}
			ep.Dane = utils.PtrTo(verdict)
			if message != "" {
				ep.DaneMessage = utils.PtrTo(message)
			}
		}
	}
}

// collectDANE hands the TLSA records of host to checker-dane, shaped as the
// svcs.TLSAs service it reads them from in happyDomain.
func collectDANE(ctx context.Context, host string, records []*dns.TLSA, validated bool) (*dane.DANEData, error) {
	var tlsa []map[string]any
	for _, r := range records {
		tlsa = append(tlsa, map[string]any{
			"Hdr":          map[string]any{"Name": "_25._tcp." + host + "."},
			"Usage":        r.Usage,
			"Selector":     r.Selector,
			"MatchingType": r.MatchingType,
			"Certificate":  strings.ToLower(r.Certificate),
		})
	}
	opts := sdk.CheckerOptions{
		dane.OptionService: map[string]any{
			"_svctype": "svcs.TLSAs",
			"_domain":  host,
			"Service":  map[string]any{"tlsa": tlsa},
		},
		dane.OptionDomain:          host,
		dane.OptionDNSSECValidated: validated,
	}
	raw, err := dane.Provider().Collect(ctx, opts)
	if err != nil {
		return nil, err
	}
	data, ok := raw.(*dane.DANEData)
	if !ok || data == nil {
		return nil, fmt.Errorf("unexpected DANE observation %T", raw)
	}
	return data, nil
}

// evaluateDANE runs the rules of checker-dane against one TLS probe.
func evaluateDANE(ctx context.Context, data *dane.DANEData, probe tlschecker.TLSProbe) (model.MailServerEndpointDane, string) {
	obs := &daneObservations{data: data, probe: probe}
	matched := false
	for _, rule := range dane.Rules() {
		for _, state := range rule.Evaluate(ctx, obs, nil) {
			switch {
			case state.Status == sdk.StatusCrit:
				return model.MailServerEndpointDaneMismatch, state.Message
			case state.Code == "dane_match_ok":
				matched = true
			}
		}
	}
	if matched {
		return model.MailServerEndpointDaneMatch, ""
	}
	return model.MailServerEndpointDaneUnverified, "The TLSA records could not be compared with the certificate."
}

// daneObservations serves the rules of checker-dane its own observation, and
// the TLS probe of one address as the related observation of every target:
// the rules then judge that address alone.
type daneObservations struct {
	data  *dane.DANEData
	probe tlschecker.TLSProbe
}

func (o *daneObservations) Get(_ context.Context, key sdk.ObservationKey, dest any) error {
	if key != dane.ObservationKeyDANE {
		return fmt.Errorf("no observation %q", key)
	}
	raw, err := json.Marshal(o.data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

func (o *daneObservations) GetRelated(_ context.Context, key sdk.ObservationKey) ([]sdk.RelatedObservation, error) {
	if key != tlschecker.ObservationKeyTLSProbes {
		return nil, nil
	}
	probes := map[string]tlschecker.TLSProbe{}
	for _, t := range o.data.Targets {
		probes[t.Ref] = o.probe
	}
	raw, err := json.Marshal(tlschecker.TLSData{Probes: probes})
	if err != nil {
		return nil, err
	}
	var related []sdk.RelatedObservation
	for _, t := range o.data.Targets {
		related = append(related, sdk.RelatedObservation{Key: key, Data: raw, Ref: t.Ref})
	}
	return related, nil
}
