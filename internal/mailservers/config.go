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
	"log"
	"strings"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/pkg/analyzer"
	"git.happydns.org/happyDeliver/pkg/domainname"
)

// NewFromConfig builds the service the configuration describes, or nil when
// the probes are disabled.
func NewFromConfig(cfg *config.Config) *Service {
	if cfg.DisableMXProbes {
		return nil
	}

	secure, err := analyzer.NewValidatingResolver(cfg.Analysis.DNSResolver, cfg.Analysis.DNSTimeout)
	if err != nil {
		log.Printf("DANE checks of the mail servers disabled: %v", err)
		secure = nil
	}
	resolver := analyzer.NewStandardDNSResolver()

	helo := cfg.Analysis.MXProbe.HeloName
	if helo == "" {
		helo = cfg.Email.ReceiverHostname
	}
	if !isHostname(helo) {
		helo = ""
	}

	opts := Options{
		Timeout:        cfg.Analysis.MXProbe.Timeout,
		DNSTimeout:     cfg.Analysis.DNSTimeout,
		HeloName:       helo,
		RelayRecipient: RelayRecipient(cfg.Email.Domain),
		Witness:        cfg.Analysis.MXProbe.Witness,
	}
	if opts.RelayRecipient == "" {
		log.Printf("Open relay test of the mail servers disabled: the receiving domain %q is not a public domain", cfg.Email.Domain)
	}
	policies := analyzer.NewMailPolicyChecker(cfg.Analysis.DNSTimeout, cfg.Analysis.HTTPTimeout, resolver)
	return NewService(NewProber(opts, resolver, secure, policies), cfg.Analysis.MXProbe.CacheTTL)
}

// RelayRecipient is the address the open relay test sends to: one of the
// receiving domain of the instance, so that a relay accepting it would only
// ever bring a message back here, and the transaction stops at RCPT anyway.
// Empty, the test is skipped, when that domain is not a public one, as with
// the default happydeliver.local.
func RelayRecipient(receivingDomain string) string {
	d := domainname.Normalize(receivingDomain)
	if !isHostname(d) || !strings.Contains(d, ".") {
		return ""
	}
	for _, reserved := range []string{".local", ".localhost", ".test", ".invalid", ".example", ".internal", ".lan", ".home.arpa"} {
		if strings.HasSuffix(d, reserved) {
			return ""
		}
	}
	if domainname.Organizational(d) == "" {
		return ""
	}
	return "relay-test@" + d
}

// isHostname tells whether s can be written into an SMTP command as a
// hostname: letters, digits, dots and hyphens.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}
