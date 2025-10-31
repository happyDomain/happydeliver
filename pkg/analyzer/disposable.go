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

import "strings"

// disposableDomains is a list of known disposable/temporary email provider domains
// This is a curated subset of common disposable email providers
var disposableDomains = map[string]bool{
	"10minutemail.com":     true,
	"guerrillamail.com":    true,
	"mailinator.com":       true,
	"temp-mail.org":        true,
	"throwaway.email":      true,
	"yopmail.com":          true,
	"tempmail.com":         true,
	"getnada.com":          true,
	"trashmail.com":        true,
	"maildrop.cc":          true,
	"sharklasers.com":      true,
	"guerrillamail.biz":    true,
	"guerrillamail.de":     true,
	"grr.la":               true,
	"spam4.me":             true,
	"fakeinbox.com":        true,
	"mailcatch.com":        true,
	"mintemail.com":        true,
	"mytemp.email":         true,
	"dispostable.com":      true,
	"emailondeck.com":      true,
	"20minutemail.com":     true,
	"moakt.com":            true,
	"mohmal.com":           true,
	"emailsensei.com":      true,
	"crazymailing.com":     true,
	"spambox.us":           true,
	"disposablemail.com":   true,
	"temp-mail.io":         true,
	"tmpmail.net":          true,
	"inboxkitten.com":      true,
	"tmailor.com":          true,
	"armyspy.com":          true,
	"cuvox.de":             true,
	"dayrep.com":           true,
	"einrot.com":           true,
	"fleckens.hu":          true,
	"gustr.com":            true,
	"jourrapide.com":       true,
	"rhyta.com":            true,
	"superrito.com":        true,
	"teleworm.us":          true,
	"harakirimail.com":     true,
	"anonbox.net":          true,
	"anonymbox.com":        true,
	"binkmail.com":         true,
	"bobmail.info":         true,
	"boxformail.in":        true,
	"bugmenot.com":         true,
	"casualdx.com":         true,
	"chacuo.net":           true,
	"chammy.info":          true,
	"deadaddress.com":      true,
	"despam.it":            true,
	"disposeamail.com":     true,
	"dontreg.com":          true,
	"emltmp.com":           true,
	"ezehe.com":            true,
	"filzmail.com":         true,
	"getairmail.com":       true,
	"hidemail.de":          true,
	"instant-mail.de":      true,
	"jetable.org":          true,
	"kontum.de":            true,
	"labetteraverouge.at":  true,
	"lroid.com":            true,
	"mail-temporaire.fr":   true,
	"mail.by":              true,
	"meltmail.com":         true,
	"nospam.ze.tc":         true,
	"objectmail.com":       true,
	"pookmail.com":         true,
	"proxymail.eu":         true,
	"shiftmail.com":        true,
	"sneakemail.com":       true,
	"sofort-mail.de":       true,
	"spamfree24.org":       true,
	"spamgourmet.com":      true,
	"spamify.com":          true,
	"spamspot.com":         true,
	"tempemail.net":        true,
	"temporaryemail.net":   true,
	"trashmailer.com":      true,
	"trialmail.de":         true,
	"willselfdestruct.com": true,
	"wpg.im":               true,
	"yuurok.com":           true,
	"zoemail.org":          true,
}

// IsDisposableEmailDomain checks if a domain is a known disposable email provider
func IsDisposableEmailDomain(domain string) bool {
	// Normalize domain to lowercase
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Direct lookup
	return disposableDomains[domain]
}
