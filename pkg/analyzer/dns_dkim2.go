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

// DKIM2 (draft-ietf-dkim-dkim2-spec, draft-ietf-dkim-dkim2-dns) keeps its keys
// where DKIM1 keeps them, at <selector>._domainkey.<domain>, in the same
// record format, v=DKIM1 included: one key can serve both. What changes is how
// a verifier reads it: the h=, n=, s= and t= tags are deprecated, an empty p=
// revokes the key, the k= type must match the algorithm of the signature, and
// RSA keys may be published as RSAPublicKey as well as SubjectPublicKeyInfo.
// A Domain Policy Record at _domainkey.<domain> may also forbid subdomains to
// make From header fields of the domain Authentic.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"git.happydns.org/happyDeliver/internal/model"
	"git.happydns.org/happyDeliver/internal/utils"
	"git.happydns.org/happyDeliver/pkg/mailmsg"
)

// Points of the DNS section the DKIM2 keys may cost at most. DKIM2 is still an
// IETF draft, so its keys weigh lightly, on top of the checks the section
// averages, and never more than this all together.
const (
	dkim2PenaltyMax     = 5
	dkim2PenaltyInvalid = 5
	dkim2PenaltyKeyWeak = 2
)

// dkim2KeyTypes maps each signing algorithm DKIM2 defines to the key type
// (k= value) a key used with it must declare.
var dkim2KeyTypes = map[string]string{
	"rsa-sha256":     "rsa",
	"ed25519-sha256": "ed25519",
	"mldsa44":        "mldsa44",
}

// dkim2DeprecatedTags are the deprecated key record tags: DKIM2 verifiers ignore
// them, and DKIM1 records should not use them either.
var dkim2DeprecatedTags = []string{"h", "n", "s", "t"}

// Raw public key lengths, in octets, of the key types whose length is fixed.
const (
	ed25519KeyLen = 32   // RFC 8032
	mldsa44KeyLen = 1312 // FIPS 204
)

// dkim2RSAMinBits is the shortest RSA key a DKIM2 signer may use: verifiers
// have no need to accept anything shorter.
const dkim2RSAMinBits = 1024

// checkDKIM2Records looks up the key of each selector of each DKIM2 signature.
func (d *DNSAnalyzer) checkDKIM2Records(signatures []mailmsg.DKIM2Signature) []model.DKIM2Record {
	var records []model.DKIM2Record
	for _, sig := range signatures {
		seen := map[string]bool{}
		for _, key := range sig.Keys {
			// A selector named twice in one signature is the signer trying to
			// confuse the verifier, whatever its key says.
			if seen[key.Selector] {
				records = append(records, model.DKIM2Record{
					Instance:         sig.Instance,
					Alternative:      utils.PtrTo(key.Group),
					Selector:         key.Selector,
					Domain:           sig.Domain,
					SigningAlgorithm: signingAlgorithmPtr(key.Algorithm),
					Error:            utils.PtrTo(fmt.Sprintf("PERMERROR: DKIM2-Signature i=%d has a duplicate selector", sig.Instance)),
				})
				continue
			}
			seen[key.Selector] = true
			records = append(records, *d.checkDKIM2Record(sig, key))
		}
	}
	return records
}

// checkDKIM2Record looks up the key a DKIM2 signature names, and says whether
// a DKIM2 verifier could use it to check that signature. An error the draft has
// words for is worded as it asks verifiers to, with in parentheses what helps
// fixing it.
func (d *DNSAnalyzer) checkDKIM2Record(sig mailmsg.DKIM2Signature, key mailmsg.DKIM2Key) *model.DKIM2Record {
	rec := &model.DKIM2Record{
		Instance:         sig.Instance,
		Alternative:      utils.PtrTo(key.Group),
		Selector:         key.Selector,
		Domain:           sig.Domain,
		SigningAlgorithm: signingAlgorithmPtr(key.Algorithm),
	}
	fail := func(state, what string) *model.DKIM2Record {
		rec.Valid = false
		rec.Error = utils.PtrTo(fmt.Sprintf("%s: DKIM2-Signature i=%d public key %s %s", state, sig.Instance, key.Selector, what))
		return rec
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, fmt.Sprintf("%s._domainkey.%s", key.Selector, sig.Domain))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return fail("PERMERROR", "does not exist")
		}
		return fail("TEMPERROR", fmt.Sprintf("could not be fetched (%s)", formatDNSError(err)))
	}

	// Records beginning with another version than DKIM1 are not key records.
	var keys, foreign []string
	for _, txt := range txtRecords {
		if v := leadingVersion(txt); v != "" && v != "DKIM1" {
			foreign = append(foreign, v)
			continue
		}
		keys = append(keys, txt)
	}
	switch {
	case len(keys) == 0:
		if len(foreign) > 0 {
			if desc := describeMisplacedRecord(foreign[0], "DKIM"); desc != "" {
				return fail("PERMERROR", fmt.Sprintf("does not exist (%s is published there instead)", desc))
			}
		}
		return fail("PERMERROR", "does not exist")
	case len(keys) > 1:
		return fail("PERMERROR", "has multiple records")
	}

	record := keys[0]
	rec.Record = &record

	tags, ok := parseTagList(record)
	if !ok {
		return fail("PERMERROR", "has a syntax error")
	}

	var deprecated []string
	for _, tag := range dkim2DeprecatedTags {
		if _, present := tags[tag]; present {
			deprecated = append(deprecated, tag)
		}
	}
	if deprecated != nil {
		rec.DeprecatedTags = &deprecated
	}

	p, hasP := tags["p"]
	if !hasP {
		return fail("PERMERROR", "has a syntax error (no p= tag)")
	}

	keyType := tags["k"]
	if keyType == "" {
		keyType = "rsa"
	}
	rec.KeyType = &keyType

	if p == "" {
		return fail("PERMERROR", "has been revoked")
	}

	expected, known := dkim2KeyTypes[key.Algorithm]
	if !known {
		rec.Error = utils.PtrTo(fmt.Sprintf("PERMERROR: DKIM2-Signature i=%d selector %s algorithm unknown", sig.Instance, key.Selector))
		return rec
	}
	if keyType != expected {
		return fail("PERMERROR", fmt.Sprintf("algorithm mismatch (k=%s, signature made with %s)", keyType, key.Algorithm))
	}

	der, err := decodeKeyData(p)
	if err != nil {
		return fail("PERMERROR", "has a syntax error (p= is not valid padded base64)")
	}

	switch keyType {
	case "rsa":
		pub, err := parseRSAPublicKey(der)
		if err != nil {
			return fail("PERMERROR", "is malformed (p= is neither a SubjectPublicKeyInfo nor an RSAPublicKey)")
		}
		rec.KeySize = utils.PtrTo(pub.N.BitLen())
		if pub.N.BitLen() < dkim2RSAMinBits {
			return fail("PERMERROR", "too short")
		}
	case "ed25519":
		if len(der) != ed25519KeyLen {
			return fail("PERMERROR", fmt.Sprintf("is malformed (an Ed25519 key is the %d raw octets, not %d)", ed25519KeyLen, len(der)))
		}
		rec.KeySize = utils.PtrTo(ed25519KeyLen * 8)
	case "mldsa44":
		if len(der) != mldsa44KeyLen {
			return fail("PERMERROR", fmt.Sprintf("is malformed (an ML-DSA-44 key is %d octets, not %d)", mldsa44KeyLen, len(der)))
		}
	}

	rec.Valid = true
	return rec
}

// parseTagList splits a tag=value list, and says whether it is one: a tag
// written twice, or a part that is no tag=value, makes the whole list invalid.
func parseTagList(record string) (map[string]string, bool) {
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, false
		}
		if _, dup := tags[name]; dup {
			return nil, false
		}
		tags[name] = strings.TrimSpace(value)
	}
	return tags, true
}

// decodeKeyData decodes the base64 of a p= tag, which may hold whitespace and
// must be padded, with zero bits and trailing = characters.
func decodeKeyData(p string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(strings.Join(strings.Fields(p), ""))
}

// parseRSAPublicKey reads an RSA key published either way DKIM2 accepts:
// SubjectPublicKeyInfo, as nearly everyone publishes it, or the bare
// RSAPublicKey RFC 6376 literally asks for.
func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("not an RSA key")
	}
	return x509.ParsePKCS1PublicKey(der)
}

// checkDKIM2PolicyRecord reads the DKIM2 Domain Policy Record of a domain, at
// _domainkey.<domain>. No record at all is a valid answer: subdomains are then
// authorized.
func (d *DNSAnalyzer) checkDKIM2PolicyRecord(domain string) model.DKIM2PolicyRecord {
	rec := model.DKIM2PolicyRecord{Domain: domain, Valid: true}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	txtRecords, err := d.resolver.LookupTXT(ctx, "_domainkey."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return rec
		}
		rec.Valid = false
		rec.Error = utils.PtrTo(fmt.Sprintf("TEMPERROR: the Domain Policy Record could not be fetched (%s)", formatDNSError(err)))
		return rec
	}

	// Purported records that do not begin with v=DKIM1 are ignored, such as
	// a DomainKeys (RFC 4870) policy statement left at the same name.
	var policies []string
	for _, txt := range txtRecords {
		if leadingVersion(txt) == "DKIM1" {
			policies = append(policies, txt)
		}
	}
	switch len(policies) {
	case 0:
		return rec
	case 1:
	default:
		rec.Valid = false
		rec.Error = utils.PtrTo("PERMERROR: more than one Domain Policy Record is published")
		return rec
	}

	rec.Record = &policies[0]
	tags, ok := parseTagList(policies[0])
	if !ok {
		rec.Valid = false
		rec.Error = utils.PtrTo("PERMERROR: the Domain Policy Record has a syntax error")
		return rec
	}
	for _, flag := range strings.Split(tags["f"], ":") {
		if strings.TrimSpace(flag) == "strict" {
			rec.Strict = utils.PtrTo(true)
		}
	}
	if rec.Strict == nil {
		rec.Strict = utils.PtrTo(false)
	}
	return rec
}

// hasValidDKIM2Key says whether some DKIM2 signature points to a usable key.
func hasValidDKIM2Key(results *model.DNSResults) bool {
	if results.Dkim2Records == nil {
		return false
	}
	for _, rec := range *results.Dkim2Records {
		if rec.Valid {
			return true
		}
	}
	return false
}

// dkim2KeyIssues says what the keys of the DKIM2 signatures call for changing,
// and how many points of the DNS section that costs: a signature none of
// whose alternatives has usable keys, and weak RSA keys. Deprecated tags are
// told about without costing anything. The points never exceed
// dkim2PenaltyMax.
func dkim2KeyIssues(results *model.DNSResults) ([]model.Issue, int) {
	if results.Dkim2Records == nil || len(*results.Dkim2Records) == 0 {
		return nil, 0
	}
	records := *results.Dkim2Records

	issues := []model.Issue{}
	budget := dkim2PenaltyMax
	charge := func(points int, issue model.Issue) {
		points = min(points, budget)
		budget -= points
		sectionIssue(&issues, points, issue)
	}

	// Signatures, in order, each with its keys by alternative
	type signature struct {
		instance int
		domain   string
		groups   map[int][]model.DKIM2Record
	}
	var signatures []*signature
	for _, rec := range records {
		var sig *signature
		for _, s := range signatures {
			if s.instance == rec.Instance && s.domain == rec.Domain {
				sig = s
			}
		}
		if sig == nil {
			sig = &signature{instance: rec.Instance, domain: rec.Domain, groups: map[int][]model.DKIM2Record{}}
			signatures = append(signatures, sig)
		}
		alt := utils.Deref(rec.Alternative)
		sig.groups[alt] = append(sig.groups[alt], rec)
	}

	for _, sig := range signatures {
		usable := false
		var reasons []string
		for _, alt := range slices.Sorted(maps.Keys(sig.groups)) {
			group := sig.groups[alt]
			all := true
			for _, rec := range group {
				if !rec.Valid {
					all = false
					if reason := utils.Deref(rec.Error); !slices.Contains(reasons, reason) {
						reasons = append(reasons, reason)
					}
				}
			}
			usable = usable || all
		}
		if usable {
			continue
		}
		where := fmt.Sprintf("DKIM2-Signature i=%d (%s)", sig.instance, sig.domain)
		charge(dkim2PenaltyInvalid, newIssue(model.IssueTypeDkim2Invalid, model.IssueSeverityMedium, where,
			fmt.Sprintf("No key of the DKIM2 signature i=%d of %s can be used: %s.", sig.instance, sig.domain, strings.Join(reasons, "; ")),
			"Publish, at each selector the signature names, the public key the DKIM2 signer uses, with a k= tag matching its algorithm; an RSA key needs at least 2048 bits."))
	}

	newKey := "Generate a 2048-bit key under a new selector, publish it, switch your DKIM2 signer to it, then remove the old one."
	for _, rec := range records {
		where := fmt.Sprintf("%s._domainkey.%s", rec.Selector, rec.Domain)
		if rec.Valid && utils.Deref(rec.KeyType) == "rsa" && rec.KeySize != nil && *rec.KeySize < 2048 {
			charge(dkim2PenaltyKeyWeak, newIssue(model.IssueTypeDkim2KeyWeak, model.IssueSeverityLow, where,
				fmt.Sprintf("%s publishes a %d-bit RSA key. DKIM2 signers should use at least 2048 bits.", where, *rec.KeySize),
				newKey))
		}
		if rec.DeprecatedTags != nil && len(*rec.DeprecatedTags) > 0 {
			tags := make([]string, len(*rec.DeprecatedTags))
			for i, tag := range *rec.DeprecatedTags {
				tags[i] = tag + "="
			}
			sectionIssue(&issues, 0, newIssue(model.IssueTypeDkim2DeprecatedTags, model.IssueSeverityInfo, where,
				fmt.Sprintf("The key at %s carries %s, which are deprecated: DKIM2 verifiers ignore them, and DKIM1 records should not use them either.", where, strings.Join(tags, ", ")),
				"Remove them from the key record, even if it also serves DKIM1."))
		}
	}

	return issues, dkim2PenaltyMax - budget
}
