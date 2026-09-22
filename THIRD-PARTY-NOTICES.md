# Third-party notices

happyDeliver embeds third-party material whose license differs from the
project's own terms. This file lists that material, where it comes from and
what its license requires. Each dataset lives in a package of its own under
`pkg/emaildata/`, which holds the embedded copy, its license text and the
directive that refreshes it.

## URL shortener domain list

- **File**: `pkg/emaildata/shorteners/data/url-shorteners.list`
- **Upstream**: [PeterDaveHello/url-shorteners](https://github.com/PeterDaveHello/url-shorteners),
  by PeterDave Hello and contributors
- **License**: [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/),
  full text in `pkg/emaildata/shorteners/data/url-shorteners.LICENSE`
- **Modified**: no (kept as a separate, unmodified file to avoid ShareAlike
  obligations spreading to the rest of the codebase; happyDeliver's own
  additions to the list live as Go code in `pkg/analyzer/url_shorteners.go`,
  outside the package holding the list)

Used to recognise links that hide their destination behind a URL shortening
service.

**To refresh the list**, re-download it (and its license text) with:

```sh
go generate -tags refresh_shorteners ./pkg/emaildata/shorteners/
```

## Disposable email domain list

- **File**: `pkg/emaildata/disposable/data/disposable_email_blocklist.conf`
- **Upstream**: [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains),
  by Martin and contributors
- **License**: [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/),
  a public domain dedication, full text in
  `pkg/emaildata/disposable/data/disposable_email_blocklist.LICENSE`
- **Modified**: no

Used to recognise a sender domain that belongs to a throwaway address
provider.

**To refresh the list**, re-download it (and its license text) with:

```sh
go generate -tags refresh_disposable ./pkg/emaildata/disposable/
```

## Free mailbox provider domain list

- **File**: `pkg/emaildata/freemail/data/free-email-domains.json`
- **Upstream**: [Kikobeats/free-email-domains](https://github.com/Kikobeats/free-email-domains),
  by Kiko Beats and contributors
- **License**: [MIT](https://opensource.org/licenses/MIT),
  full text in `pkg/emaildata/freemail/data/free-email-domains.LICENSE`
- **Modified**: no

Used to tell a personal mailbox at a public provider from a domain the sender
controls.

**To refresh the list**, re-download it (and its license text) with:

```sh
go generate -tags refresh_freemail ./pkg/emaildata/freemail/
```

## Email client support data

- **File**: `pkg/emaildata/caniemail/data/caniemail.json`
- **Upstream**: [Can I email…](https://www.caniemail.com/api/data.json),
  [hteumeuleu/caniemail](https://github.com/hteumeuleu/caniemail), by Rémi
  Parmentier and contributors
- **License**: MIT, full text in `pkg/emaildata/caniemail/data/caniemail.LICENSE`
- **Modified**: no (embedded exactly as published; which of its features
  happyDeliver looks for, and what it advises a sender to do instead, live as Go
  code in `pkg/analyzer/content_clientcompat.go`, outside the package holding
  the data)

Used to tell a sender which email clients will not render the CSS their message
is built with, by name rather than in general.

**To refresh the data**, re-download it (and its license text) with:

```sh
go generate -tags refresh_caniemail ./pkg/emaildata/caniemail/
```

## rspamd symbol descriptions

- **File**: `pkg/rspamd/data/rspamd-symbols.json`
- **Upstream**: [rspamd](https://github.com/rspamd/rspamd), by Vsevolod Stakhov
  and contributors, read from the `/symbols` endpoint of a running instance
- **License**: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), full
  text in `pkg/rspamd/data/rspamd.LICENSE`
- **Modified**: no (each description is embedded exactly as rspamd publishes
  it; how much a symbol weighs on a report, and what happyDeliver advises a
  sender to do about it, live as Go code in `pkg/analyzer/`)

Used to say, in a sender's own terms, what a symbol an rspamd scan returned
means. A configured instance is asked first; this copy is what answers when
there is none.

**To refresh the descriptions**, see `pkg/rspamd/README.md`.

## Mark Verifying Authority root certificates

- **File**: `pkg/bimi/roots/vmc-roots.pem`
- **Upstream**: the authorities the [BIMI Group](https://bimigroup.org/vmc-issuers/)
  recognises, each root fetched from its own publisher by
  `pkg/bimi/roots/update.sh`: DigiCert, GlobalSign, SSL.com
- **License**: none accompanies the certificates. An authority publishes its
  root precisely so that it can be carried in the trust stores that check the
  certificates it issues.
- **Modified**: no (each certificate is embedded exactly as issued; which
  authorities are recognised follows the BIMI Group's list, and what
  happyDeliver makes of a chain that leads to one of them lives as Go code in
  `pkg/bimi/`)

Used to anchor the certificate chain of a BIMI Verified Mark Certificate, which
no system trust store holds.

**To refresh the bundle**, re-fetch each root and check the printed
fingerprints against the authority's own repository before committing:

```sh
./pkg/bimi/roots/update.sh
```
