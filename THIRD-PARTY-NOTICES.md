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
