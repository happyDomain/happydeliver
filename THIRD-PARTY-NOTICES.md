# Third-party notices

happyDeliver embeds third-party material whose license differs from the
project's own terms. This file lists that material, where it comes from and
what its license requires.

## URL shortener domain list

- **File**: `pkg/analyzer/data/url-shorteners.list`
- **Upstream**: [PeterDaveHello/url-shorteners](https://github.com/PeterDaveHello/url-shorteners),
  by PeterDave Hello and contributors
- **License**: [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/),
  full text in `pkg/analyzer/data/url-shorteners.LICENSE`
- **Modified**: no (kept as a separate, unmodified file to avoid ShareAlike
  obligations spreading to the rest of the codebase; happyDeliver's own
  additions to the list live as Go code in `pkg/analyzer/url_shorteners.go`)

Used to recognise links that hide their destination behind a URL shortening
service.

**To refresh the list**, re-download it (and its license text) with:

```sh
go generate -tags refresh_shorteners ./pkg/analyzer/
```
