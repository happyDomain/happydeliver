# rspamd symbol descriptions

`data/rspamd-symbols.json` holds rspamd symbol descriptions, embedded into the binary at compile time as a fallback when no rspamd API URL is configured.

## How to update

Fetch the latest symbols from a running rspamd instance:

```sh
curl http://127.0.0.1:11334/symbols > data/rspamd-symbols.json
```

Or with docker:

```sh
docker run --rm --name rspamd --pull always rspamd/rspamd
docker exec -u 0 rspamd apt install -y curl
docker exec rspamd curl http://127.0.0.1:11334/symbols > data/rspamd-symbols.json
```

Then rebuild the project.

The descriptions are rspamd's own, published under Apache-2.0; `data/rspamd.LICENSE`
is the license text shipped with them, and `happyDeliver licenses` prints it. Refresh
it from the same release you took the symbols from:

```sh
curl -sSfL -o data/rspamd.LICENSE https://raw.githubusercontent.com/rspamd/rspamd/master/LICENSE.md
```
