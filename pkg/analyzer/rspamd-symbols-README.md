# rspamd-symbols.json

This file contains rspamd symbol descriptions, embedded into the binary at compile time as a fallback when no rspamd API URL is configured.

## How to update

Fetch the latest symbols from a running rspamd instance:

```sh
curl http://127.0.0.1:11334/symbols > rspamd-symbols.json
```

Or with docker:

```sh
docker run --rm --name rspamd --pull always rspamd/rspamd
docker exec -u 0 rspamd apt install -y curl
docker exec rspamd curl http://127.0.0.1:11334/symbols > rspamd-symbols.json
```

Then rebuild the project.
