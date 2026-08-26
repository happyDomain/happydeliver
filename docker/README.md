# happyDeliver Docker Configuration

This directory contains all configuration files for the all-in-one Docker container.

## Architecture

The Docker container integrates multiple components:

- **Postfix**: Mail Transfer Agent (MTA) that receives emails on port 25
- **authentication_milter**: SPF, DKIM, DMARC, ARC, BIMI, IPRev, PTR and TLS verification
- **SpamAssassin**: Spam scoring and content analysis, through `spamass-milter`
- **rspamd**: Second spam filter, through its milter proxy worker
- **happyDeliver**: Go application (API server + LMTP receiver + email analyzer)
- **Supervisor**: Process manager that runs all services

## Directory Structure

```
docker/
├── postfix/
│   ├── main.cf              # Postfix main configuration
│   ├── master.cf            # Postfix service definitions
│   └── transport_maps       # Email routing rules
├── authentication_milter/
│   ├── authentication_milter.json  # Handlers and authserv-id
│   └── mail-dmarc.ini              # Mail::DMARC settings
├── rspamd/
│   └── local.d/             # Milter proxy worker, actions, headers
├── spamassassin/
│   └── local.cf             # SpamAssassin rules and scoring
├── supervisor/
│   └── supervisord.conf     # Supervisor service definitions
└── entrypoint.sh            # Container initialization script
```

## Configuration Details

### Postfix (postfix/)

**main.cf**: Core Postfix settings
- Configures hostname, domain, and network interfaces
- Chains the three milters: authentication_milter, spamass-milter, rspamd
- Authorizes `XCLIENT` from loopback, for the relay front-end (see Ports below)
- Uses transport_maps to route test emails to happyDeliver

**master.cf**: Service definitions
- Defines the SMTP service and the standard Postfix helper services

**transport_maps**: PCRE-based routing
- Matches test-UUID@domain emails
- Routes them to the happyDeliver LMTP server on `127.0.0.1:2525`

### authentication_milter (authentication_milter/)

**authentication_milter.json**: the only component that authenticates mail
- Handlers: SPF, DKIM, DMARC, ARC, BIMI, IPRev, PTR, TLS, SenderID, Auth, AlignedFrom
- Writes the `Authentication-Results` headers happyDeliver later parses
- `authserv_id` is the container hostname, which is what happyDeliver trusts
- The `Sanitize` handler strips inbound headers claiming that same authserv-id
- Set `MILTER_DEBUG=1` to turn on verbose tracing

**mail-dmarc.ini**: Mail::DMARC settings used by the DMARC handler (reporting disabled)

### SpamAssassin (spamassassin/)

**local.cf**: Spam detection rules
- Enables network tests (RBL checks)
- SPF and DKIM checking
- Required score: 5.0 (standard threshold)
- Adds detailed spam report headers
- 5-second RBL timeout

### Supervisor (supervisor/)

**supervisord.conf**: Service orchestration
- Runs all services as daemons
- Start order: milters → rspamd → spamd → Postfix → API
- Automatic restart on failure
- Centralized logging

### Entrypoint Script (entrypoint.sh)

Initialization script that:
1. Creates required directories and sets permissions
2. Replaces configuration placeholders with environment variables
3. Initializes Postfix (aliases, transport maps)
4. Updates SpamAssassin rules
5. Starts Supervisor to launch all services

### happyDeliver Configuration

Defaults for the Docker environment are set as `HAPPYDELIVER_*` environment variables in the
`Dockerfile`: API server on `:8080`, SQLite database at
`/var/lib/happydeliver/happydeliver.db`, `test-` address prefix, and the DNS/HTTP timeouts.
Every command-line flag can be overridden the same way (`_` becomes `-`, lowercased).

## Environment Variables

The container accepts these environment variables:

- `HAPPYDELIVER_DOMAIN`: Email domain for test addresses (default: happydeliver.local)
- `HAPPYDELIVER_RECEIVER_HOSTNAME`: Hostname used to filter `Authentication-Results` headers (see below)
- `POSTFIX_CERT_FILE` / `POSTFIX_KEY_FILE`: TLS certificate and key paths for Postfix SMTP
- `MILTER_DEBUG`: set to `1` for verbose authentication_milter logging
- `HAPPYDELIVER_RELAY_ADDR` / `HAPPYDELIVER_RELAY_TRUSTED_NETS`: enable the relay front-end
  when the host's port 25 belongs to another MTA (see Ports below)

### Receiver Hostname

happyDeliver filters `Authentication-Results` headers by hostname to only trust results from the expected MTA. By default, it uses the system hostname (i.e., the container's `--hostname`).

In the all-in-one Docker container, the container hostname is also used as the `authserv-id` in the embedded Postfix and authentication_milter, so everything matches automatically.

**When bypassing the embedded Postfix** (e.g., routing emails from your own MTA via LMTP), your MTA's `authserv-id` will likely differ from the container hostname. In that case, set `HAPPYDELIVER_RECEIVER_HOSTNAME` to your MTA's hostname:

```bash
docker run -d \
  -e HAPPYDELIVER_DOMAIN=example.com \
  -e HAPPYDELIVER_RECEIVER_HOSTNAME=mail.example.com \
  ...
```

To find the correct value, look at the `Authentication-Results` headers in a received email — they start with the authserv-id, e.g. `Authentication-Results: mail.example.com; spf=pass ...`.

If the value is misconfigured, happyDeliver will log a warning when the last `Received` hop doesn't match the expected hostname.

Example (all-in-one, no override needed):
```bash
docker run -e HAPPYDELIVER_DOMAIN=example.com --hostname mail.example.com ...
```

Example (external MTA integration):
```bash
docker run -e HAPPYDELIVER_DOMAIN=example.com -e HAPPYDELIVER_RECEIVER_HOSTNAME=mail.example.com ...
```

## Volumes

**Required volumes:**
- `/var/lib/happydeliver`: Database and persistent data
- `/var/log/happydeliver`: Log files from all services

**Optional volumes:**
- `/etc/happydeliver/config.yaml`: Custom configuration file

## Ports

- **25**: SMTP (Postfix)
- **8080**: HTTP API (happyDeliver)
- **10025**: XFORWARD-to-XCLIENT relay, disabled unless `HAPPYDELIVER_RELAY_ADDR` is set

Internal only: **2525** (happyDeliver LMTP) and **11334** (rspamd HTTP).

The relay exists for hosts whose port 25 already belongs to another MTA. That MTA relays test
messages to port 10025 with `XFORWARD`; the relay replays them to the container's Postfix with
`XCLIENT`, so the milters keep evaluating SPF, IPRev, PTR and DMARC against the original
sender rather than against the front MTA. Only peers listed in
`HAPPYDELIVER_RELAY_TRUSTED_NETS` may restate the client identity — anyone who can do so can
forge an `spf=pass`. See the main README for the host-side Postfix configuration.

## Service Startup Order

Supervisor ensures services start in the correct order:

1. **syslogd** (priority 9): collects the mail logs
2. **spamass-milter** (priority 7) and **authentication_milter** (priority 10)
3. **rspamd** (priority 11) and **spamd** (priority 12)
4. **Postfix** (priority 20): MTA that uses the above milters
5. **happyDeliver API** (priority 30): REST API and LMTP server

## Email Processing Flow

1. Email arrives at Postfix on port 25 (or through the relay on 10025)
2. Postfix runs the milter chain, in order:
   - **authentication_milter** adds the `Authentication-Results` headers
     (`spf=`, `dkim=`, `dmarc=`, `arc=`, `bimi=`, `iprev=`, `x-ptr=`, `x-tls=`, …)
   - **spamass-milter** adds `X-Spam-Status`, `X-Spam-Level` and `X-Spam-Report`
   - **rspamd** adds `X-Spamd-Result`
3. Postfix checks transport_maps
   - If the recipient matches the test-UUID pattern, deliver over LMTP to `127.0.0.1:2525`
4. happyDeliver receives the email
   - Extracts the test ID from the recipient
   - Parses the headers added above, trusting only the expected authserv-id
   - Performs additional analysis (DNS, RBL, content)
   - Generates a deliverability score and stores the report
