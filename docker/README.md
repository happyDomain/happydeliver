# happyDeliver Docker Configuration

This directory contains all configuration files for the all-in-one Docker container.

## Architecture

The Docker container integrates multiple components:

- **Postfix**: Mail Transfer Agent (MTA) that receives emails on port 25
- **OpenDKIM**: DKIM signature verification
- **OpenDMARC**: DMARC policy validation
- **SpamAssassin**: Spam scoring and content analysis
- **happyDeliver**: Go application (API server + email analyzer)
- **Supervisor**: Process manager that runs all services

## Directory Structure

```
docker/
├── postfix/
│   ├── main.cf              # Postfix main configuration
│   ├── master.cf            # Postfix service definitions
│   └── transport_maps       # Email routing rules
├── opendkim/
│   └── opendkim.conf        # DKIM verification config
├── opendmarc/
│   └── opendmarc.conf       # DMARC validation config
├── spamassassin/
│   └── local.cf             # SpamAssassin rules and scoring
├── supervisor/
│   └── supervisord.conf     # Supervisor service definitions
├── entrypoint.sh            # Container initialization script
└── config.docker.yaml       # happyDeliver default config
```

## Configuration Details

### Postfix (postfix/)

**main.cf**: Core Postfix settings
- Configures hostname, domain, and network interfaces
- Sets up milter integration for OpenDKIM and OpenDMARC
- Configures SPF policy checking
- Routes emails through SpamAssassin content filter
- Uses transport_maps to route test emails to happyDeliver

**master.cf**: Service definitions
- Defines SMTP service with content filtering
- Sets up SPF policy service (postfix-policyd-spf-perl)
- Configures SpamAssassin content filter
- Defines happydeliver pipe for email analysis

**transport_maps**: PCRE-based routing
- Matches test-UUID@domain emails
- Routes them to the happydeliver pipe

### OpenDKIM (opendkim/)

**opendkim.conf**: DKIM verification settings
- Operates in verification-only mode
- Adds Authentication-Results headers
- Socket communication with Postfix via milter
- 5-second DNS timeout

### OpenDMARC (opendmarc/)

**opendmarc.conf**: DMARC validation settings
- Validates DMARC policies
- Adds results to Authentication-Results headers
- Does not reject emails (analysis mode only)
- Socket communication with Postfix via milter

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
- Start order: OpenDKIM → OpenDMARC → SpamAssassin → Postfix → API
- Automatic restart on failure
- Centralized logging

### Entrypoint Script (entrypoint.sh)

Initialization script that:
1. Creates required directories and sets permissions
2. Replaces configuration placeholders with environment variables
3. Initializes Postfix (aliases, transport maps)
4. Updates SpamAssassin rules
5. Starts Supervisor to launch all services

### happyDeliver Config (config.docker.yaml)

Default configuration for the Docker environment:
- API server on 0.0.0.0:8080
- SQLite database at /var/lib/happydeliver/happydeliver.db
- Configurable domain for test emails
- RBL servers for blacklist checking
- Timeouts for DNS and HTTP checks

## Environment Variables

The container accepts these environment variables:

- `HAPPYDELIVER_DOMAIN`: Email domain for test addresses (default: happydeliver.local)
- `HAPPYDELIVER_RECEIVER_HOSTNAME`: Hostname used to filter `Authentication-Results` headers (see below)
- `POSTFIX_CERT_FILE` / `POSTFIX_KEY_FILE`: TLS certificate and key paths for Postfix SMTP

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

## Service Startup Order

Supervisor ensures services start in the correct order:

1. **OpenDKIM** (priority 10): DKIM verification milter
2. **OpenDMARC** (priority 11): DMARC validation milter
3. **SpamAssassin** (priority 12): Spam scoring daemon
4. **Postfix** (priority 20): MTA that uses the above services
5. **happyDeliver API** (priority 30): REST API server

## Email Processing Flow

1. Email arrives at Postfix on port 25
2. Postfix sends to OpenDKIM milter
   - Verifies DKIM signature
   - Adds `Authentication-Results: ... dkim=pass/fail`
3. Postfix sends to OpenDMARC milter
   - Validates DMARC policy
   - Adds `Authentication-Results: ... dmarc=pass/fail`
4. Postfix routes through SpamAssassin content filter
   - Checks SPF record
   - Scores email for spam
   - Adds `X-Spam-Status` and `X-Spam-Report` headers
5. Postfix checks transport_maps
   - If recipient matches test-UUID pattern, route to happydeliver pipe
6. happyDeliver analyzer receives email
   - Extracts test ID from recipient
   - Parses all headers added by filters
   - Performs additional analysis (DNS, RBL, content)
   - Generates deliverability score
   - Stores report in database
