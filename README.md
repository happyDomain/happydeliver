# happyDeliver - Email Deliverability Tester

![banner](banner.webp)

An open-source email deliverability testing platform that analyzes test emails and provides detailed deliverability reports with scoring.

## Features

- **Complete Email Analysis**: Analyzes SPF, DKIM, DMARC, BIMI, SpamAssassin scores, DNS records, blacklist status, content quality, and more
- **REST API**: Full-featured API for creating tests and retrieving reports
- **LMTP Server**: Built-in LMTP server for seamless MTA integration
- **Scoring System**: 0-10 scoring with weighted factors across authentication, spam, blacklists, content, and headers
- **Database Storage**: SQLite or PostgreSQL support
- **Configurable**: via environment or config file for all settings

## Quick Start

### With Docker (Recommended)

The easiest way to run happyDeliver is using the all-in-one Docker container that includes Postfix, OpenDKIM, OpenDMARC, SpamAssassin, and the happyDeliver application.

#### What's included in the Docker container:

- **Postfix MTA**: Receives emails on port 25
- **OpenDKIM**: DKIM signature verification
- **OpenDMARC**: DMARC policy validation
- **SpamAssassin**: Spam scoring and analysis
- **happyDeliver API**: REST API server on port 8080
- **SQLite Database**: Persistent storage for tests and reports

#### 1. Using docker-compose

```bash
# Clone the repository
git clone https://git.nemunai.re/happyDomain/happyDeliver.git
cd happydeliver

# Edit docker-compose.yml to set your domain
# Change HAPPYDELIVER_DOMAIN and HOSTNAME environment variables

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

The API will be available at `http://localhost:8080` and SMTP at `localhost:25`.

#### 2. Using docker build directly

```bash
# Build the image
docker build -t happydeliver:latest .

# Run the container
docker run -d \
  --name happydeliver \
  -p 25:25 \
  -p 8080:8080 \
  -e HAPPYDELIVER_DOMAIN=yourdomain.com \
  -e HOSTNAME=mail.yourdomain.com \
  -v $(pwd)/data:/var/lib/happydeliver \
  -v $(pwd)/logs:/var/log/happydeliver \
  happydeliver:latest
```

### Manual Build

#### 1. Build

```bash
go generate
go build -o happyDeliver ./cmd/happyDeliver
```

### 2. Run the API Server

```bash
./happyDeliver server
```

The server will start on `http://localhost:8080` by default.

#### 3. Integrate with your existing e-mail setup

It is expected your setup annotate the email with eg. opendkim, spamassassin, ...
happyDeliver will not perform thoses checks, it relies instead on standard software to have real world annotations.

Choose one of the following way to integrate happyDeliver in your existing setup:

#### Postfix LMTP Transport

You'll obtain the best results with a custom [transport rule](https://www.postfix.org/transport.5.html) using LMTP.

1. Start the happyDeliver server with LMTP enabled (default listens on `127.0.0.1:2525`):

  ```bash
  ./happyDeliver server
  ```

  You can customize the LMTP address with the `-lmtp-addr` flag or in the config file.

2. Create the file `/etc/postfix/transport_happydeliver` with the following content:

  ```
  # Transport map - route test emails to happyDeliver LMTP server
  # Pattern: test-<uuid>@yourdomain.com -> LMTP on localhost:2525

  /^test-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@yourdomain\.com$/  lmtp:inet:127.0.0.1:2525
  ```

3. Append the created file to `transport_maps` in your `main.cf`:

  ```diff
  -transport_maps = texthash:/etc/postfix/transport
  +transport_maps = texthash:/etc/postfix/transport, pcre:/etc/postfix/transport_happydeliver
  ```

  If your `transport_maps` option is not set, just append this line:

  ```
  transport_maps = pcre:/etc/postfix/transport_happydeliver
  ```

  Note: to use the `pcre:` type, you need to have `postfix-pcre` installed.

4. Reload Postfix configuration:

  ```bash
  postfix reload
  ```

#### 4. Create a Test

```bash
curl -X POST http://localhost:8080/api/test
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "test-550e8400@localhost",
  "status": "pending",
  "message": "Send your test email to the address above"
}
```

#### 5. Send Test Email

Send a test email to the address provided (you'll need to configure your MTA to route emails to the analyzer - see MTA Integration below).

#### 6. Get Report

```bash
curl http://localhost:8080/api/report/550e8400-e29b-41d4-a716-446655440000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/test` | POST | Create a new deliverability test |
| `/api/test/{id}` | GET | Get test metadata and status |
| `/api/report/{id}` | GET | Get detailed analysis report |
| `/api/report/{id}/raw` | GET | Get raw annotated email |
| `/api/status` | GET | Service health and status |

## Email Analyzer (CLI Mode)

For manual testing or debugging, you can analyze emails from the command line:

```bash
cat email.eml | ./happyDeliver analyze
```

Or specify recipient explicitly:

```bash
cat email.eml | ./happyDeliver analyze -recipient test-uuid@yourdomain.com
```

**Note:** In production, emails are delivered via LMTP (see integration instructions above).

## Scoring System

The deliverability score is calculated from 0 to 10 based on:

- **Authentication (3 pts)**: SPF, DKIM, DMARC validation
- **Spam (2 pts)**: SpamAssassin score
- **Blacklist (2 pts)**: RBL/DNSBL checks
- **Content (2 pts)**: HTML quality, links, images, unsubscribe
- **Headers (1 pt)**: Required headers, MIME structure

**Note:** BIMI (Brand Indicators for Message Identification) is also checked and reported but does not contribute to the score, as it's a branding feature rather than a deliverability factor.

**Ratings:**
- 9-10: Excellent
- 7-8.9: Good
- 5-6.9: Fair
- 3-4.9: Poor
- 0-2.9: Critical

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/happyDomain).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
