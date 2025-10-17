# Multi-stage Dockerfile for happyDeliver with integrated MTA
# Stage 1: Build the Svelte application
FROM node:22-alpine AS nodebuild

WORKDIR /build

COPY api/ api/
COPY web/ web/

RUN yarn --cwd web install && \
    yarn --cwd web run generate:api && \
    yarn --cwd web --offline build

# Stage 2: Build the Go application
FROM golang:1-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache ca-certificates git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .
COPY --from=nodebuild /build/web/build/ ./web/build/

# Build the application
RUN go generate ./... && \
    CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o happyDeliver ./cmd/happyDeliver

# Stage 3: Runtime image with Postfix and all filters
FROM alpine:3

# Install all required packages
RUN apk add --no-cache \
    bash \
    ca-certificates \
    opendkim \
    opendkim-utils \
    opendmarc \
    postfix \
    postfix-pcre \
    postfix-policyd-spf-perl \
    spamassassin \
    spamassassin-client \
    supervisor \
    sqlite \
    tzdata \
    && rm -rf /var/cache/apk/*

# Get test-only version of postfix-policyd-spf-perl
ADD https://git.nemunai.re/happyDomain/postfix-policyd-spf-perl/raw/branch/master/postfix-policyd-spf-perl  /usr/bin/postfix-policyd-spf-perl
RUN chmod +x /usr/bin/postfix-policyd-spf-perl && chmod 755 /usr/bin/postfix-policyd-spf-perl

# Create happydeliver user and group
RUN addgroup -g 1000 happydeliver && \
    adduser -D -u 1000 -G happydeliver happydeliver

# Create necessary directories
RUN mkdir -p /etc/happydeliver \
    /var/lib/happydeliver \
    /var/log/happydeliver \
    /var/spool/postfix/opendkim \
    /var/spool/postfix/opendmarc \
    /etc/opendkim/keys \
    && chown -R happydeliver:happydeliver /var/lib/happydeliver /var/log/happydeliver \
    && chown -R opendkim:postfix /var/spool/postfix/opendkim \
    && chown -R opendmarc:postfix /var/spool/postfix/opendmarc

# Copy the built application
COPY --from=builder /build/happyDeliver /usr/local/bin/happyDeliver
RUN chmod +x /usr/local/bin/happyDeliver

# Copy configuration files
COPY docker/postfix/ /etc/postfix/
COPY docker/opendkim/ /etc/opendkim/
COPY docker/opendmarc/ /etc/opendmarc/
COPY docker/spamassassin/ /etc/mail/spamassassin/
COPY docker/supervisor/ /etc/supervisor/
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

# Expose ports
# 25 - SMTP
# 8080 - API server
EXPOSE 25 8080

# Default configuration
ENV HAPPYDELIVER_DATABASE_TYPE=sqlite HAPPYDELIVER_DATABASE_DSN=/var/lib/happydeliver/happydeliver.db HAPPYDELIVER_DOMAIN=happydeliver.local HAPPYDELIVER_ADDRESS_PREFIX=test- HAPPYDELIVER_DNS_TIMEOUT=5s HAPPYDELIVER_HTTP_TIMEOUT=10s HAPPYDELIVER_RBL=zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org,dnsbl.sorbs.net,dnsbl-1.uceprotect.net,bl.mailspike.net

# Volume for persistent data
VOLUME ["/var/lib/happydeliver", "/var/log/happydeliver"]

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
