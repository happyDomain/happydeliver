# Multi-stage Dockerfile for happyDeliver with integrated MTA
# Stage 1: Build the Svelte application
FROM node:24-alpine AS nodebuild

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

# Stage 3: Prepare perl and spamass-milt
FROM alpine:3 AS pl

RUN echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk add --no-cache \
    build-base \
    libmilter-dev \
    musl-obstack-dev \
    openssl \
    openssl-dev \
    perl-app-cpanminus \
    perl-alien-libxml2 \
    perl-class-load-xs \
    perl-cpanel-json-xs \
    perl-crypt-openssl-rsa \
    perl-crypt-openssl-random \
    perl-crypt-openssl-verify \
    perl-crypt-openssl-x509 \
    perl-dbd-sqlite \
    perl-dbi \
    perl-email-address-xs \
    perl-json-xs \
    perl-list-moreutils \
    perl-moose \
    perl-net-idn-encode@testing \
    perl-net-ssleay \
    perl-netaddr-ip \
    perl-package-stash \
    perl-params-util \
    perl-params-validate \
    perl-proc-processtable \
    perl-sereal-decoder \
    perl-sereal-encoder \
    perl-socket6 \
    perl-sub-identify \
    perl-variable-magic \
    perl-xml-libxml \
    perl-dev \
    spamassassin-client \
    zlib-dev \
    && \
    ln -s /usr/bin/ld /bin/ld

RUN cpanm --notest Mail::SPF && \
    cpanm --notest Mail::Milter::Authentication

RUN wget https://download.savannah.nongnu.org/releases/spamass-milt/spamass-milter-0.4.0.tar.gz && \
    tar xzf spamass-milter-0.4.0.tar.gz && \
    cd spamass-milter-0.4.0 && \
    ./configure && make install

# Stage 4: Runtime image with Postfix and all filters
FROM alpine:3

# Install all required packages
RUN echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk add --no-cache \
    bash \
    ca-certificates \
    libmilter \
    openssl \
    perl \
    perl-alien-libxml2 \
    perl-class-load-xs \
    perl-cpanel-json-xs \
    perl-crypt-openssl-rsa \
    perl-crypt-openssl-random \
    perl-crypt-openssl-verify \
    perl-crypt-openssl-x509 \
    perl-dbd-sqlite \
    perl-dbi \
    perl-email-address-xs \
    perl-json-xs \
    perl-list-moreutils \
    perl-moose \
    perl-net-idn-encode@testing \
    perl-net-ssleay \
    perl-netaddr-ip \
    perl-package-stash \
    perl-params-util \
    perl-params-validate \
    perl-proc-processtable \
    perl-sereal-decoder \
    perl-sereal-encoder \
    perl-socket6 \
    perl-sub-identify \
    perl-variable-magic \
    perl-xml-libxml \
    postfix \
    postfix-pcre \
    spamassassin \
    spamassassin-client \
    supervisor \
    sqlite \
    tzdata \
    && rm -rf /var/cache/apk/*

# Copy Mail::Milter::Authentication and its dependancies
COPY --from=pl /usr/local/ /usr/local/

# Create happydeliver user and group
RUN addgroup -g 1000 happydeliver && \
    adduser -D -u 1000 -G happydeliver happydeliver

# Create necessary directories
RUN mkdir -p /etc/happydeliver \
    /var/lib/happydeliver \
    /var/log/happydeliver \
    /var/cache/authentication_milter \
    /var/lib/authentication_milter \
    /var/spool/postfix/authentication_milter \
    /var/spool/postfix/spamassassin \
    && chown -R happydeliver:happydeliver /var/lib/happydeliver /var/log/happydeliver \
    && chown -R mail:mail /var/spool/postfix/authentication_milter /var/spool/postfix/spamassassin

# Copy the built application
COPY --from=builder /build/happyDeliver /usr/local/bin/happyDeliver
RUN chmod +x /usr/local/bin/happyDeliver

# Copy configuration files
COPY docker/postfix/ /etc/postfix/
COPY docker/authentication_milter/authentication_milter.json /etc/authentication_milter.json
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
