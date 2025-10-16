#!/bin/bash
set -e

echo "Starting happyDeliver container..."

# Get environment variables with defaults
HOSTNAME="${HOSTNAME:-mail.happydeliver.local}"
HAPPYDELIVER_DOMAIN="${HAPPYDELIVER_DOMAIN:-happydeliver.local}"

echo "Hostname: $HOSTNAME"
echo "Domain: $HAPPYDELIVER_DOMAIN"

# Create runtime directories
mkdir -p /var/run/opendkim /var/run/opendmarc
chown opendkim:postfix /var/run/opendkim
chown opendmarc:postfix /var/run/opendmarc

# Create socket directories
mkdir -p /var/spool/postfix/opendkim /var/spool/postfix/opendmarc
chown opendkim:postfix /var/spool/postfix/opendkim
chown opendmarc:postfix /var/spool/postfix/opendmarc
chmod 750 /var/spool/postfix/opendkim /var/spool/postfix/opendmarc

# Create log directory
mkdir -p /var/log/happydeliver
chown happydeliver:happydeliver /var/log/happydeliver

# Replace placeholders in Postfix configuration
echo "Configuring Postfix..."
sed -i "s/__HOSTNAME__/${HOSTNAME}/g" /etc/postfix/main.cf
sed -i "s/__DOMAIN__/${HAPPYDELIVER_DOMAIN}/g" /etc/postfix/main.cf

# Replace placeholders in OpenDMARC configuration
sed -i "s/__HOSTNAME__/${HOSTNAME}/g" /etc/opendmarc/opendmarc.conf

# Initialize Postfix aliases
if [ -f /etc/postfix/aliases ]; then
    echo "Initializing Postfix aliases..."
    postalias /etc/postfix/aliases || true
fi

# Compile transport maps
if [ -f /etc/postfix/transport_maps ]; then
    echo "Compiling transport maps..."
    postmap /etc/postfix/transport_maps
fi

# Update SpamAssassin rules
echo "Updating SpamAssassin rules..."
sa-update || echo "SpamAssassin rules update failed (might be first run)"

# Compile SpamAssassin rules
sa-compile || echo "SpamAssassin compilation skipped"

# Initialize database if it doesn't exist
if [ ! -f /var/lib/happydeliver/happydeliver.db ]; then
    echo "Database will be initialized on first API startup..."
fi

# Set proper permissions
chown -R happydeliver:happydeliver /var/lib/happydeliver

echo "Configuration complete, starting services..."

# Execute the main command (supervisord)
exec "$@"
