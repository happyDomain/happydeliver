#!/bin/bash
set -e

echo "Starting happyDeliver container..."

# Get environment variables with defaults
HOSTNAME="${HOSTNAME:-mail.happydeliver.local}"
HAPPYDELIVER_DOMAIN="${HAPPYDELIVER_DOMAIN:-happydeliver.local}"

echo "Hostname: $HOSTNAME"
echo "Domain: $HAPPYDELIVER_DOMAIN"

# Create socket directories
mkdir -p /var/spool/postfix/authentication_milter
chown mail:mail /var/spool/postfix/authentication_milter
chmod 750 /var/spool/postfix/authentication_milter

# Create log directory
mkdir -p /var/log/happydeliver /var/cache/authentication_milter /var/spool/authentication_milter /var/lib/authentication_milter /run/authentication_milter
chown happydeliver:happydeliver /var/log/happydeliver
chown mail:mail /var/cache/authentication_milter /run/authentication_milter /var/spool/authentication_milter /var/lib/authentication_milter

# Replace placeholders in Postfix configuration
echo "Configuring Postfix..."
sed -i "s/__HOSTNAME__/${HOSTNAME}/g" /etc/postfix/main.cf
sed -i "s/__DOMAIN__/${HAPPYDELIVER_DOMAIN}/g" /etc/postfix/main.cf

# Replace placeholders in configurations
sed -i "s/__HOSTNAME__/${HOSTNAME}/g" /etc/authentication_milter.json

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
