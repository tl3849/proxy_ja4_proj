#!/usr/bin/bash
set -e

echo "=== Squid SSL Bump Startup Script ==="
echo "Starting at: $(date)"

# Install additional packages if needed
if command -v apt-get >/dev/null 2>&1; then
    echo "Installing additional packages..."
    apt-get update -qq
    apt-get install -y tcpdump
fi

# Ensure cache dirs exist
mkdir -p /var/cache/squid /var/log/squid /var/run/squid

# Initialize cache dirs if needed
if [ ! -d /var/cache/squid/00 ]; then
    echo "Initializing cache directories..."
    /usr/sbin/squid -z -N
fi

# Initialize SSL certificate database if missing content
if [ ! -f /var/cache/squid/ssl_db/index.txt ]; then
	echo "Initializing SSL certificate database..."
	rm -rf /var/cache/squid/ssl_db
	/usr/lib/squid/security_file_certgen -c -s /var/cache/squid/ssl_db -M 4MB
	chown -R proxy:proxy /var/cache/squid/ssl_db
fi

# Verify
if [ ! -f /var/cache/squid/ssl_db/index.txt ] || [ ! -d /var/cache/squid/ssl_db/certs ]; then
	echo "ERROR: SSL database initialization failed"
	ls -ld /var/cache/squid/ssl_db; ls -la /var/cache/squid/ssl_db
	exit 1
fi

# Ensure proper permissions on existing SSL database
if [ -d /var/cache/squid/ssl_db ]; then
	echo "Setting proper permissions on SSL database..."
	chown -R proxy:proxy /var/cache/squid/ssl_db
	chmod 755 /var/cache/squid/ssl_db
fi

# Remove stale PID file (squid -z may leave one behind)
rm -f /var/run/squid.pid

# Run Squid in foreground
exec /usr/sbin/squid -N -d 1
