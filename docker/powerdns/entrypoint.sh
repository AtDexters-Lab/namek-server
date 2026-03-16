#!/bin/sh
set -eu

# Validate required environment variables
for var in PDNS_DB_HOST PDNS_DB_PORT PDNS_DB_USER PDNS_DB_PASSWORD PDNS_API_KEY; do
  eval val=\$$var
  if [ -z "$val" ]; then
    echo "FATAL: $var is not set"
    exit 1
  fi
done

# Wait for postgres to be ready
TIMEOUT=120
ELAPSED=0
until nc -z "${PDNS_DB_HOST}" "${PDNS_DB_PORT}" 2>/dev/null; do
  ELAPSED=$((ELAPSED + 1))
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "FATAL: postgres not reachable at ${PDNS_DB_HOST}:${PDNS_DB_PORT} after ${TIMEOUT}s"
    exit 1
  fi
  sleep 1
done

echo "postgres is ready at ${PDNS_DB_HOST}:${PDNS_DB_PORT}"

# Generate pdns.conf
cat > /etc/powerdns/pdns.conf <<EOF
launch=gpgsql
gpgsql-host=${PDNS_DB_HOST}
gpgsql-port=${PDNS_DB_PORT}
gpgsql-user=${PDNS_DB_USER}
gpgsql-password=${PDNS_DB_PASSWORD}
gpgsql-dbname=powerdns

local-port=${PDNS_LOCAL_PORT:-53}
api=yes
api-key=${PDNS_API_KEY}
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.0/8

strict-rfc-wildcards=no
enable-lua-records=yes

setuid=
setgid=
EOF

exec pdns_server --guardian=no --daemon=no
