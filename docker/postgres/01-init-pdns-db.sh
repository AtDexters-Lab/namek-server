#!/bin/bash
set -eu

psql -v ON_ERROR_STOP=1 -v pdns_pass="$PDNS_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER pdns WITH PASSWORD :'pdns_pass';
    CREATE DATABASE powerdns OWNER pdns;
    GRANT ALL PRIVILEGES ON DATABASE powerdns TO pdns;
EOSQL
