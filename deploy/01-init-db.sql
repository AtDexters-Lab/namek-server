-- Create databases and users for Namek and PowerDNS

-- Namek database
CREATE USER namek WITH PASSWORD 'namek';
CREATE DATABASE namek OWNER namek;

-- PowerDNS database
CREATE USER pdns WITH PASSWORD 'pdns';
CREATE DATABASE powerdns OWNER pdns;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE namek TO namek;
GRANT ALL PRIVILEGES ON DATABASE powerdns TO pdns;
