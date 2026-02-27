-- Bootstrap PowerDNS zone for Namek
-- Run against the powerdns database after PowerDNS schema is created
--
-- Variables to replace before running:
--   BASE_DOMAIN     = piccolospace.com
--   NAMEK_IP        = <namek-server-ip>
--   NS_PRIMARY      = ns1.piccolospace.com
--   ADMIN_EMAIL     = admin.piccolospace.com (SOA rname format)

\connect powerdns

-- Create the zone
INSERT INTO domains (name, type) VALUES ('piccolospace.com', 'NATIVE')
ON CONFLICT (name) DO NOTHING;

-- SOA record
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'piccolospace.com', 'SOA',
       'ns1.piccolospace.com admin.piccolospace.com 1 10800 3600 604800 300',
       86400
FROM domains WHERE name = 'piccolospace.com'
ON CONFLICT DO NOTHING;

-- NS record
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'piccolospace.com', 'NS', 'ns1.piccolospace.com', 86400
FROM domains WHERE name = 'piccolospace.com'
ON CONFLICT DO NOTHING;

-- Wildcard CNAME: all subdomains -> relay
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, '*.piccolospace.com', 'CNAME', 'relay.piccolospace.com', 300
FROM domains WHERE name = 'piccolospace.com'
ON CONFLICT DO NOTHING;

-- Namek A record (explicit override of wildcard)
-- Replace 127.0.0.1 with actual Namek server IP
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'namek.piccolospace.com', 'A', '127.0.0.1', 300
FROM domains WHERE name = 'piccolospace.com'
ON CONFLICT DO NOTHING;

-- Relay hostname (initially empty — populated when Nexus instances register)
-- Example: INSERT INTO records (domain_id, name, type, content, ttl)
-- SELECT id, 'relay.piccolospace.com', 'A', '203.0.113.1', 60
-- FROM domains WHERE name = 'piccolospace.com';
