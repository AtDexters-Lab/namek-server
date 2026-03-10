-- Bootstrap PowerDNS zone for dev/test environment
\connect powerdns

-- Create the zone
INSERT INTO domains (name, type) VALUES ('test.local', 'NATIVE')
ON CONFLICT (name) DO NOTHING;

-- SOA record
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'test.local', 'SOA',
       'ns1.test.local admin.test.local 1 10800 3600 604800 300',
       86400
FROM domains WHERE name = 'test.local'
ON CONFLICT DO NOTHING;

-- NS record
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'test.local', 'NS', 'ns1.test.local', 86400
FROM domains WHERE name = 'test.local'
ON CONFLICT DO NOTHING;

-- Wildcard CNAME: all subdomains -> relay
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, '*.test.local', 'CNAME', 'relay.test.local', 300
FROM domains WHERE name = 'test.local'
ON CONFLICT DO NOTHING;

-- Relay A record (CNAME target for device hostnames)
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'relay.test.local', 'A', '127.0.0.1', 300
FROM domains WHERE name = 'test.local'
ON CONFLICT DO NOTHING;

-- Namek A record
INSERT INTO records (domain_id, name, type, content, ttl)
SELECT id, 'namek.test.local', 'A', '127.0.0.1', 300
FROM domains WHERE name = 'test.local'
ON CONFLICT DO NOTHING;
