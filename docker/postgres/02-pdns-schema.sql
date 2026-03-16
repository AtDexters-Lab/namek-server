\connect powerdns

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO pdns;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO pdns;

CREATE TABLE IF NOT EXISTS domains (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INT DEFAULT NULL,
  type                  VARCHAR(8) NOT NULL DEFAULT 'NATIVE',
  notified_serial       BIGINT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               TEXT DEFAULT NULL,
  catalog               TEXT DEFAULT NULL,
  CONSTRAINT c_lowercase_name UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS name_index ON domains(name);

CREATE TABLE IF NOT EXISTS records (
  id                    BIGSERIAL PRIMARY KEY,
  domain_id             INT DEFAULT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INT DEFAULT NULL,
  prio                  INT DEFAULT NULL,
  disabled              BOOL DEFAULT 'f',
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 't'
);

CREATE INDEX IF NOT EXISTS rec_name_index ON records(name);
CREATE INDEX IF NOT EXISTS nametype_index ON records(name, type);
CREATE INDEX IF NOT EXISTS domain_id ON records(domain_id);
CREATE INDEX IF NOT EXISTS orderindex ON records(ordername);

CREATE TABLE IF NOT EXISTS supermasters (
  ip                    INET NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) NOT NULL DEFAULT '',
  PRIMARY KEY(ip, nameserver)
);

CREATE TABLE IF NOT EXISTS comments (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL
);

CREATE INDEX IF NOT EXISTS comments_domain_id_idx ON comments(domain_id);
CREATE INDEX IF NOT EXISTS comments_name_type_idx ON comments(name, type);
CREATE INDEX IF NOT EXISTS comments_order_idx ON comments(domain_id, modified_at);

CREATE TABLE IF NOT EXISTS domainmetadata (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);

CREATE INDEX IF NOT EXISTS domainidmetaindex ON domainmetadata(domain_id);

CREATE TABLE IF NOT EXISTS cryptokeys (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INT NOT NULL DEFAULT 0,
  active                BOOL DEFAULT 't',
  published             BOOL DEFAULT 't',
  content               TEXT
);

CREATE INDEX IF NOT EXISTS domainidindex ON cryptokeys(domain_id);

CREATE TABLE IF NOT EXISTS tsigkeys (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  CONSTRAINT c_lowercase_name_tsig UNIQUE (name, algorithm)
);
