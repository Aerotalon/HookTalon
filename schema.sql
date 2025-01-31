-- Endpoints table to store different API configurations
CREATE TABLE endpoints (
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  target_url TEXT NOT NULL,
  signature_header TEXT,
  max_retries INTEGER DEFAULT 3, -- UNUSED. SET THIS IN QUEUE CONFIG
  signature_type TEXT CHECK(signature_type IN ('hmac_sha256', 'hmac_sha1', 'hmac_sha512', NULL)),
  secret_key TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  friendly_name TEXT
);

-- Events table to store webhook events
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT UNIQUE,
  endpoint_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  headers TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  retry_count INTEGER DEFAULT 0,
  last_error TEXT,
  last_attempt DATETIME,
  alert_sent BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME,
  FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
); 

-- Event logs table to store webhook event logs
    CREATE TABLE event_logs (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    response_status INTEGER,
    response_body TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events(id)
);