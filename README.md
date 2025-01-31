# HookTalon

A simple, reliable webhook ingest service built with Cloudflare Workers, Queues & D1 Database. This service receives webhooks, validates them, and forwards them to specified endpoints with retry capabilities and error handling. 

BYO UI in any framework you wish!

HookTalon - An open source alternative to Hookdeck & Inngest

**Note:** HookTalon is an internal hobby project that may not be secure and turn into spaghetti code if hasn't already. Please evaluate this for your specific needs and conduct thorough testing before relying on it for critical systems.

An example UI that can be paired to this service: 

![Preview React Router App](/ui-preview.png?raw=true "Preview React Router App")

## Features

- **Secure Webhook Processing**

  - Signature verification (HMAC SHA-1/SHA-256/SHA-512)
  - Payload encryption
  - Request size limits
  - Timeout protection

- **Reliability**

  - Automatic retries with exponential backoff 
  - Queue-based processing with at-least-once delivery
  - Automatic Idempotency support via Idempotency-Key header
  - Stuck event detection

- **Monitoring & Alerts**

  - Slack notifications for failed webhooks
  - Email alerts via SendGrid
  - Detailed error tracking
  - Event status monitoring

- **Performance**
  - Built on Cloudflare's edge network
  - Efficient database operations
  - Concurrent processing

## How It Works

1. **Webhook Reception**

   - Service receives POST requests with JSON payloads
   - Validates request size and format
   - Checks endpoint configuration using the URL slug

2. **Security Verification**

   - Validates signatures if configured
   - Supports multiple signature algorithms
   - Implements timing attack protection

3. **Processing Pipeline**

   ```
   Receive Webhook → Validate → Store Event → Queue Delivery → Forward Request
   ```

4. **Error Handling**
   - Comprehensive error capture
   - Automatic alerts for failures
   - Detailed error logging

## Configuration

### Environment Variables

```env
SLACK_WEBHOOK_URL=your_slack_webhook // Slack Webhook URL to send failure alerts
ENCRYPTION_KEY=your_encryption_key // Used to encrypt your webhook source signatures for storage in D1
OUTGOING_SIGNING_KEY=your_signing_key // Signature to validate request made to your destination
SENDGRID_API_KEY=your_sendgrid_key
ALERT_EMAIL_FROM='email alert from'
ALERT_EMAIL_TO='email alert to'
WEBHOOK_TIMEOUT_MS=30000  // Max timeout for webhook forwarding
MAX_PAYLOAD_SIZE=10485760 // Max payload size in bytes (10MB default)
EVENT_RETENTION_DAYS=28   // Automatic cleanup of events older than this
API_KEY=                  // Required for manual retries and admin operations
```

### Database Schema

The service uses a Cloudflare D1 database with tables available in schema.sql

### Event Retention

Events are automatically cleaned up after the configured retention period (default: 28 days). The cleanup process:

- Runs periodically during webhook processing (1% of requests)
- Removes events older than `EVENT_RETENTION_DAYS`
- Executes asynchronously to avoid impacting webhook delivery
- Logs the number of cleaned up events for monitoring

You can configure the retention period by setting `EVENT_RETENTION_DAYS` in your environment variables.

## Cloudflare Infrastructure

HookTalon leverages Cloudflare's platform with this architecture:

**Relationships**
- **Workers**: Handle incoming webhooks and API requests
- **Queues**: Manage webhook delivery with retries and backoff
- **D1 Database**: Stores endpoints, events, and delivery logs

### Configuration Setup

1. **Create D1 Database**
```bash
wrangler d1 create hooktalon
```
2. **Create Queues**
```bash
wrangler queues create hooktalon-delivery
wrangler queues create hooktalon-dead-letter
```

3. **Add Secrets** 
```bash
npx wrangler secret put SLACK_WEBHOOK_URL
npx wrangler secret put ENCRYPTION_KEY
npx wrangler secret put OUTGOING_SIGNING_KEY
npx wrangler secret put SENDGRID_API_KEY
npx wrangler secret put API_KEY
```

Add to your `wrangler.toml`:
```toml:wrangler.toml
[[d1_databases]]
binding = "DB"
database_name = "hooktalon"
database_id = "YOUR_D1_ID"

[[queues.producers]]
binding = "WEBHOOK_QUEUE"
queue = "hooktalon-delivery"

[[queues.consumers]]
queue = "hooktalon-delivery"
dead_letter_queue = "hooktalon-dead-letter"
max_retries = 2
max_batch_size = 1
```

### Dashboard Setup
1. Navigate to Cloudflare Dashboard
2. Create D1 database and note Database ID
3. Create Queues for delivery and dead letters
4. Link resources to your Worker:
   - D1 database binding
   - Queue producers/consumers
   - Environment variables under Settings

Apply database schema manually via the Cloudflare D1 Console or:
```bash
wrangler d1 execute webhooks --file=./schema.sql
```

## Usage

### Creating an Endpoint

```sql
INSERT INTO endpoints (
    id,
    slug,
    friendly_name,
    target_url,
    signature_header,
    signature_type,
    secret_key, -- Needs to be encrypted via the example function below
) VALUES (
    'ep_' || lower(hex(randomblob(8))),  -- Generates a random ID with 'ep_' prefix
    'random-slug',
    'My Stripe Processing API',
    'https://api.destination.com/webhook',
    'X-Signature',
    'hmac_sha256',
    'your-secret-key',
);
```

### Sending a Webhook

```http
POST /{endpoint-slug}
Content-Type: application/json
Idempotency-Key: auto-generated

{
  "your": "payload"
}
```

## Error Handling

The service implements multiple layers of error handling:

1. **Request Validation**

   - Size limits
   - Format checking
   - URL validation

2. **Processing Errors**

   - Database timeouts
   - Network issues
   - Invalid configurations

3. **Delivery Failures**
   - Timeout handling
   - Response validation
   - Retry management

### Retry Mechanism

Events that fail delivery will automatically be retried with exponential backoff. Retries are configured based on your Queue setup. When an event reaches the maximum retry count, it will be marked as failed and alerts will be triggered.

#### Manual Retries

Failed events can be manually retried via the API endpoint:

```http
POST /retry/{event-id}
Authorization: Bearer your-api-key
```

Manual retries:

- Require authentication via API key
- Reset the event status to 'pending'
- Increment the existing retry count for tracking purposes
- Will still trigger alerts if the retry fails

To enable manual retries, set the `API_KEY` environment variable:

```env
API_KEY=your-secure-api-key
```

Example retry request:

```bash
curl -X POST \
  -H "Authorization: Bearer your-api-key" \
  https://your-worker.workers.dev/retry/evt_123456
```

Response codes:

- 202: Event accepted for retry
- 401: Invalid or missing API key
- 404: Event not found or not in failed state
- 405: Method not allowed (only POST supported)
- 400: Invalid event ID

### Event Status Tracking

Events can have the following statuses:

- `pending`: Initial state
- `processing`: Currently being processed
- `delivered`: Successfully delivered
- `failed`: Failed after all retries
- `stuck`: No progress after threshold

### Logging

All events are logged with the following information:

- Timestamp
- Event ID
- Endpoint details
- Status
- Response data
- Error details from API (if any)
- Detailed event logs with:
  - Exact error messages
  - Response bodies from failed deliveries
  - Timing information for each attempt
- Dual alert channels (Slack + Email) with failure snapshots

## Some Poorly Written Example Endpoint Creation Function

#### 1. Endpoint Creation Handler
```typescript
async function createEndpointHandler({ request, context }) {
  // Parse form data from incoming request
  const formData = await request.formData();
  
  // Extract endpoint configuration parameters
  const friendlyName = formData.get('friendly_name') as string;
  const targetUrl = formData.get('target_url') as string;
  const signatureType = formData.get('signature_type') as string;
  const signatureHeader = formData.get('signature_header') as string;
  const secretKey = formData.get('secret_key') as string;

  // Encrypt secret if security is enabled
  let encryptedSecret = null;
  if (secretKey && signatureType !== 'none') {
    encryptedSecret = await encryptSecret(
      secretKey,
      env.WEBHOOK_ENCRYPTION_KEY
    );
  }

  // Database connection and slug generation
  const db = env.WEBHOOK_DB;
  const slug = await generateUniqueSlug(db, false);
  
  // Insert new endpoint into database
  await db
    .prepare(
      `INSERT INTO endpoints (
        id, slug, friendly_name, target_url, 
        signature_header, signature_type, secret_key, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      crypto.randomUUID(),  // Generate unique UUIDv4 identifier
      slug,                 // Human-readable unique slug
      friendlyName,         // User-defined endpoint name
      targetUrl,            // Destination URL for webhooks
      signatureHeader || null,  // Header to validate inbound webhook signature
      signatureType === 'none' ? null : signatureType,  // Security method
      encryptedSecret,      // Encrypted version of secret key
      new Date().toISOString()
    )
    .run();
}
```
---

#### 2. Encryption Utility
```typescript
async function encryptSecret(plaintext: string, encryptionKey: string): Promise<string> {
  // Cryptographic configuration
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt


  // unnecessary ??? Could be improved
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(encryptionKey),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext)
  );

  // Combine salt + IV + ciphertext for storage
  const encryptedArray = new Uint8Array(encryptedData);
  const combined = new Uint8Array(salt.length + iv.length + encryptedArray.length);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(encryptedArray, salt.length + iv.length);

  return Buffer.from(combined).toString('base64');
}
```

---

#### 3. Slug Generation Utilities
```typescript
// Generates random URL-safe identifier
function generateRandomSlug(length: number = 10): string {
  const characters = 'abcdefghijklmnopqrstuvwxyz0123456789'; // 36 possible chars
  return Array.from({ length }, () => characters[Math.floor(Math.random() * characters.length)]).join('');
}

// Ensures unique slug across all endpoints
async function generateUniqueSlug(db: any, length: number = 10): Promise<string> {
  const maxAttempts = 5;
  let attempts = 0;

  while (attempts < maxAttempts) {
    const slug = generateRandomSlug(length);
    // Check for existing slugs in database
    const { results } = await db.prepare('SELECT id FROM endpoints WHERE slug = ?').bind(slug).all();
    if (!results?.length) return slug;
    attempts++;
  }
  throw new Error('Could not generate unique slug after multiple attempts');
}
```

---

## License

MIT License

Copyright (c) 2025 Aerotalon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.