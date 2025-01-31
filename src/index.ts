/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.json`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import sendGridMail from '@sendgrid/mail';

interface Env {
	DB: D1Database;
	SLACK_WEBHOOK_URL: string;
	ENCRYPTION_KEY: string;
	OUTGOING_SIGNING_KEY: string;
	SENDGRID_API_KEY: string;
	ALERT_EMAIL_TO: string;
	ALERT_EMAIL_FROM: string;
	WEBHOOK_QUEUE: Queue;
	WEBHOOK_TIMEOUT_MS: string;
	MAX_PAYLOAD_SIZE: string;
	EVENT_RETENTION_DAYS: string;
	API_KEY: string;
}

interface Endpoint {
	id: string;
	slug: string;
	friendly_name: string;
	target_url: string;
	max_retries: number;
	signature_header: string | null;
	signature_type: 'hmac_sha256' | 'hmac_sha1' | 'hmac_sha512' | null;
	secret_key: string | null;
}

interface WebhookMessage {
	eventId: string;
	endpointId: string;
	targetUrl: string;
	payload: any;
	headers: Record<string, string>;
	attempt: number;
}

interface EventLog {
	id: string;
	event_id: string;
	attempt_number: number;
	status: 'success' | 'failed';
	error_message?: string;
	response_status?: number;
	response_body?: string;
}

async function forwardWebhook(url: string, payload: any, headers: Record<string, string>, signingKey: string) {
	const payloadString = JSON.stringify(payload);
	const encoder = new TextEncoder();
	const payloadBuffer = encoder.encode(payloadString);
	const timestamp = Math.floor(Date.now() / 1000).toString();

	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(signingKey),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);

	const signature = await crypto.subtle.sign(
		'HMAC',
		key,
		payloadBuffer
	);

	const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

	const response = await fetch(url, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Webhook-Signature': signatureBase64,
			'X-Timestamp': timestamp,
			...headers
		},
		body: payloadString
	});

	if (!response.ok) {
		throw new Error(`API responded with status ${response.status}: ${await response.text()}`);
	}

	return response;
}

async function sendAlert(webhookUrl: string, event: any, error: Error) {
	const slackMessage = {
		blocks: [
			{
				type: 'header',
				text: {
					type: 'plain_text',
					text: 'Webhook Delivery Failed',
					emoji: true
				}
			},
			{
				type: 'section',
				fields: [
					{
						type: 'mrkdwn',
						text: `*Event ID:*\n${event.id}`
					},
					{
						type: 'mrkdwn',
						text: `*Target URL:*\n${event.target_url}`
					},
					{
						type: 'mrkdwn',
						text: `*Error Message:*\n${error.message}`
					},
					{
						type: 'mrkdwn',
						text: `*Payload:*\n\`\`\`${JSON.stringify(JSON.parse(event.payload), null, 2)}\`\`\``
					}
				]
			}
		]
	};

	await fetch(webhookUrl, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(slackMessage)
	});
}

async function encryptSecret(plaintext: string, encryptionKey: string): Promise<string> {
	const encoder = new TextEncoder();
	const iv = crypto.getRandomValues(new Uint8Array(12));
	
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(encryptionKey),
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt']
	);

	const encryptedData = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv },
		key,
		encoder.encode(plaintext)
	);

	const encryptedArray = new Uint8Array(encryptedData);
	const combined = new Uint8Array(iv.length + encryptedArray.length);
	combined.set(iv);
	combined.set(encryptedArray, iv.length);

	return Buffer.from(combined).toString('base64');
}

async function decryptSecret(encrypted: string, encryptionKey: string): Promise<string> {
	const decoder = new TextDecoder();
	const combined = Buffer.from(encrypted, 'base64');
	
	const salt = combined.slice(0, 16);
	const iv = combined.slice(16, 28);
	const encryptedData = combined.slice(28);

	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(encryptionKey),
		{ name: 'PBKDF2' },
		false,
		['deriveBits', 'deriveKey']
	);

	const key = await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt,
			iterations: 100000,
			hash: 'SHA-256',
		},
		keyMaterial,
		{ name: 'AES-GCM', length: 256 },
		false,
		['decrypt']
	);

	const decryptedData = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv },
		key,
		encryptedData
	);

	return decoder.decode(decryptedData);
}

async function verifySignature(
	payload: string,
	signature: string,
	encryptedSecretKey: string,
	signatureType: 'hmac_sha256' | 'hmac_sha1' | 'hmac_sha512',
	encryptionKey: string
): Promise<boolean> {
	const secretKey = await decryptSecret(encryptedSecretKey, encryptionKey);
	
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secretKey),
		{ 
			name: 'HMAC', 
			hash: signatureType === 'hmac_sha256' ? 'SHA-256' : 
				  signatureType === 'hmac_sha512' ? 'SHA-512' : 'SHA-1'
		},
		false,
		['verify']
	);

	const signatureBytes = hexToBytes(signature);
	return await crypto.subtle.verify(
		'HMAC',
		key,
		signatureBytes,
		encoder.encode(payload)
	);
}

function hexToBytes(hex: string): Uint8Array {
	hex = hex.replace(/^(?:sha256=|sha1=)/, '');
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}


async function sendFailureAlert(event: any, error: Error, env: Env) {
	if(!env.SENDGRID_API_KEY) {
		return;
	}

	sendGridMail.setApiKey(env.SENDGRID_API_KEY);

	const msg = {
		to: env.ALERT_EMAIL_TO,
		from: env.ALERT_EMAIL_FROM,
		subject: 'Webhook Delivery Failed',
		html: `
			<h2>Webhook Delivery Failed</h2>
			<p><strong>Error:</strong> ${error.message}</p>
			<p><strong>Endpoint URL:</strong> ${event.target_url}</p>
			<p><strong>Event ID:</strong> ${event.id}</p>
			<p><strong>Retry Count:</strong> ${event.retry_count}</p>
			<p><strong>Original Payload:</strong></p>
			<pre>${JSON.stringify(JSON.parse(event.payload), null, 2)}</pre>
		`
	};

	try {
		await sendGridMail.send(msg);
	} catch (error) {
		console.error('Failed to send alert email:', error);
	}
}

async function scheduleWebhookDelivery(env: Env, eventId: string, endpointId: string, maxRetries: number) {
	const data = await env.DB.prepare(`
		SELECT e.payload, e.headers, ep.target_url
		FROM events e
		JOIN endpoints ep ON ep.id = e.endpoint_id
		WHERE e.id = ? AND ep.id = ?
	`).bind(eventId, endpointId).first<any>();

	if (!data) {
		throw new Error('Event or endpoint not found');
	}

	const message: WebhookMessage = {
		eventId,
		endpointId,
		targetUrl: data.target_url,
		payload: JSON.parse(data.payload),
		headers: JSON.parse(data.headers),
		attempt: 0
	};

	await env.WEBHOOK_QUEUE.send(message);
	
	return eventId;
}

async function logEventAttempt(env: Env, log: EventLog) {
	await env.DB.prepare(`
		INSERT INTO event_logs (
			id,
			event_id,
			attempt_number,
			status,
			error_message,
			response_status,
			response_body
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`).bind(
		crypto.randomUUID(),
		log.event_id,
		log.attempt_number,
		log.status,
		log.error_message,
		log.response_status,
		log.response_body
	).run();
}

async function processWebhookDelivery(env: Env, queueId: string, isManualRetry: boolean = false): Promise<boolean> {
	const updated = await env.DB.prepare(`
		UPDATE events 
		SET status = 'processing'
				WHERE id = ? AND status = 'pending'
		RETURNING id
	`).bind(queueId).first();

	if (!updated) {
		return false;
	}

	try {
		const item = await env.DB.prepare(`
			SELECT e.*, ep.target_url, ep.max_retries
			FROM events e
			JOIN endpoints ep ON ep.id = e.endpoint_id
			WHERE e.id = ?
		`).bind(queueId).first<any>();

		if (!item) return false;

		const payload = JSON.parse(item.payload);
		const headers = JSON.parse(item.headers);

		try {
			const response = await forwardWebhook(item.target_url, payload, headers, env.OUTGOING_SIGNING_KEY);
            const responseBody = await response.text();
			
			await env.DB.prepare(`
				UPDATE events SET status = 'success', completed_at = CURRENT_TIMESTAMP WHERE id = ?
			`).bind(item.id).run();

			await logEventAttempt(env, {
                id: crypto.randomUUID(),
                event_id: item.id,
                attempt_number: item.retry_count + 1,
                status: 'success',
                response_status: response.status,
                response_body: responseBody
            });

			return true;
		} catch (error) {
			await env.DB.prepare(`
				UPDATE events 
				SET retry_count = CASE WHEN ? THEN retry_count ELSE retry_count + 1 END,
					status = CASE 
						WHEN retry_count >= ? THEN 'failed'
						ELSE 'pending'
					END,
					last_error = ?,
					completed_at = CASE 
						WHEN retry_count >= ? THEN CURRENT_TIMESTAMP
						ELSE NULL
					END
				WHERE id = ?
			`).bind(isManualRetry, item.max_retries, error.message, item.max_retries, item.id).run();

			await logEventAttempt(env, {
                id: crypto.randomUUID(),
                event_id: item.id,
                attempt_number: item.retry_count + 1,
                status: 'failed',
                error_message: error.message
            });

			if (item.retry_count >= item.max_retries) {
				const eventDetails = {
					id: item.id,
					target_url: item.target_url,
					payload: item.payload,
					retry_count: item.retry_count + (isManualRetry ? 0 : 1)
				};
				await sendAlert(env.SLACK_WEBHOOK_URL, eventDetails, error);
				await sendFailureAlert(eventDetails, error, env);
			}
			return false;
		}
	} catch (error) {
		await env.DB.prepare(`
			UPDATE events 
			SET status = 'pending'
						WHERE id = ? AND status = 'processing'
		`).bind(queueId).run();
		
		throw error;
	}
}

async function generateIdempotencyKey(payload: string, slug: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(`${slug}:${payload}`);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hashBuffer))
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
}

async function forwardWebhookWithTimeout(
    targetUrl: string,
    payload: any,
    headers: Record<string, string>,
    signingKey: string,
    env: Env
): Promise<Response> {
    const forwardPromise = forwardWebhook(targetUrl, payload, headers, signingKey);
    const timeoutMs = Number(env.WEBHOOK_TIMEOUT_MS || 30000);
    
    return Promise.race([
        forwardPromise,
        new Promise<Response>((_, reject) => 
            setTimeout(() => reject(new Error(`Webhook delivery timed out after ${timeoutMs/1000} seconds`)), timeoutMs)
        )
    ]);
}

async function handleSystemError(
    error: Error,
    request: Request,
    env: Env,
    ctx: ExecutionContext
): Promise<Response> {
    console.error('Unhandled error:', error);

    try {
        const errorDetails = {
            id: 'system_error',
            target_url: request.url,
            payload: JSON.stringify({
                error: error.message,
                stack: error.stack,
                url: request.url,
                method: request.method,
            }),
            retry_count: 0
        };

        ctx.waitUntil(Promise.all([
            sendAlert(env.SLACK_WEBHOOK_URL, errorDetails, error),
            sendFailureAlert(errorDetails, error, env)
        ]));
    } catch (alertError) {
        console.error('Failed to send error alerts:', alertError);
    }

    return new Response('An internal error occurred', { status: 500 });
}

async function cleanupOldEvents(env: Env) {
	try {
		const retentionDays = Number(env.EVENT_RETENTION_DAYS || '28');
		const result = await env.DB.prepare(`
			DELETE FROM events 
			WHERE created_at < datetime('now', '-' || ? || ' days')
			RETURNING id
		`).bind(retentionDays).run();
		
		if (result.changes > 0) {
			console.log(`Cleaned up ${result.changes} old events (${retentionDays} day retention)`);
		}
	} catch (error) {
		console.error('Error cleaning up old events:', error);
	}
}

async function retryFailedEvent(eventId: string, env: Env, ctx: ExecutionContext): Promise<boolean> {
	const event = await env.DB.prepare(`
		SELECT e.*, ep.max_retries
		FROM events e
		JOIN endpoints ep ON ep.id = e.endpoint_id
		WHERE e.id = ? AND e.status = 'failed'
	`).bind(eventId).first<any>();

	if (!event) {
		return false;
	}

	await env.DB.prepare(`
		UPDATE events 
		SET status = 'pending',
			last_error = NULL,
			completed_at = NULL,
			alert_sent = 0
		WHERE id = ?
	`).bind(eventId).run();

	ctx.waitUntil(processWebhookDelivery(env, eventId, true));
	return true;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		try {
			const url = new URL(request.url);
			
			// Is not needed?!?!?!
			const corsHeaders = {
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type, Authorization',
			};

			if (url.pathname.startsWith('/retry/')) {
				if (request.method === 'OPTIONS') {
					return new Response(null, {
						headers: corsHeaders,
						status: 204,
					});
				}

				if (request.method !== 'POST') {
					return new Response('Method Not Allowed', { 
						status: 405,
						headers: corsHeaders
					});
				}

				const authHeader = request.headers.get('Authorization');
				if (!authHeader || !authHeader.startsWith('Bearer ')) {
					return new Response('Unauthorized', { 
						status: 401,
						headers: corsHeaders
					});
				}

				const apiKey = authHeader.replace('Bearer ', '');
				if (!env.API_KEY || apiKey !== env.API_KEY) {
					return new Response('Unauthorized', { 
						status: 401,
						headers: corsHeaders
					});
				}

				const eventId = url.pathname.split('/')[2];
				if (!eventId) {
					return new Response('Event ID is required', { 
						status: 400,
						headers: corsHeaders
					});
				}

				const success = await retryFailedEvent(eventId, env, ctx);
				if (!success) {
					return new Response('Event not found or not in failed state', { 
						status: 404,
						headers: corsHeaders
					});
				}

				return new Response('Event queued for retry', { 
					status: 202,
					headers: corsHeaders
				});
			}

			if (request.method !== 'POST') {
				return new Response('Method Not Allowed', { status: 405 });
			}

			if (Math.random() < 0.01) {
				ctx.waitUntil(cleanupOldEvents(env));
			}

			const contentLength = parseInt(request.headers.get('content-length') || '0');
			const maxPayloadSize = Number(env.MAX_PAYLOAD_SIZE || 10485760);

			if (contentLength > maxPayloadSize) {
				return new Response('Payload too large', { status: 413 });
			}

			const slug = url.pathname.split('/')[1];
			
			if (!slug || !/^[a-zA-Z0-9-_]{5,64}$/.test(slug)) {
				return new Response('Not Found', { status: 404 });
			}

			console.log('Received request for slug:', slug);

			const endpointPromise = env.DB.prepare(
				'SELECT * FROM endpoints WHERE slug = ?'
			).bind(slug).first<Endpoint>();

			const endpoint = await Promise.race([
				endpointPromise,
				new Promise((_, reject) => 
					setTimeout(() => reject(new Error('DB timeout')), 5000)
				)
			]) as Endpoint;

			if (!endpoint) {
				return new Response('Not Found', { status: 404 });
			}

			try {
				new URL(endpoint.target_url);
			} catch {
				console.error('Invalid target URL configuration');
				return new Response('Internal Server Error', { status: 500 });
			}

			if (typeof endpoint.id === 'undefined') {
				console.error('Endpoint found but has no ID:', endpoint);
				return new Response('Invalid endpoint configuration', { status: 500 });
			}

			const rawBody = await request.text();
			let payload;
			try {
				payload = JSON.parse(rawBody);
			} catch (error) {
				return new Response('', { status: 422 });
			}
			
			if (!payload || typeof payload !== 'object') {
				return new Response('Invalid payload format', { status: 400 });
			}

			const headers = Object.fromEntries(request.headers);

			if (endpoint.signature_header && endpoint.signature_type && endpoint.secret_key) {
				const signature = request.headers.get(endpoint.signature_header);
				if (!signature) {
					return new Response('Unauthorized', { status: 401 });
				}

				try {
					const isValid = await verifySignature(
						rawBody,
						signature,
						endpoint.secret_key,
						endpoint.signature_type,
						env.ENCRYPTION_KEY
					);

					if (!isValid) {
						await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
						return new Response('Unauthorized', { status: 401 });
					}
				} catch (error) {
					return new Response('Unauthorized', { status: 401 });
				}
			}
			
			const eventPayload = JSON.stringify(payload);
			const eventHeaders = JSON.stringify(headers);
			
			const eventId = crypto.randomUUID();
			
			let idempotencyKey = request.headers.get('Idempotency-Key');
			if (!idempotencyKey) {
				idempotencyKey = await generateIdempotencyKey(eventPayload, slug);
			}

			const result = await env.DB.prepare(`
				BEGIN TRANSACTION;
				INSERT OR IGNORE INTO events (
					id, endpoint_id, payload, headers, status, 
					retry_count, alert_sent, idempotency_key
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
				COMMIT;
			`).bind(
				eventId,
				endpoint.id,
				eventPayload,
				eventHeaders,
				'pending',
				0,
				false,
				idempotencyKey
			).run();

			if (!result) {
				const existing = await env.DB.prepare(`
					SELECT id, status FROM events 
					WHERE idempotency_key = ?
				`).bind(idempotencyKey).first<{ id: string; status: string }>();
				
				if (!existing) {
					return new Response('Not found', { status: 404 });
				}
				
				return new Response('Already processed', { 
					status: 200,
					headers: {
						'X-Event-ID': existing.id,
						'X-Idempotency-Key': idempotencyKey
					}
				});
			}

			const tx = env.DB.batch([]);
			try {
				const queueId = await scheduleWebhookDelivery(
					env, 
					eventId, 
					endpoint.id,
					endpoint.max_retries
				);

				ctx.waitUntil(processWebhookDelivery(env, queueId));

				return new Response('Webhook accepted', { 
					status: 202,
					headers: {
						'X-Event-ID': eventId
					}
				});
			} catch (error) {
				console.error('Error processing webhook:', error);
				return new Response('Internal Server Error', { status: 500 });
			}
		} catch (error) {
			return handleSystemError(error as Error, request, env, ctx);
		}
	},

	async queue(batch: MessageBatch<WebhookMessage>, env: Env): Promise<void> {
		const maxRetries = 2;
		
		for (const message of batch.messages) {
			try {
				const { eventId, endpointId, targetUrl, payload, headers } = message.body;
				const currentAttempt = message.attempts - 1;

				const stuckEvent = await env.DB.prepare(`
					SELECT id, endpoint_id, retry_count 
					FROM events 
					WHERE id = ? 
					AND status = 'processing' 
					AND last_attempt < datetime('now', '-5 minutes')
				`).bind(eventId).first();

				if (stuckEvent) {
					await handleFailedDelivery(env, {
						eventId,
						targetUrl,
						payload,
						attempt: currentAttempt,
						error: new Error('Event timed out in processing state'),
						isFinalAttempt: currentAttempt >= maxRetries
					});
					message.ack();
					continue;
				}

				await env.DB.prepare(`
					UPDATE events 
					SET status = 'processing',
						retry_count = ?,
						last_attempt = CURRENT_TIMESTAMP
					WHERE id = ?
				`).bind(currentAttempt + 1, eventId).run();

				await forwardWebhookWithTimeout(
					targetUrl,
					payload,
					headers,
					env.OUTGOING_SIGNING_KEY,
					env
				);

				await env.DB.prepare(`
					UPDATE events 
					SET status = 'success',
						completed_at = CURRENT_TIMESTAMP
					WHERE id = ?
				`).bind(eventId).run();

				message.ack();

			} catch (error) {
				console.error('Error processing queued webhook:', error);
				
				const currentAttempt = message.attempts - 1;
				
				await handleFailedDelivery(env, {
					eventId: message.body.eventId,
					targetUrl: message.body.targetUrl,
					payload: message.body.payload,
					attempt: currentAttempt,
					error: error as Error,
					isFinalAttempt: currentAttempt >= maxRetries
				});

				if (currentAttempt >= maxRetries) {
					message.ack();
				} else {
					const baseDelay = Math.min(Math.pow(2, currentAttempt) * 30, 3600);
					const jitter = Math.random() * 0.3 * baseDelay;
					const delaySeconds = Math.ceil(baseDelay + jitter);
					message.retry({ delaySeconds });
				}
			}
		}
	}
} satisfies ExportedHandler<Env>;

async function handleFailedDelivery(env: Env, {
	eventId,
	targetUrl,
	payload,
	attempt,
	error,
	isFinalAttempt
}: {
	eventId: string;
	targetUrl: string;
	payload: any;
	attempt: number;
	error: Error;
	isFinalAttempt: boolean;
}) {
	const errorMessage = error.message;

	await env.DB.prepare(`
		UPDATE events 
		SET status = ?,
			last_error = ?,
			alert_sent = ?,
			retry_count = ?,
			completed_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END
		WHERE id = ?
	`).bind(
		isFinalAttempt ? 'failed' : 'pending',
		errorMessage,
		isFinalAttempt ? 1 : 0,
		attempt + 1,
		isFinalAttempt,
		eventId
	).run();

	if (isFinalAttempt) {
		const eventDetails = {
			id: eventId,
			target_url: targetUrl,
			payload: JSON.stringify(payload),
			retry_count: attempt + 1
		};

		await sendAlert(env.SLACK_WEBHOOK_URL, eventDetails, error);
		await sendFailureAlert(eventDetails, error, env);
	}
}
