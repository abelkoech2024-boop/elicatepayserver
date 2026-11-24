'use strict';

/*
 * Elicate Pay backend for Node.js 20+ / Render.
 *
 * Render environment variables:
 *   APP_API_KEY                  Long random key for server-only routes (required to use protected routes)
 *   ELICATEPAY_SECRET_KEY        Elicate Pay secret key (ep_test_sk_... or ep_live_sk_...)
 *   ELICATEPAY_PUBLIC_KEY        Elicate Pay public key (ep_test_pk_... or ep_live_pk_...)
 *   ELICATEPAY_WEBHOOK_SECRET    HMAC secret configured for your webhook
 *   ALLOWED_ORIGINS              Comma-separated exact frontend origins, e.g. https://shop.example.com,https://admin.example.com
 *   PORT                         Supplied by Render
 *
 * Public browser routes: POST /api/checkout/pay and GET /api/checkout/status/:transactionId.
 * All other API routes require Authorization: Bearer <APP_API_KEY> (or X-App-Api-Key),
 * except the signed incoming webhook at POST /api/webhooks/elicatepay.
 * Receipts are returned with collection responses and are not persisted by this server.
 */

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ELicatePAY_BASE_URL = 'https://elicatepay.online';
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5173')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean),
);

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    // Requests without an Origin header are usually server-to-server.
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('Origin is not in ALLOWED_ORIGINS'));
  },
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-App-Api-Key'],
  maxAge: 600,
}));
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
}));

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function requireSetting(name) {
  const value = process.env[name];
  if (!value || !value.trim()) throw new HttpError(503, `Server configuration is missing ${name}.`);
  return value.trim();
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAppKey(req, res, next) {
  const expected = process.env.APP_API_KEY;
  if (!expected) {
    return res.status(503).json({ error: 'Server configuration is missing APP_API_KEY.' });
  }
  const bearer = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '');
  const supplied = req.get('x-app-api-key') || (bearer && bearer[1]);
  if (!supplied || !safeEqual(supplied, expected)) {
    return res.status(401).json({ error: 'Valid server API key required.' });
  }
  return next();
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function makeReference(prefix = 'ORDER') {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
}

function cleanString(value, name, { required = false, max = 200 } = {}) {
  if (value === undefined || value === null || value === '') {
    if (required) throw new HttpError(400, `${name} is required.`);
    return undefined;
  }
  if (typeof value !== 'string') throw new HttpError(400, `${name} must be a string.`);
  const cleaned = value.trim();
  if (!cleaned && required) throw new HttpError(400, `${name} is required.`);
  if (cleaned.length > max) throw new HttpError(400, `${name} is too long.`);
  return cleaned || undefined;
}

function cleanAmount(value, { required = true } = {}) {
  if ((value === undefined || value === null || value === '') && !required) return undefined;
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0 || !Number.isSafeInteger(Math.round(amount * 100))) {
    throw new HttpError(400, 'amount must be a positive number.');
  }
  return Math.round(amount * 100) / 100;
}

function cleanMinimumAmount(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0 || !Number.isSafeInteger(Math.round(amount * 100))) {
    throw new HttpError(400, 'min_amount must be a non-negative number.');
  }
  return Math.round(amount * 100) / 100;
}

function cleanReference(value) {
  const reference = cleanString(value, 'reference', { max: 128 });
  if (reference && !/^[A-Za-z0-9._:-]+$/.test(reference)) {
    throw new HttpError(400, 'reference may contain only letters, numbers, dots, underscores, colons, and hyphens.');
  }
  return reference || makeReference();
}

function normalizeStatus(value, fallback = 'pending') {
  const status = String(value || '').toLowerCase().trim();
  if (status === 'redirect') return 'pending';
  if (['pending', 'success', 'test success', 'failed'].includes(status)) return status;
  return fallback;
}

function receiptNumber(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function createReceipt({
  transactionId = null,
  status = 'pending',
  amount = null,
  fee = null,
  netAmount = null,
  currency = 'ZMW',
  reference = null,
} = {}) {
  const now = new Date().toISOString();
  return {
    receipt_id: transactionId ? `rcpt_${transactionId}` : `rcpt_${crypto.randomUUID()}`,
    transaction_id: transactionId,
    kind: 'payment',
    status: normalizeStatus(status),
    amount: receiptNumber(amount),
    fee: receiptNumber(fee),
    net_amount: receiptNumber(netAmount),
    currency: currency || 'ZMW',
    reference: reference || null,
    created_at: now,
    updated_at: now,
  };
}

async function providerRequest(path, { method = 'GET', body, auth = 'secret' } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth === 'secret') headers.Authorization = `Bearer ${requireSetting('ELICATEPAY_SECRET_KEY')}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  try {
    const response = await fetch(`${ELicatePAY_BASE_URL}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { error: text.slice(0, 500) || 'Provider returned an unreadable response.' };
    }
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

function providerMessage(data, fallback) {
  const message = data && (data.error || data.message);
  return typeof message === 'string' && message.trim()
    ? message.trim().slice(0, 400)
    : fallback;
}

function validTransactionId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function validatePayment(body, { checkout = false } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError(400, 'A JSON request body is required.');
  }
  const network = cleanString(body.network, 'network', { required: true, max: 20 }).toUpperCase();
  const allowed = checkout ? ['MTN', 'AIRTEL', 'ZAMTEL'] : ['MTN', 'AIRTEL', 'ZAMTEL', 'CARD'];
  if (!allowed.includes(network)) {
    throw new HttpError(400, `network must be one of: ${allowed.join(', ')}.`);
  }
  const phone = cleanString(body.phone, 'phone', { required: network !== 'CARD', max: 24 });
  if (phone && !/^\+?[0-9 ()-]{6,24}$/.test(phone)) throw new HttpError(400, 'phone has an invalid format.');
  const customerName = cleanString(body.customer_name ?? body.name, 'customer_name', { max: 200 }) || 'Customer';
  const email = cleanString(body.email, 'email', { max: 254 });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'email has an invalid format.');
  const amount = cleanAmount(body.amount, { required: !(checkout && body.link_slug) });
  const reference = cleanReference(body.reference);
  const currency = (cleanString(body.currency, 'currency', { max: 3 }) || 'ZMW').toUpperCase();
  if (!/^[A-Z]{3}$/.test(currency)) throw new HttpError(400, 'currency must be a three-letter code.');

  return {
    amount,
    phone,
    network,
    currency,
    reference,
    customer_name: customerName,
    ...(email ? { email } : {}),
  };
}

function publicCheckoutPayload(body, validated) {
  const linkSlug = cleanString(body.link_slug, 'link_slug', { max: 80 });
  if (!linkSlug && !process.env.ELICATEPAY_PUBLIC_KEY) {
    throw new HttpError(503, 'Server configuration is missing ELICATEPAY_PUBLIC_KEY.');
  }
  const payload = {
    customer_name: validated.customer_name,
    phone: validated.phone,
    network: validated.network,
    reference: validated.reference,
  };
  if (linkSlug) payload.link_slug = linkSlug;
  else payload.public_key = requireSetting('ELICATEPAY_PUBLIC_KEY');
  if (validated.amount !== undefined) payload.amount = validated.amount;
  if (body.description) payload.description = cleanString(body.description, 'description', { max: 500 });
  return payload;
}

async function submitPayment(req, res, { checkout }) {
  if (checkout) {
    // Link-slug checkout uses the public endpoint; direct checkout needs the public key.
    if (!req.body?.link_slug) requireSetting('ELICATEPAY_PUBLIC_KEY');
  } else {
    requireSetting('ELICATEPAY_SECRET_KEY');
  }

  const validated = validatePayment(req.body, { checkout });
  const input = checkout
    ? publicCheckoutPayload(req.body, validated)
    : {
        ...validated,
        ...(req.body.redirect_url
          ? { redirect_url: cleanString(req.body.redirect_url, 'redirect_url', { max: 2048 }) }
          : {}),
      };
  if (input.redirect_url) {
    let redirect;
    try { redirect = new URL(input.redirect_url); } catch { throw new HttpError(400, 'redirect_url must be a valid HTTPS URL.'); }
    if (redirect.protocol !== 'https:') throw new HttpError(400, 'redirect_url must use HTTPS.');
  }

  let result;
  try {
    const endpoint = checkout ? '/api/v1/checkout/pay' : '/api/v1/payments/charge';
    result = await providerRequest(endpoint, {
      method: 'POST',
      body: input,
      auth: checkout ? 'none' : 'secret',
    });
  } catch {
    const receipt = createReceipt({
      status: 'pending',
      amount: validated.amount,
      currency: validated.currency,
      reference: validated.reference,
    });
    return res.status(502).json({
      error: 'The payment outcome could not be confirmed. Check its status before retrying.',
      receipt,
    });
  }

  const data = result.data && typeof result.data === 'object' ? result.data : {};
  const providerTransactionId = data.transaction_id || null;
  const status = result.ok
    ? normalizeStatus(data.status)
    : (result.status >= 500 ? 'pending' : 'failed');
  const receipt = createReceipt({
    transactionId: providerTransactionId,
    status,
    amount: data.amount ?? validated.amount,
    fee: data.fee,
    netAmount: data.net_amount,
    currency: data.currency || validated.currency,
    reference: data.reference || validated.reference,
  });

  if (!result.ok) {
    const responseStatus = result.status >= 500 ? 502 : result.status;
    return res.status(responseStatus).json({
      error: providerMessage(data, 'Payment request was rejected.'),
      receipt,
    });
  }
  return res.status(result.status).json({ ...data, receipt });
}

app.get('/health', asyncRoute(async (_req, res) => {
  return res.json({ status: 'ok' });
}));

// Public checkout uses only the public key. It never accepts a secret provider key from a browser.
app.post('/api/checkout/pay', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
}), express.json({ limit: '32kb' }), asyncRoute(async (req, res) => {
  await submitPayment(req, res, { checkout: true });
}));

app.get('/api/checkout/status/:transactionId', asyncRoute(async (req, res) => {
  const transactionId = req.params.transactionId;
  if (!validTransactionId(transactionId)) throw new HttpError(400, 'Invalid transaction_id.');
  const result = await providerRequest(
    `/api/v1/checkout/status/${encodeURIComponent(transactionId)}`,
    { auth: 'none' },
  );
  if (!result.ok) {
    return res.status(result.status).json({
      error: providerMessage(result.data, 'Could not retrieve payment status.'),
    });
  }

  const data = result.data || {};
  const receipt = createReceipt({
    transactionId: data.transaction_id || transactionId,
    status: normalizeStatus(data.status),
    amount: data.amount,
    fee: data.fee,
    netAmount: data.net_amount,
    currency: data.currency || 'ZMW',
    reference: data.reference,
  });
  return res.json({ ...data, receipt });
}));

// Secret-key charge, transaction details, and server-sent status stream.
app.post('/api/payments/charge', requireAppKey, express.json({ limit: '32kb' }), asyncRoute(async (req, res) => {
  await submitPayment(req, res, { checkout: false });
}));

app.get('/api/payments/:transactionId/stream', requireAppKey, asyncRoute(async (req, res) => {
  const transactionId = req.params.transactionId;
  if (!validTransactionId(transactionId)) throw new HttpError(400, 'Invalid transaction_id.');
  const secret = requireSetting('ELICATEPAY_SECRET_KEY');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 65_000);
  res.on('close', () => controller.abort());

  let upstream;
  try {
    upstream = await fetch(
      `${ELicatePAY_BASE_URL}/api/v1/payments/${encodeURIComponent(transactionId)}/stream`,
      { headers: { Authorization: `Bearer ${secret}`, Accept: 'text/event-stream' }, signal: controller.signal },
    );
  } catch {
    clearTimeout(timeout);
    if (!res.headersSent) return res.status(502).json({ error: 'Could not connect to the payment status stream.' });
    return res.end();
  }

  if (!upstream.ok || !upstream.body) {
    clearTimeout(timeout);
    const text = upstream.body ? await upstream.text() : '';
    let data;
    try { data = JSON.parse(text); } catch { data = { error: text }; }
    return res.status(upstream.status).json({
      error: providerMessage(data, 'Could not open the payment status stream.'),
    });
  }

  res.status(200);
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  let buffer = '';
  const decoder = new TextDecoder();
  try {
    for await (const chunk of upstream.body) {
      if (res.destroyed) break;
      buffer += decoder.decode(chunk, { stream: true });
      let boundary;
      while ((boundary = buffer.search(/\r?\n\r?\n/)) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary).replace(/^\r?\n\r?\n/, '');
        const dataLines = frame.split(/\r?\n/).filter((line) => line.startsWith('data:'));
        let outputFrame = frame;
        try {
          const eventData = dataLines.length
            ? JSON.parse(dataLines.map((line) => line.slice(5).trim()).join('\n'))
            : null;
          if (eventData.transaction_id && eventData.status) {
            eventData.receipt = createReceipt({
              transactionId: eventData.transaction_id,
              status: eventData.status,
              amount: eventData.amount,
              fee: eventData.fee,
              netAmount: eventData.net_amount,
              currency: eventData.currency || 'ZMW',
              reference: eventData.reference,
            });
            outputFrame = [
              ...frame.split(/\r?\n/).filter((line) => !line.startsWith('data:')),
              `data: ${JSON.stringify(eventData)}`,
            ].join('\n');
          }
        } catch {
          // Forward provider events that do not contain JSON payment data unchanged.
        }
        res.write(`${outputFrame}\n\n`);
      }
    }
    if (buffer && !res.destroyed) res.write(buffer);
  } catch {
    if (!res.destroyed) res.write('event: error\ndata: {"message":"Status stream interrupted"}\n\n');
  } finally {
    clearTimeout(timeout);
    if (!res.destroyed) res.end();
  }
}));

app.get('/api/payments/:transactionId', requireAppKey, asyncRoute(async (req, res) => {
  const transactionId = req.params.transactionId;
  if (!validTransactionId(transactionId)) throw new HttpError(400, 'Invalid transaction_id.');
  const result = await providerRequest(`/api/v1/payments/${encodeURIComponent(transactionId)}`);
  if (!result.ok) {
    return res.status(result.status).json({ error: providerMessage(result.data, 'Could not retrieve transaction details.') });
  }
  const data = result.data || {};
  const receipt = createReceipt({
    transactionId: data.transaction_id || transactionId,
    status: normalizeStatus(data.status),
    amount: data.amount,
    fee: data.fee,
    netAmount: data.net_amount,
    currency: data.currency || 'ZMW',
    reference: data.reference,
  });
  return res.json({ ...data, receipt });
}));

// Payment links.
app.get('/api/payment-links', requireAppKey, asyncRoute(async (_req, res) => {
  const result = await providerRequest('/api/v1/payment-links');
  return res.status(result.status).json(result.data);
}));

app.post('/api/payment-links', requireAppKey, express.json({ limit: '32kb' }), asyncRoute(async (req, res) => {
  const body = req.body || {};
  const name = cleanString(body.name, 'name', { required: true, max: 200 });
  const type = cleanString(body.type, 'type', { required: true, max: 20 });
  if (!['fixed', 'flexible'].includes(type)) throw new HttpError(400, 'type must be fixed or flexible.');
  const payload = { name, type };
  if (type === 'fixed') payload.amount = cleanAmount(body.amount);
  if (type === 'flexible' && body.min_amount !== undefined) payload.min_amount = cleanMinimumAmount(body.min_amount);
  if (body.description !== undefined) payload.description = cleanString(body.description, 'description', { max: 500 });
  if (body.redirect_url !== undefined) {
    payload.redirect_url = cleanString(body.redirect_url, 'redirect_url', { max: 2048 });
    let redirect;
    try { redirect = new URL(payload.redirect_url); } catch { throw new HttpError(400, 'redirect_url must be a valid HTTPS URL.'); }
    if (redirect.protocol !== 'https:') throw new HttpError(400, 'redirect_url must use HTTPS.');
  }
  const result = await providerRequest('/api/v1/payment-links', { method: 'POST', body: payload });
  return res.status(result.status).json(result.data);
}));

app.get('/api/payment-links/:linkId', requireAppKey, asyncRoute(async (req, res) => {
  const linkId = cleanString(req.params.linkId, 'linkId', { required: true, max: 128 });
  const result = await providerRequest(`/api/v1/payment-links/${encodeURIComponent(linkId)}`);
  return res.status(result.status).json(result.data);
}));

app.patch('/api/payment-links/:linkId', requireAppKey, express.json({ limit: '32kb' }), asyncRoute(async (req, res) => {
  const linkId = cleanString(req.params.linkId, 'linkId', { required: true, max: 128 });
  const body = req.body || {};
  const payload = {};
  if (body.name !== undefined) payload.name = cleanString(body.name, 'name', { required: true, max: 200 });
  if (body.type !== undefined) {
    payload.type = cleanString(body.type, 'type', { required: true, max: 20 });
    if (!['fixed', 'flexible'].includes(payload.type)) throw new HttpError(400, 'type must be fixed or flexible.');
  }
  if (body.amount !== undefined) payload.amount = cleanAmount(body.amount);
  if (body.min_amount !== undefined) payload.min_amount = cleanMinimumAmount(body.min_amount);
  if (body.description !== undefined) payload.description = cleanString(body.description, 'description', { max: 500 });
  if (body.active !== undefined) {
    if (typeof body.active !== 'boolean') throw new HttpError(400, 'active must be a boolean.');
    payload.active = body.active;
  }
  if (body.redirect_url !== undefined) {
    payload.redirect_url = cleanString(body.redirect_url, 'redirect_url', { max: 2048 });
    let redirect;
    try { redirect = new URL(payload.redirect_url); } catch { throw new HttpError(400, 'redirect_url must be a valid HTTPS URL.'); }
    if (redirect.protocol !== 'https:') throw new HttpError(400, 'redirect_url must use HTTPS.');
  }
  if (Object.keys(payload).length === 0) throw new HttpError(400, 'Include at least one supported field to update.');
  const result = await providerRequest(`/api/v1/payment-links/${encodeURIComponent(linkId)}`, {
    method: 'PATCH',
    body: payload,
  });
  return res.status(result.status).json(result.data);
}));

// Signed Elicate Pay collection webhook.
app.post('/api/webhooks/elicatepay', express.raw({ type: 'application/json', limit: '256kb' }), asyncRoute(async (req, res) => {
  const secret = process.env.ELICATEPAY_WEBHOOK_SECRET;
  if (!secret) return res.status(503).send('Webhook secret is not configured.');
  const signature = req.get('x-elicatepay-signature') || '';
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!/^[a-f0-9]{64}$/i.test(signature)) return res.status(401).send('Invalid signature.');
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  if (!safeEqual(signature.toLowerCase(), expected)) return res.status(401).send('Invalid signature.');

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).send('Invalid JSON.');
  }
  const { event, data } = payload || {};
  if (typeof event !== 'string' || !data || typeof data !== 'object') {
    return res.status(400).send('Invalid webhook payload.');
  }

  if (!event.startsWith('payment.') || !data.transaction_id) {
    // A signed test or unrelated event is acknowledged without creating a receipt.
    return res.status(200).send('OK');
  }
  const transactionId = String(data.transaction_id);
  if (!validTransactionId(transactionId)) return res.status(400).send('Invalid transaction ID.');

  const receipt = createReceipt({
    transactionId,
    status: data.status || (event.endsWith('.success') ? 'success' : event.endsWith('.failed') ? 'failed' : 'pending'),
    amount: data.amount,
    fee: data.fee,
    netAmount: data.net_amount,
    currency: data.currency || 'ZMW',
    reference: data.reference,
  });
  return res.status(200).json({ received: true, receipt });
}));

// Test webhook delivery is sensitive because it sends a request to the supplied URL.
app.post('/api/webhooks/test', requireAppKey, express.json({ limit: '16kb' }), asyncRoute(async (req, res) => {
  const url = cleanString(req.body?.url, 'url', { required: true, max: 2048 });
  let parsed;
  try { parsed = new URL(url); } catch { throw new HttpError(400, 'url must be a valid HTTPS URL.'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new HttpError(400, 'url must be HTTPS and must not contain embedded credentials.');
  }
  const secret = cleanString(req.body?.secret, 'secret', { required: true, max: 500 });
  const result = await providerRequest('/api/v1/webhooks/test', {
    method: 'POST',
    body: { url: parsed.toString(), secret },
  });
  return res.status(result.status).json(result.data);
}));

app.use(express.json({ limit: '32kb' }));

app.use((error, _req, res, _next) => {
  if (res.headersSent) return res.end();
  if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
  if (error && error.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON body.' });
  if (error && error.message === 'Origin is not in ALLOWED_ORIGINS') {
    return res.status(403).json({ error: 'Frontend origin is not allowed. Add it to ALLOWED_ORIGINS.' });
  }
  console.error('Request failed:', error && error.name ? error.name : 'Error');
  return res.status(500).json({ error: 'Internal server error.' });
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Elicate Pay collections backend listening on port ${PORT}`);
  });
}

module.exports = app;
