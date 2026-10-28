import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import express from 'express';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hash = value => createHash('sha256').update(String(value)).digest('hex');
const fail = (status, message) => { const error = new Error(message); error.status = status; throw error; };
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));
const id = value => uuid.test(value || '') ? value.toLowerCase() : fail(400, 'Expected UUID');
const outcomes = new Set(['response_produced', 'cancelled', 'error', 'interrupted']);
const eventNames = new Set(['diagnostic', 'presentation_started', 'request_received', 'request_validated', 'response_intent_ready', 'connected', 'disconnected', 'response_produced', 'response_sent', 'cancelled', 'error', 'interrupted']);
const cas = `if redis.call('GET',KEYS[1]) == ARGV[1] then redis.call('SET',KEYS[1],ARGV[2],'KEEPTTL'); return 1 else return 0 end`;

// Separate evidence storage: atomic compare-and-swap avoids concurrent upload loss.
export class WalletReporting {
  constructor(redis, { now = () => Date.now(), secret = process.env.ITB_WALLET_TOKEN_SECRET, executionMs = 240000, graceMs = 86400000 } = {}) {
    this.redis = redis; this.now = now; this.secret = secret; this.executionMs = executionMs; this.graceMs = graceMs;
  }
  token(s) {
    if (!this.secret || this.secret.length < 32) fail(503, 'Reporting token secret is not configured');
    return createHmac('sha256', this.secret).update(`${s.sessionId}:${s.installationId}:${s.pairingRequestId}`).digest('base64url');
  }
  async create(sessionId) {
    if (!this.secret || this.secret.length < 32) fail(503, 'Reporting token secret is not configured');
    sessionId = id(sessionId); const now = this.now();
    const s = { sessionId, expiresAt: now + this.executionMs, uploadExpiresAt: now + this.executionMs + this.graceMs, events: {}, status: 'pending' };
    const ok = await this.redis.set(`itb-wallet:${sessionId}`, JSON.stringify(s), { NX: true, PX: this.executionMs + this.graceMs * 2 });
    if (!ok) fail(409, 'Execution UUID already exists');
    return this.view(s);
  }
  async read(sessionId) {
    sessionId = id(sessionId); const raw = await this.redis.get(`itb-wallet:${sessionId}`);
    if (!raw) fail(404, 'Unknown execution');
    return JSON.parse(raw);
  }
  view(s) { return { sessionId: s.sessionId, status: s.status === 'completed' ? 'completed' : this.now() > s.uploadExpiresAt ? 'expired' : 'pending', expiresAt: s.expiresAt, uploadExpiresAt: s.uploadExpiresAt, paired: !!s.installationId, reportedOutcome: s.reportedOutcome, evidenceComplete: s.status === 'completed' }; }
  async mutate(sessionId, change) {
    sessionId = id(sessionId);
    for (let i = 0; i < 20; i++) {
      const s = await this.read(sessionId), before = JSON.stringify(s);
      const result = change(s);
      if (await this.redis.eval(cas, { keys: [`itb-wallet:${sessionId}`], arguments: [before, JSON.stringify(s)] })) return result;
    }
    fail(503, 'Concurrent update; retry');
  }
  async pair(sessionId, body) {
    const installationId = id(body.installationId), pairingRequestId = id(body.pairingRequestId);
    return this.mutate(sessionId, s => {
      if (s.installationId && (s.installationId !== installationId || s.pairingRequestId !== pairingRequestId)) fail(409, 'Execution already paired');
      if (s.status === 'completed' || this.now() > s.expiresAt) fail(410, 'Execution closed');
      s.installationId = installationId; s.pairingRequestId = pairingRequestId;
      return { ...this.view(s), uploadToken: this.token(s) };
    });
  }
  authorize(s, token) {
    if (!s.installationId || !equal(this.token(s), token)) fail(401, 'Invalid upload capability');
    if (this.now() > s.uploadExpiresAt) fail(410, 'Upload window closed');
  }
  async events(sessionId, attemptId, body, token) {
    id(attemptId);
    if (body.schemaVersion !== 1 || !Array.isArray(body.events) || !body.events.length || body.events.length > 100) fail(400, 'Invalid event batch');
    const entries = body.events.map(e => {
      if (!e || typeof e !== 'object' || Array.isArray(e)) fail(400, 'Invalid event');
      id(e.eventId);
      if (!Number.isSafeInteger(e.sequence) || e.sequence < 1 || e.sequence > 2000 || !Number.isFinite(Date.parse(e.timestamp)) || !eventNames.has(e.metadata?.event)) fail(400, 'Invalid event');
      // Accept structured metadata only. Arbitrary text, credentials and tokens never enter the report.
      const metadata = { event: e.metadata.event };
      if (['dc_api', 'openid4vp', 'proximity'].includes(e.metadata.transport)) metadata.transport = e.metadata.transport;
      if (typeof e.metadata.errorType === 'string' && /^[A-Za-z0-9_$]{1,96}$/.test(e.metadata.errorType)) metadata.errorType = e.metadata.errorType;
      const stages = ['qr_engagement_ready', 'connecting', 'redirect_received', 'key_unlock_check',
        'key_unlocked', 'response_generation_started', 'response_generated', 'response_dispatch_started',
        'selection_updated', 'transfer_callback', 'request_processing', 'generate_or_send_response'];
      if (stages.includes(e.metadata.stage)) metadata.stage = e.metadata.stage;
      for (const key of ['elapsedMs', 'combinationCount', 'matchCount', 'credentialCount',
        'selectionCount', 'selectedClaimCount', 'unlockedKeyCount']) {
        if (Number.isSafeInteger(e.metadata[key]) && e.metadata[key] >= 0) metadata[key] = e.metadata[key];
      }
      for (const key of ['verifierFullyVerified', 'authenticationRequired']) {
        if (typeof e.metadata[key] === 'boolean') metadata[key] = e.metadata[key];
      }
      if (typeof e.metadata.exceptionClass === 'string' && /^[A-Za-z0-9_.$]{1,256}$/.test(e.metadata.exceptionClass)) metadata.exceptionClass = e.metadata.exceptionClass;
      if (typeof e.metadata.causeClasses === 'string' && e.metadata.causeClasses.length <= 2048 &&
        e.metadata.causeClasses.split(' -> ').every(c => /^[A-Za-z0-9_.$]{1,256}$/.test(c))) metadata.causeClasses = e.metadata.causeClasses;
      // Frame syntax only; never persist throwable messages or arbitrary debug text.
      if (typeof e.metadata.stackTrace === 'string' && e.metadata.stackTrace.length <= 4096 &&
        e.metadata.stackTrace.split('\n').every(line => /^(?:(?:Caused by: )?[A-Za-z0-9_.$]+|at [A-Za-z0-9_.$<>]+\([A-Za-z0-9_.$ :+-]+\))$/.test(line))) metadata.stackTrace = e.metadata.stackTrace;
      return { eventId: e.eventId, attemptId, sequence: e.sequence, timestamp: new Date(e.timestamp).toISOString(), level: e.metadata.event === 'error' ? 'error' : e.metadata.event === 'diagnostic' ? 'debug' : 'info', message: e.metadata.event.replaceAll('_', ' '), metadata };
    });
    return this.mutate(sessionId, s => {
      this.authorize(s, token);
      for (const e of entries) {
        const existing = s.events[e.eventId];
        if (existing && JSON.stringify(existing.event) !== JSON.stringify(e)) fail(409, 'Conflicting event ID');
        if (!existing) {
          if (s.status === 'completed') fail(409, 'Execution completed');
          if (Object.keys(s.events).length >= 2000) fail(413, 'Evidence limit reached');
          if (Object.values(s.events).some(x => x.event.attemptId === attemptId && x.event.sequence === e.sequence)) fail(409, 'Conflicting event sequence');
          s.events[e.eventId] = { event: e, receivedAt: new Date(this.now()).toISOString() };
        }
      }
      return { acceptedEventIds: entries.map(e => e.eventId) };
    });
  }
  async complete(sessionId, body, token) {
    id(body.completionId);
    if (body.schemaVersion !== 1 || !outcomes.has(body.reportedOutcome) || !Array.isArray(body.attempts) || body.attempts.length < 1 || body.attempts.length > 100) fail(400, 'Invalid completion');
    const completion = { schemaVersion: 1, completionId: body.completionId, reportedOutcome: body.reportedOutcome, attempts: body.attempts.map(a => {
      if (!a || typeof a !== 'object') fail(400, 'Invalid attempt manifest');
      return { attemptId: a.attemptId, finalSequence: a.finalSequence };
    }) };
    return this.mutate(sessionId, s => {
      this.authorize(s, token);
      if (s.completion) {
        if (JSON.stringify(s.completion) !== JSON.stringify(completion)) fail(409, 'Conflicting completion');
        return this.view(s);
      }
      const seen = new Set();
      for (const a of body.attempts) {
        id(a.attemptId);
        if (seen.has(a.attemptId) || !Number.isSafeInteger(a.finalSequence) || a.finalSequence < 1 || a.finalSequence > 2000) fail(400, 'Invalid attempt manifest');
        seen.add(a.attemptId);
        const events = Object.values(s.events).filter(x => x.event.attemptId === a.attemptId);
        if (events.length !== a.finalSequence || events.some(x => x.event.sequence > a.finalSequence)) fail(409, 'Incomplete evidence');
      }
      if (Object.values(s.events).some(x => !seen.has(x.event.attemptId))) fail(409, 'Missing attempt manifest');
      s.completion = completion; s.reportedOutcome = body.reportedOutcome; s.status = 'completed'; s.completedAt = new Date(this.now()).toISOString();
      return this.view(s);
    });
  }
  async logs(sessionId) {
    const s = await this.read(sessionId);
    const logs = Object.values(s.events).map(x => ({ ...x.event, receivedAt: x.receivedAt })).sort((a, b) => a.attemptId.localeCompare(b.attemptId) || a.sequence - b.sequence);
    if (s.status === 'completed') logs.push({ timestamp: s.completedAt, level: 'info', message: 'Wallet reported outcome', metadata: { reportedOutcome: s.reportedOutcome, evidenceComplete: true } });
    return { sessionId, logs, count: logs.length };
  }
}

export function walletReportingRouter(service, { apiKey = process.env.ITB_WALLET_SERVICE_KEY } = {}) {
  const router = express.Router();
  router.use(express.json({ limit: '128kb' }));
  router.use((req, res, next) => {
    if (req.method === 'POST' && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body))) return res.status(400).json({ error: 'Expected JSON object' });
    next();
  });
  router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const trusted = (req, res, next) => apiKey && equal(req.get('X-ITB-Service-Key'), apiKey) ? next() : res.status(401).json({ error: 'Service authorization required' });
  const wrap = fn => async (req, res) => { try { res.json(await fn(req)); } catch (e) { res.status(e.status || 503).json({ error: e.status ? e.message : 'Evidence storage unavailable' }); } };
  const bearer = req => req.get('Authorization')?.replace(/^Bearer /, '');
  router.post('/sessions', trusted, wrap(req => service.create(req.body.sessionId || randomUUID())));
  // Redis-backed rate limit works across service workers, including invalid UUIDs.
  router.post('/sessions/:id/pair', async (req, res, next) => {
    try {
      const key = `itb-wallet-rate:${hash(req.ip)}:${Math.floor(service.now() / 60000)}`;
      const n = await service.redis.incr(key); if (n === 1) await service.redis.expire(key, 120);
      if (n > 20) return res.status(429).json({ error: 'Too many pairing attempts' });
      next();
    } catch { res.status(503).json({ error: 'Pairing unavailable' }); }
  }, wrap(req => service.pair(req.params.id, req.body)));
  router.post('/sessions/:id/attempts/:attempt/events', wrap(req => service.events(req.params.id, req.params.attempt, req.body, bearer(req))));
  router.post('/sessions/:id/complete', wrap(req => service.complete(req.params.id, req.body, bearer(req))));
  // Query token is deliberately unsupported; test-service reads use the same secret header.
  router.get('/sessions/:id', trusted, wrap(async req => service.view(await service.read(req.params.id))));
  router.get('/sessions/:id/logs', trusted, wrap(req => service.logs(req.params.id)));
  router.use((_req, res) => res.status(404).json({ error: 'Unknown reporting endpoint' }));
  router.use((error, _req, res, _next) => res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: 'Invalid reporting request body' }));
  return router;
}
