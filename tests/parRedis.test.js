import { strict as assert } from 'node:assert';
import sinon from 'sinon';

describe('PAR shared Redis storage regression', () => {
  let cache, router, sandbox;
  before(async () => {
    process.env.ALLOW_NO_REDIS = 'true';
    cache = await import('../services/cacheServiceRedis.js');
    router = (await import('../routes/issue/codeFlowSdJwtRoutes.js')).default;
  });
  beforeEach(() => { sandbox = sinon.createSandbox(); });
  afterEach(() => sandbox.restore());

  it('persists a serialized request with the advertised TTL for another worker to read', async () => {
    const data = new Map();
    const writer = { isReady: true, setEx: async (key, ttl, raw) => {
      assert.equal(ttl, 90);
      data.set(key, raw);
    } };
    const reader = { isReady: true, get: async key => data.get(key) ?? null };
    const original = { client_id: 'wallet', state: 'state', redirect_uri: 'https://wallet.example/oauth/callback' };
    await cache.storePushedAuthorizationRequest('urn:test:shared', original, writer);
    original.state = 'changed';
    assert.equal((await cache.getPushedAuthorizationRequest('urn:test:shared', reader)).state, 'state');
    data.clear(); // Redis removes the key when its TTL expires.
    assert.equal(await cache.getPushedAuthorizationRequest('urn:test:shared', reader), null);
  });

  it('does not silently acknowledge a PAR write when Redis is unavailable or rejects it', async () => {
    await assert.rejects(cache.storePushedAuthorizationRequest('urn:test', {}, { isReady: false }), /unavailable/);
    await assert.rejects(cache.storePushedAuthorizationRequest('urn:test', {}, {
      isReady: true, setEx: async () => { throw new Error('write failed'); },
    }), /write failed/);
  });

  it('POST /par awaits Redis persistence before returning a usable request_uri', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    let persisted = false;
    const write = sandbox.stub(cache.client, 'setEx').callsFake(async () => {
      await new Promise(resolve => setImmediate(resolve));
      persisted = true;
    });
    const handler = router.stack.find(layer => Array.isArray(layer.route?.path) && layer.route.path.includes('/par')).route.stack[0].handle;
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; assert.equal(persisted, true); return this; },
      getHeaders() { return {}; },
    };
    await handler({ body: {
      client_id: 'wallet', response_type: 'code',
      redirect_uri: 'https://wallet.example/oauth/callback',
      code_challenge: 'challenge', code_challenge_method: 'S256',
      scope: 'VerifiablePortableDocumentA2SDJWT',
      nonce: 'posted-par-nonce',
    }, headers: {}, get() { return undefined; } }, res);
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.expires_in, 90);
    assert.equal(write.firstCall.args[0], `par-requests:${res.body.request_uri}`);
    assert.equal(JSON.parse(write.firstCall.args[2]).client_id, 'wallet');
    assert.equal(JSON.parse(write.firstCall.args[2]).nonce, 'posted-par-nonce');
  });

  async function authorize() {
    const handler = router.stack.find(layer => layer.route?.path === '/authorize').route.stack[0].handle;
    const res = {
      statusCode: 200, headers: {},
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
      redirect(code, url) { this.statusCode = code; this.location = url; return this; },
      getHeaders() { return this.headers; },
      on() { return this; },
    };
    await handler({ query: { client_id: 'wallet', request_uri: 'urn:test:shared' }, headers: {} }, res);
    return res;
  }

  it('authorizes a PAR request retrieved from Redis without process-local PAR state', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    const par = {
      client_id: 'wallet', issuerState: 'session', state: 'wallet-state',
      redirect_uri: 'https://wallet.example/oauth/callback', response_type: 'code',
      code_challenge: 'challenge', code_challenge_method: 'S256',
      nonce: 'par-nonce-value',
      authorizationDetails: JSON.stringify([{ type: 'openid_credential', credential_configuration_id: 'urn:eu.europa.ec.eudi:pid:1' }]),
    };
    sandbox.stub(cache.client, 'get').callsFake(async key => {
      if (key === 'par-requests:urn:test:shared') return JSON.stringify(par);
      if (key === 'code-flow-sessions:session') return JSON.stringify({ requests: {}, results: {}, isDynamic: false });
      return null;
    });
    const writes = [];
    sandbox.stub(cache.client, 'setEx').callsFake(async (...args) => writes.push(args));
    const res = await authorize();
    assert.equal(res.statusCode, 302);
    const target = new URL(res.location);
    assert.equal(target.origin, 'https://wallet.example');
    assert.equal(target.searchParams.get('state'), 'wallet-state');
    assert.ok(target.searchParams.get('code'));
    const storedSession = writes.find(([key]) => key === 'code-flow-sessions:session');
    assert.equal(JSON.parse(storedSession[2]).nonce, 'par-nonce-value');
  });

  it('ignores front-channel authorization_details when scope-only PAR is resolved from Redis', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    const par = {
      client_id: 'wallet', issuerState: 'session', state: 'wallet-state',
      redirect_uri: 'https://wallet.example/oauth/callback', response_type: 'code',
      code_challenge: 'challenge', code_challenge_method: 'S256',
      scope: 'urn:eu.europa.ec.eudi:pid:1',
      nonce: 'par-scope-nonce',
    };
    sandbox.stub(cache.client, 'get').callsFake(async key => {
      if (key === 'par-requests:urn:test:shared') return JSON.stringify(par);
      if (key === 'code-flow-sessions:session') return JSON.stringify({ requests: {}, results: {}, isDynamic: false });
      return null;
    });
    const writes = [];
    sandbox.stub(cache.client, 'setEx').callsFake(async (...args) => writes.push(args));
    const handler = router.stack.find(layer => layer.route?.path === '/authorize').route.stack[0].handle;
    const res = {
      statusCode: 200, headers: {},
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
      redirect(code, url) { this.statusCode = code; this.location = url; return this; },
      getHeaders() { return this.headers; }, on() { return this; },
    };
    await handler({ query: {
      client_id: 'attacker-controlled-front-channel-value',
      request_uri: 'urn:test:shared',
      authorization_details: JSON.stringify([{ type: 'openid_credential', credential_configuration_id: 'attacker-credential' }]),
      scope: 'attacker-scope',
    }, headers: {} }, res);
    assert.equal(res.statusCode, 302);
    const target = new URL(res.location);
    assert.equal(target.searchParams.get('state'), 'wallet-state');
    assert.ok(target.searchParams.get('code'));
    const storedSession = writes.find(([key]) => key === 'code-flow-sessions:session');
    assert.ok(storedSession);
    assert.deepEqual(JSON.parse(storedSession[2]).credentials, ['urn:eu.europa.ec.eudi:pid:1']);
    assert.equal(JSON.parse(storedSession[2]).nonce, 'par-scope-nonce');
  });

  it('uses client_metadata submitted through PAR after resolving the request', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    const par = {
      client_id: 'wallet', issuerState: 'session', state: 'wallet-state',
      redirect_uri: 'https://wallet.example/oauth/callback', response_type: 'code',
      code_challenge: 'challenge', code_challenge_method: 'S256',
      scope: 'urn:eu.europa.ec.eudi:pid:1', clientMetadata: '%',
    };
    sandbox.stub(cache.client, 'get').callsFake(async key => {
      if (key === 'par-requests:urn:test:shared') return JSON.stringify(par);
      if (key === 'code-flow-sessions:session') return JSON.stringify({ requests: {}, results: {}, isDynamic: false });
      return null;
    });
    sandbox.stub(cache.client, 'setEx').resolves();
    const log = sandbox.stub(console, 'log');
    const res = {
      statusCode: 200, headers: {},
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
      redirect(code, url) { this.statusCode = code; this.location = url; return this; },
      getHeaders() { return this.headers; }, on() { return this; },
    };
    const handler = router.stack.find(layer => layer.route?.path === '/authorize').route.stack[0].handle;
    await handler({ query: { request_uri: 'urn:test:shared' }, headers: {} }, res);
    assert.equal(res.statusCode, 302);
    assert.ok(log.calledWith('client_metadata was missing'));
  });

  it('uses the issuer session client_id_scheme for dynamic PAR authorization', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    const par = {
      client_id: 'wallet', issuerState: 'session', state: 'wallet-state',
      redirect_uri: 'openid://localhost/', response_type: 'code',
      code_challenge: 'challenge', code_challenge_method: 'S256',
      authorizationDetails: JSON.stringify([{ type: 'openid_credential', credential_configuration_id: 'urn:eu.europa.ec.eudi:pid:1' }]),
    };
    const session = { requests: {}, results: {}, isDynamic: true, client_id_scheme: 'redirect_uri' };
    sandbox.stub(cache.client, 'get').callsFake(async key => {
      if (key === 'par-requests:urn:test:shared') return JSON.stringify(par);
      if (key === 'code-flow-sessions:session') return JSON.stringify(session);
      return null;
    });
    sandbox.stub(cache.client, 'setEx').resolves();
    const res = await authorize();
    assert.equal(res.statusCode, 302);
    assert.match(res.location, /^openid4vp:\/\//);
  });

  it('returns a visible 400 for expired or missing PAR instead of an unhandled wallet deep link', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => true);
    sandbox.stub(cache.client, 'get').resolves(null);
    const res = await authorize();
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'invalid_request');
    assert.equal(res.location, undefined);
  });

  it('returns 503 when Redis cannot resolve PAR rather than hanging in its offline queue', async () => {
    sandbox.stub(cache.client, 'isReady').get(() => false);
    const res = await authorize();
    assert.equal(res.statusCode, 503);
    assert.equal(res.body.error, 'temporarily_unavailable');
  });
});
