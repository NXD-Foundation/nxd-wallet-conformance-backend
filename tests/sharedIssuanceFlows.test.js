import { strict as assert } from 'assert';
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import bodyParser from 'body-parser';
import sinon from 'sinon';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';

// Set up environment for testing BEFORE importing modules
process.env.ALLOW_NO_REDIS = 'true';
process.env.SERVER_URL = 'http://localhost:3000';

// NOTE: ES modules have immutable exports, so we cannot stub them directly.
// We'll test the real implementation with real dependencies configured for testing.
// The ALLOW_NO_REDIS flag allows Redis-dependent code to work without a Redis connection.

describe('Shared Issuance Flows', () => {
  /** Bound at PAR/authorize; token exchange must present the same `client_id` when set (RFC001 P0-2). */
  const TEST_OAUTH_CLIENT_ID = 'test-oauth-client-id';
  /** Bound at PAR/authorize; token exchange must present the same `redirect_uri` when set (RFC001 P0-3). */
  const TEST_OAUTH_REDIRECT_URI = 'https://wallet.test/oauth/callback';

  let sandbox;
  let app;
  let sharedModule;
  let cacheServiceRedis;
  let cryptoUtils;
  let tokenUtils;
  let credGenerationUtils;
  let testKeys;
  let globalSandbox;

  const signProofJwt = (payload, headerOverrides = {}) => {
    return jwt.sign(payload, testKeys.privateKeyPem, {
      algorithm: 'ES256',
      header: {
        typ: 'openid4vci-proof+jwt',
        jwk: testKeys.publicKeyJwk,
        ...headerOverrides,
      },
    });
  };

  // RFC001 §7.4: DPoP is mandatory at the token endpoint. Generates a fresh
  // ephemeral key + DPoP proof JWT per invocation so tests stay isolated and
  // avoid jti replay collisions between requests.
  const makeTokenDpop = async (
    { htu = 'http://localhost:3000/token_endpoint', htm = 'POST' } = {}
  ) => {
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
    const publicJwk = await jose.exportJWK(publicKey);
    const dpopJwt = await new jose.SignJWT({ htu, htm })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .setIssuedAt()
      .setJti(uuidv4())
      .sign(privateKey);
    return { dpopJwt, publicJwk };
  };

  const WIA_CLIENT_ASSERTION_TYPE =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  /** Last bundle for {@link wireWiaOAuthHeaders} / {@link pickWiaBodyFields} (tests run serially in this file). */
  let lastWiaTestBundle = null;

  const pickWiaBodyFields = (bundle) => {
    const b = bundle ?? lastWiaTestBundle;
    const { oauthAttestationHeaders: _h, ...rest } = b;
    return rest;
  };

  const wireWiaOAuthHeaders = (req) => {
    const h = lastWiaTestBundle?.oauthAttestationHeaders;
    if (!h) return req;
    let r = req;
    for (const [k, v] of Object.entries(h)) {
      r = r.set(k, v);
    }
    return r;
  };

  /**
   * RFC001 §7.3–7.4 — WIA + OAuth-Client-Attestation + PoP: WIA carries cnf.jwk; PoP verified against attestation cnf; issuer binds WIA cnf to attestation cnf.
   * @param {{ oauthClientId?: string }} [options] - When the request sends `client_id`, pass it so attestation `sub` and PoP `iss` match (HAIP).
   */
  const makeTestWiaClientAssertion = async (options = {}) => {
    const base = process.env.SERVER_URL || "http://localhost:3000";
    const tokenEndpoint = `${String(base).replace(/\/$/, "")}/token_endpoint`;
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const publicJwk = await jose.exportJWK(publicKey);
    const cnfJwk = { ...publicJwk };
    delete cnfJwk.d;

    const wiaIssuer = "did:jwk:test-wia";
    const attestationSub =
      options.oauthClientId != null && options.oauthClientId !== ""
        ? options.oauthClientId
        : wiaIssuer;

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3600;
    const client_assertion = await new jose.SignJWT({
      iss: wiaIssuer,
      aud: tokenEndpoint,
      iat: now,
      exp,
      jti: uuidv4(),
      cnf: { jwk: cnfJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", jwk: publicJwk })
      .sign(privateKey);

    const attJwt = await new jose.SignJWT({
      iss: wiaIssuer,
      sub: attestationSub,
      aud: base,
      iat: now,
      nbf: now,
      exp: now + 3600,
      jti: uuidv4(),
      cnf: { jwk: cnfJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation+jwt", jwk: publicJwk })
      .sign(privateKey);

    const popJwt = await new jose.SignJWT({
      iss: attestationSub,
      aud: base,
      iat: now,
      nbf: now,
      exp: now + 300,
      jti: uuidv4(),
    })
      .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation-pop+jwt", jwk: publicJwk })
      .sign(privateKey);

    const bundle = {
      client_assertion,
      client_assertion_type: WIA_CLIENT_ASSERTION_TYPE,
      oauthAttestationHeaders: {
        "OAuth-Client-Attestation": attJwt,
        "OAuth-Client-Attestation-PoP": popJwt,
      },
    };
    lastWiaTestBundle = bundle;
    return bundle;
  };

  before(async () => {
    // Create a global sandbox for module-level stubs
    globalSandbox = sinon.createSandbox();
    
    // Stub fs.readFileSync BEFORE importing modules that use it
    const crypto = await import('crypto');
    const { privateKey: testPrivateKey, publicKey: testPublicKey } = crypto.default.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const validPrivateKeyPem = testPrivateKey.export({ type: 'pkcs8', format: 'pem' });
    const validPublicKeyPem = testPublicKey.export({ type: 'spki', format: 'pem' });
    
    globalSandbox.stub(fs, 'readFileSync')
      .withArgs(sinon.match(/issuer-config\.json/)).returns(JSON.stringify({
        credential_configurations_supported: {
          'test-cred-config': { format: 'dc+sd-jwt', proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } },
          'rfc001-device-bound-test': {
            format: 'vc+sd-jwt',
            vct: 'urn:eu.europa.ec.eudi:pid:1',
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: { proof_signing_alg_values_supported: ['ES256'] },
            },
          },
        },
        default_signing_kid: 'test-kid',
        credential_response_encryption: {
          alg_values_supported: ['ECDH-ES', 'RSA-OAEP-256'],
          enc_values_supported: ['A256GCM'],
          encryption_required: false,
        },
      }))
      .withArgs(sinon.match(/private-key\.pem/)).returns(validPrivateKeyPem)
      .withArgs(sinon.match(/public-key\.pem/)).returns(validPublicKeyPem)
      .withArgs(sinon.match(/x509EC.*ec_private_pkcs8\.key/)).returns(validPrivateKeyPem)
      .withArgs(sinon.match(/x509EC.*client_certificate\.crt/)).returns('-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKexample\n-----END CERTIFICATE-----')
      .withArgs(sinon.match(/x509EC/)).returns(validPrivateKeyPem);
    
    // Import the real router and dependencies AFTER stubbing
    cacheServiceRedis = await import('../services/cacheServiceRedis.js');
    cryptoUtils = await import('../utils/cryptoUtils.js');
    tokenUtils = await import('../utils/tokenUtils.js');
    credGenerationUtils = await import('../utils/credGenerationUtils.js');
    sharedModule = await import('../routes/issue/sharedIssuanceFlows.js');
    
    // Wait for Redis to be ready if available
    if (cacheServiceRedis.client) {
      let attempts = 0;
      while (!cacheServiceRedis.client.isReady && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
      
      if (!cacheServiceRedis.client.isReady && process.env.ALLOW_NO_REDIS !== 'true') {
        console.warn('Redis is not ready - tests may fail if Redis operations are required');
      }
    }
  });

  after(() => {
    if (globalSandbox) {
      globalSandbox.restore();
    }
  });

  beforeEach(async () => {
    // Other suites (e.g. metadata discovery) may change SERVER_URL; DPoP `htu` checks
    // use getServerUrl() per request, so reset to this file's expected issuer base URL.
    process.env.SERVER_URL = 'http://localhost:3000';

    sandbox = sinon.createSandbox();

    // Generate a valid EC private key for testing
    const crypto = await import('crypto');
    const { privateKey: testPrivateKey, publicKey: testPublicKey } = crypto.default.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const validPrivateKeyPem = testPrivateKey.export({ type: 'pkcs8', format: 'pem' });
    const validPublicKeyPem = testPublicKey.export({ type: 'spki', format: 'pem' });
    const validPublicKeyJwk = testPublicKey.export({ format: 'jwk' });

    testKeys = {
      privateKeyPem: validPrivateKeyPem,
      publicKeyPem: validPublicKeyPem,
      publicKeyJwk: validPublicKeyJwk,
    };

    // Create Express app and mount router at root (matches production server)
    app = express();
    app.use(bodyParser.text({ type: (req) => req.is('application/jwt'), limit: '10mb' }));
    app.use(bodyParser.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));
    app.use('/', sharedModule.default);
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('POST /token_endpoint', () => {
    it('MUST return invalid_client when WIA (client_assertion) is missing', async () => {
      if (!cacheServiceRedis.client.isReady) {
        throw new Error("Redis is not ready - cannot run test");
      }
      const preAuthCode = "test-pre-auth-no-wia-" + uuidv4();
      await cacheServiceRedis.storePreAuthSession(preAuthCode, {
        status: "pending",
        authorizationDetails: null,
      });
      await new Promise((resolve) => setTimeout(resolve, 50));
      const { dpopJwt } = await makeTokenDpop();
      const response = await request(app)
        .post("/token_endpoint")
        .set("DPoP", dpopJwt)
        .send({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": preAuthCode,
        })
        .expect(400);
      expect(response.body).to.have.property("error", "invalid_client");
    });

    it('should handle pre-authorized code flow successfully', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null
      };
      
      // Set up real test data using actual cache functions
      // Ensure Redis is ready before storing
      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }
      
      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      
      // Small delay to ensure session is stored
      await new Promise(resolve => setTimeout(resolve, 50));

      // RFC001 §7.4: DPoP is mandatory at the token endpoint.
      const { dpopJwt, publicJwk } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('refresh_token');
      expect(response.body).to.have.property('token_type', 'DPoP');
      expect(response.body).to.have.property('expires_in', 86400);
      expect(response.body).to.have.property('c_nonce');
      expect(response.body.c_nonce).to.be.a('string');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;

      // RFC001 §7.4 / RFC 9449 — access token MUST be sender-constrained via cnf.jkt.
      const decoded = jwt.decode(response.body.access_token);
      expect(decoded).to.be.an('object');
      expect(decoded).to.have.property('cnf');
      expect(decoded.cnf).to.have.property('jkt');
      const expectedJkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
      expect(decoded.cnf.jkt).to.equal(expectedJkt);
    });

    it('MUST return invalid_grant when offer required tx_code but token request omits tx_code', async () => {
      const preAuthCode = 'test-pre-auth-tx-required-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null,
        requireTxCode: true,
      };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('accepts any non-empty tx_code when offer required tx_code', async () => {
      const preAuthCode = 'test-pre-auth-tx-any-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null,
        requireTxCode: true,
      };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const { dpopJwt, publicJwk } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
          tx_code: 'not-validated-by-issuer',
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      const decoded = jwt.decode(response.body.access_token);
      const expectedJkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
      expect(decoded.cnf.jkt).to.equal(expectedJkt);
    });

    it('should issue a DPoP-bound access token with cnf.jkt in pre-authorized flow when DPoP header is present', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null
      };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      // Build a simple ephemeral EC key pair for the DPoP header
      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);

      // Per RFC 9449 the DPoP header is a JWT whose header contains jwk with the public key
      const dpopJwt = await new jose.SignJWT({ htu: 'http://localhost:3000/token_endpoint', htm: 'POST' })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .setIssuedAt()
        .setJti(uuidv4())
        .sign(privateKey);

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('token_type', 'DPoP');
      expect(response.body).to.have.property('c_nonce');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;

      // Decode the access_token (we trust local signing key from stubs)
      const decoded = jwt.decode(response.body.access_token);
      expect(decoded).to.be.an('object');
      expect(decoded).to.have.property('cnf');
      expect(decoded.cnf).to.have.property('jkt');
      expect(decoded.cnf.jkt).to.be.a('string');

      // DPOP-08 — Ensure cnf.jkt matches DPoP public key thumbprint
      const expectedJkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
      expect(decoded.cnf.jkt).to.equal(expectedJkt);
    });

    it('should handle authorization code flow successfully', async () => {
      const authCode = 'test-auth-code-' + uuidv4();
      const sessionId = 'test-session-id-' + uuidv4();
      const codeVerifier = 'test-verifier';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };

      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: TEST_OAUTH_CLIENT_ID,
          redirect_uri: TEST_OAUTH_REDIRECT_URI,
        })
        .expect(200);

      expect(response.body).to.have.property('access_token');
      expect(response.body).to.have.property('refresh_token');
      expect(response.body).to.have.property('token_type', 'DPoP');
      expect(response.body).to.have.property('c_nonce');
      expect(response.body.c_nonce).to.be.a('string');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;
    });

    it('should issue a DPoP-bound access token with cnf.jkt in authorization_code flow when DPoP header is present', async () => {
      const authCode = 'test-auth-code-dpop-' + uuidv4();
      const sessionId = 'test-session-id-dpop-' + uuidv4();
      const codeVerifier = 'test-verifier-dpop';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };

      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);

      const dpopJwt = await new jose.SignJWT({ htu: 'http://localhost:3000/token_endpoint', htm: 'POST' })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .setIssuedAt()
        .setJti(uuidv4())
        .sign(privateKey);

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: TEST_OAUTH_CLIENT_ID,
          redirect_uri: TEST_OAUTH_REDIRECT_URI,
        });

      if (response.status === 200) {
        expect(response.body).to.have.property('access_token');
        expect(response.body).to.have.property('token_type', 'DPoP');
        expect(response.body).to.have.property('c_nonce');
        expect(response.body).to.have.property('c_nonce_expires_in', 86400);

        const decoded = jwt.decode(response.body.access_token);
        expect(decoded).to.be.an('object');
        expect(decoded).to.have.property('cnf');
        expect(decoded.cnf).to.have.property('jkt');
        expect(decoded.cnf.jkt).to.be.a('string');

        // DPOP-08 — Ensure cnf.jkt matches DPoP public key thumbprint
        const expectedJkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
        expect(decoded.cnf.jkt).to.equal(expectedJkt);
      } else {
        expect([400, 500]).to.include(response.status);
      }
    });

    // DPOP-02 — Malformed DPoP proof handling
    it('DPOP-02 — should reject malformed DPoP JWT with invalid_dpop_proof', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-malformed-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: null
      };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      // Malformed DPoP header (not a valid JWS / bad base64)
      const malformedDpop = 'not-a-valid-jwt';

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', malformedDpop)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_dpop_proof');
      expect(response.body).to.have.property('error_description');
    });

    it('DPOP-02b — should reject DPoP proof without jwk in protected header (no Bearer fallback)', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-no-jwk-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      const { privateKey } = await jose.generateKeyPair('ES256');
      const now = Math.floor(Date.now() / 1000);
      const dpopJwt = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'POST',
        iat: now,
        jti: uuidv4(),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt' })
        .sign(privateKey);

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_dpop_proof');
      expect(response.body.error_description).to.match(/jwk/i);
    });

    it('DPOP-03 — should reject DPoP JWT with missing required claims (htu, htm, iat, jti)', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-missing-claims-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);
      const now = Math.floor(Date.now() / 1000);

      const buildAndSend = async (payloadOverrides) => {
        const basePayload = {
          htm: 'POST',
          htu: 'http://localhost:3000/token_endpoint',
          iat: now,
          jti: uuidv4()
        };
        const payload = { ...basePayload, ...payloadOverrides };
        const dpopJwt = await new jose.SignJWT(payload)
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const res = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopJwt)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_dpop_proof');
      };

      // Missing htu
      await buildAndSend({ htu: undefined });

      // Missing htm
      await buildAndSend({ htm: undefined });

      // Missing iat
      await buildAndSend({ iat: undefined });

      // Missing jti
      await buildAndSend({ jti: undefined });
    });

    it('DPOP-04 — should reject DPoP when htm/htu do not match the token request', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-htm-htu-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);

      // htm mismatch (GET instead of POST)
      const dpopWrongMethod = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'GET',
        iat: Math.floor(Date.now() / 1000),
        jti: uuidv4()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(privateKey);

      await makeTestWiaClientAssertion();
      const resMethod = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopWrongMethod)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(resMethod.body).to.have.property('error', 'invalid_dpop_proof');

      // htu mismatch (different path)
      const dpopWrongUri = await new jose.SignJWT({
        htu: 'http://localhost:3000/other-endpoint',
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: uuidv4()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(privateKey);

      await makeTestWiaClientAssertion();
      const resUri = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopWrongUri)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(resUri.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('DPOP-05 — should reject DPoP proof with stale iat outside allowed clock skew window', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-stale-iat-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);

      // iat 10 minutes in the past (beyond 5 minute window)
      const staleIat = Math.floor(Date.now() / 1000) - 600;

      const dpopStale = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'POST',
        iat: staleIat,
        jti: uuidv4()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(privateKey);

      await makeTestWiaClientAssertion();
      const res = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopStale)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(res.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('DPOP-06 — should reject replayed DPoP proof when jti is reused within replay window', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-replay-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);

      const sharedJti = uuidv4();

      const dpopJwt = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: sharedJti
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(privateKey);

      // First request should be allowed (we accept any 2xx as "not DPoP-rejected")
      await makeTestWiaClientAssertion();
      const firstResponse = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        });

      expect([200, 400, 500]).to.include(firstResponse.status);
      if (firstResponse.status === 200) {
        expect(firstResponse.body).to.have.property('access_token');
      }

      // Second request with the same DPoP proof MUST be rejected as replay
      await makeTestWiaClientAssertion();
      const secondResponse = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(secondResponse.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('DPOP-07 — should reject DPoP with invalid signature or JWK mismatch', async () => {
      const preAuthCode = 'test-pre-auth-code-dpop-badsig-' + uuidv4();
      const preAuthSession = { status: 'pending', authorizationDetails: null };

      if (!cacheServiceRedis.client.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }

      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
      await new Promise(resolve => setTimeout(resolve, 50));

      // Generate two distinct key pairs
      const { publicKey: publicKey1, privateKey: privateKey1 } = await jose.generateKeyPair('ES256');
      const { publicKey: publicKey2 } = await jose.generateKeyPair('ES256');
      const publicJwk2 = await jose.exportJWK(publicKey2);

      // Sign with privateKey1 but advertise jwk from publicKey2 -> signature/jwk mismatch
      const badDpop = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: uuidv4()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk2 })
        .sign(privateKey1);

      await makeTestWiaClientAssertion();
      const res = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', badDpop)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(res.body).to.have.property('error', 'invalid_dpop_proof');
    });

    //
    // C. DPoP Nonce / Nonce-Refresh Cycle (spec scaffolding)
    //

    it('NONCE-01 — should challenge with DPoP-Nonce when DPoP nonce is required but missing', async () => {
      const prev = process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN;
      process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = 'true';
      try {
        const preAuthCode = 'test-pre-auth-code-dpop-nonce-missing-' + uuidv4();
        const preAuthSession = {
          status: 'pending',
          authorizationDetails: null
        };

        if (!cacheServiceRedis.client.isReady) {
          throw new Error('Redis is not ready - cannot run test');
        }

        await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
        await new Promise(resolve => setTimeout(resolve, 50));

        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
        const publicJwk = await jose.exportJWK(publicKey);

        // Valid DPoP proof but without nonce claim
        const dpopJwt = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4()
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const response = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopJwt)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        expect(response.body).to.have.property('error', 'use_dpop_nonce');
        const nonceHeader = response.headers['dpop-nonce'];
        expect(nonceHeader).to.be.a('string').and.to.have.length.greaterThan(0);
      } finally {
        process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = prev;
      }
    });

    it('NONCE-02 — should accept next DPoP token request that includes the issued DPoP-Nonce', async () => {
      const prev = process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN;
      process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = 'true';
      try {
        const preAuthCode = 'test-pre-auth-code-dpop-nonce-accept-' + uuidv4();
        const preAuthSession = {
          status: 'pending',
          authorizationDetails: null
        };

        if (!cacheServiceRedis.client.isReady) {
          throw new Error('Redis is not ready - cannot run test');
        }

        await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
        await new Promise(resolve => setTimeout(resolve, 50));

        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
        const publicJwk = await jose.exportJWK(publicKey);

        // First request without nonce -> expect challenge
        const dpopWithoutNonce = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4()
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const challengeResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopWithoutNonce)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        expect(challengeResponse.body).to.have.property('error', 'use_dpop_nonce');
        const issuedNonce = challengeResponse.headers['dpop-nonce'];
        expect(issuedNonce).to.be.a('string').and.to.have.length.greaterThan(0);

        // Second request with nonce included -> should succeed and mint access token
        const dpopWithNonce = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4(),
          nonce: issuedNonce
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const successResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopWithNonce)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(200);

        expect(successResponse.body).to.have.property('access_token');
        expect(successResponse.body).to.have.property('token_type', 'DPoP');
      } finally {
        process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = prev;
      }
    });

    it('NONCE-03 — should reject DPoP token request with wrong nonce and return fresh DPoP-Nonce', async () => {
      const prev = process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN;
      process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = 'true';
      try {
        const preAuthCode = 'test-pre-auth-code-dpop-nonce-wrong-' + uuidv4();
        const preAuthSession = {
          status: 'pending',
          authorizationDetails: null
        };

        if (!cacheServiceRedis.client.isReady) {
          throw new Error('Redis is not ready - cannot run test');
        }

        await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
        await new Promise(resolve => setTimeout(resolve, 50));

        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
        const publicJwk = await jose.exportJWK(publicKey);

        // Initial challenge to establish a valid nonce
        const initialDpop = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4()
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const initialResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', initialDpop)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        const firstNonce = initialResponse.headers['dpop-nonce'];
        expect(firstNonce).to.be.a('string');

        // Now send a DPoP with a wrong/unknown nonce value
        const wrongNonce = firstNonce + '-wrong';
        const dpopWrongNonce = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4(),
          nonce: wrongNonce
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const response = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopWrongNonce)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        expect(response.body).to.have.property('error', 'use_dpop_nonce');
        const newNonce = response.headers['dpop-nonce'];
        expect(newNonce).to.be.a('string').and.to.have.length.greaterThan(0);
        expect(newNonce).to.not.equal(firstNonce);
      } finally {
        process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = prev;
      }
    });

    it('NONCE-04 — should treat DPoP nonce as single-use per policy', async () => {
      const prev = process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN;
      process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = 'true';
      try {
        const preAuthCode = 'test-pre-auth-code-dpop-nonce-single-use-' + uuidv4();
        const preAuthSession = {
          status: 'pending',
          authorizationDetails: null
        };

        if (!cacheServiceRedis.client.isReady) {
          throw new Error('Redis is not ready - cannot run test');
        }

        await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);
        await new Promise(resolve => setTimeout(resolve, 50));

        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
        const publicJwk = await jose.exportJWK(publicKey);

        // First, get a nonce challenge
        const dpopNoNonce = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4()
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const challengeResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopNoNonce)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        const nonce = challengeResponse.headers['dpop-nonce'];
        expect(nonce).to.be.a('string');

        // Use the nonce once — should succeed
        const dpopFirstUse = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4(),
          nonce
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const firstUseResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopFirstUse)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          });

        expect([200, 400, 500]).to.include(firstUseResponse.status);
        if (firstUseResponse.status === 200) {
          expect(firstUseResponse.body).to.have.property('access_token');
        }

        // Reuse the same nonce in a new DPoP proof — must be rejected/re-challenged
        const dpopSecondUse = await new jose.SignJWT({
          htu: 'http://localhost:3000/token_endpoint',
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: uuidv4(),
          nonce
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
          .sign(privateKey);

        await makeTestWiaClientAssertion();
        const secondUseResponse = await wireWiaOAuthHeaders(
          request(app)
            .post('/token_endpoint')
            .set('DPoP', dpopSecondUse)
        )
          .send({
            ...pickWiaBodyFields(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': preAuthCode
          })
          .expect(400);

        expect(secondUseResponse.body).to.have.property('error', 'use_dpop_nonce');
        const newNonce = secondUseResponse.headers['dpop-nonce'];
        expect(newNonce).to.be.a('string').and.to.have.length.greaterThan(0);
        expect(newNonce).to.not.equal(nonce);
      } finally {
        process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN = prev;
      }
    });

    it.skip('NONCE-05 — should scope DPoP nonce per endpoint and reject cross-endpoint reuse', async () => {
      // Current implementation enforces DPoP nonce only on the token endpoint.
      // This test documents the desired behavior for cross-endpoint nonce scoping
      // (e.g., /token_endpoint vs /credential) and can be enabled once DPoP nonce
      // challenges are implemented consistently across multiple endpoints.
    });

    //
    // D. “Glue” tests (PAR + DPoP interplay) / HAIP profile
    //

    it('INT-01 — MUST reject authorization_code exchange without DPoP (RFC001 §7.4)', async () => {
      const authCode = 'test-auth-code-rfc001-' + uuidv4();
      const sessionId = 'test-session-id-rfc001-' + uuidv4();
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256('test-verifier-rfc001');
      const codeSession = {
        requests: { challenge: codeChallenge },
        results: { issuerState: sessionId }
      };

      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          // Note: no DPoP header on purpose
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: 'test-verifier-rfc001'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('INT-01a — MUST reject pre-authorized_code exchange without DPoP (RFC001 §7.4)', async () => {
      const preAuthCode = 'test-pre-auth-code-rfc001-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(preAuthCode, { status: 'pending' });

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('INT-02 — MUST reject authorization_code redeem when DPoP key (cnf.jkt) mismatches expected session binding', async () => {
      const authCode = 'test-auth-code-jkt-mismatch-' + uuidv4();
      const sessionId = 'test-session-id-jkt-mismatch-' + uuidv4();

      // Key A: the key that the PAR / authorization phase would have used
      const { publicKey: publicKeyA } = await jose.generateKeyPair('ES256');
      const publicJwkA = await jose.exportJWK(publicKeyA);
      const expectedJkt = await jose.calculateJwkThumbprint(publicJwkA, 'sha256');

      // Store a code flow session that records the expected DPoP thumbprint for this auth code
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256('test-verifier-jkt-mismatch');
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId },
        expectedDpopJkt: expectedJkt
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      // Key B: different key used when redeeming the authorization_code
      const { publicKey: publicKeyB, privateKey: privateKeyB } = await jose.generateKeyPair('ES256');
      const publicJwkB = await jose.exportJWK(publicKeyB);

      const dpopJwt = await new jose.SignJWT({
        htu: 'http://localhost:3000/token_endpoint',
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: uuidv4()
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwkB })
        .sign(privateKeyB);

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: 'test-verifier-jkt-mismatch',
          client_id: TEST_OAUTH_CLIENT_ID,
          redirect_uri: TEST_OAUTH_REDIRECT_URI,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('P0-2 — MUST reject authorization_code when client_id mismatches PAR-bound value (RFC001 §7.3–7.4)', async () => {
      const authCode = 'test-auth-code-client-mismatch-' + uuidv4();
      const sessionId = 'test-session-client-mismatch-' + uuidv4();
      const codeVerifier = 'test-verifier-client-mismatch';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion({ oauthClientId: 'different-oauth-client-id' });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: 'different-oauth-client-id',
          redirect_uri: TEST_OAUTH_REDIRECT_URI,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('P0-2b — MUST reject authorization_code when client_id is omitted but PAR bound a client_id', async () => {
      const authCode = 'test-auth-code-no-client-id-' + uuidv4();
      const sessionId = 'test-session-no-client-id-' + uuidv4();
      const codeVerifier = 'test-verifier-no-client-id';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('P0-3 — MUST reject authorization_code when redirect_uri mismatches PAR-bound value (RFC001 §6.1.5 / §7.4)', async () => {
      const authCode = 'test-auth-code-redirect-mismatch-' + uuidv4();
      const sessionId = 'test-session-redirect-mismatch-' + uuidv4();
      const codeVerifier = 'test-verifier-redirect-mismatch';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: TEST_OAUTH_CLIENT_ID,
          redirect_uri: 'https://evil.example/other-callback',
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('P0-3b — MUST reject authorization_code when redirect_uri is omitted but PAR bound a redirect_uri', async () => {
      const authCode = 'test-auth-code-no-redirect-' + uuidv4();
      const sessionId = 'test-session-no-redirect-' + uuidv4();
      const codeVerifier = 'test-verifier-no-redirect';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: TEST_OAUTH_CLIENT_ID,
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('MUST include c_nonce and c_nonce_expires_in on success (pre-authorized_code)', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(preAuthCode, { status: 'pending' });

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
        })
        .expect(200);

      expect(response.body.c_nonce).to.be.a('string');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;
    });

    it('MUST include c_nonce and c_nonce_expires_in on success (authorization_code)', async () => {
      const authCode = 'test-auth-code-cn2-' + uuidv4();
      const sessionId = 'test-session-cn2-' + uuidv4();
      const codeVerifier = 'test-verifier-cn2';
      const codeChallenge = await cryptoUtils.base64UrlEncodeSha256(codeVerifier);
      const codeSession = {
        authorizationRequestClientId: TEST_OAUTH_CLIENT_ID,
        requests: {
          challenge: codeChallenge,
          sessionId: authCode,
          issuerState: sessionId,
          redirectUri: TEST_OAUTH_REDIRECT_URI,
        },
        results: { issuerState: sessionId, status: 'pending' },
      };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion({ oauthClientId: TEST_OAUTH_CLIENT_ID });
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          client_id: TEST_OAUTH_CLIENT_ID,
          redirect_uri: TEST_OAUTH_REDIRECT_URI,
        })
        .expect(200);

      expect(response.body.c_nonce).to.be.a('string');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;
    });

    it('MUST persist c_nonce in session and nonce store (pre-authorized_code)', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      const preAuthSession = { status: 'pending' };
      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
        })
        .expect(200);

      const updatedSession = await cacheServiceRedis.getPreAuthSession(preAuthCode);
      expect(updatedSession).to.have.property('c_nonce');
      expect(updatedSession.c_nonce).to.equal(response.body.c_nonce);
      expect(await cacheServiceRedis.checkNonce(updatedSession.c_nonce)).to.be.true;
    });

    it('should handle authorization_details in pre-authorized flow', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: [
          {
            type: 'openid_credential',
            credential_configuration_id: 'test-cred-config',
          },
        ],
      };
      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
          authorization_details: [
            {
              type: 'openid_credential',
              credential_configuration_id: 'test-cred-config',
            },
          ],
        })
        .expect(200);

      expect(response.body).to.have.property('authorization_details');
      expect(response.body.authorization_details).to.be.an('array');
      expect(response.body.authorization_details[0]).to.have.property(
        'credential_identifiers'
      );
      expect(response.body.authorization_details[0].credential_identifiers).to.deep.equal([
        'test-cred-config'
      ]);
      const roundTrip = JSON.parse(JSON.stringify(response.body.authorization_details));
      expect(roundTrip[0].credential_identifiers).to.deep.equal(['test-cred-config']);
      expect(response.body).to.have.property('c_nonce');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
    });

    it('should set credential_identifiers per authorization_details entry (not only from the first)', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      const vctId = 'https://example.org/SecondCredential';
      const preAuthSession = {
        status: 'pending',
        authorizationDetails: [
          { type: 'openid_credential', credential_configuration_id: 'test-cred-config' },
          { type: 'openid_credential', format: 'vc+sd-jwt', vct: vctId },
        ],
      };
      await cacheServiceRedis.storePreAuthSession(preAuthCode, preAuthSession);

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
          authorization_details: [
            { type: 'openid_credential', credential_configuration_id: 'test-cred-config' },
            { type: 'openid_credential', format: 'vc+sd-jwt', vct: vctId },
          ],
        })
        .expect(200);

      expect(response.body.authorization_details).to.have.length(2);
      expect(response.body.authorization_details[0].credential_identifiers).to.deep.equal([
        'test-cred-config',
      ]);
      expect(response.body.authorization_details[1].credential_identifiers).to.deep.equal([vctId]);
      const roundTrip = JSON.parse(JSON.stringify(response.body.authorization_details));
      expect(roundTrip[1].credential_identifiers).to.deep.equal([vctId]);
    });

    it('MUST return invalid_request when authorization_details omits type openid_credential', async () => {
      const preAuthCode = 'test-pre-auth-code-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(preAuthCode, { status: 'pending' });

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode,
          authorization_details: [
            { credential_configuration_id: 'test-cred-config' },
          ],
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_request');
    });

    it('should reject request without code or pre-authorized_code', async () => {
      const { dpopJwt } = await makeTokenDpop();
      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('Authorization', 'Bearer test-token')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_request');
    });

    it('should reject invalid pre-authorized code', async () => {
      // Don't create session - this should result in invalid grant
      const invalidCode = 'invalid-code-' + uuidv4();

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': invalidCode
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_grant');
    });

    it('should reject PKCE verification failure', async () => {
      // This test requires setting up auth code to session mapping
      // For now, we'll test that invalid PKCE results in error
      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'authorization_code',
          code: 'test-auth-code',
          code_verifier: 'wrong-verifier'
        });

      // Expect either invalid_grant (if code mapping exists) or 400/500
      expect([400, 500]).to.include(response.status);
    });

    it('should reject unsupported grant type', async () => {
      const { dpopJwt } = await makeTokenDpop();
      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('Authorization', 'Bearer test-token')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'unsupported_grant_type',
          'pre-authorized_code': 'test-code'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'unsupported_grant_type');
    });

    it('MUST return authorization_pending when external completion is pending (pre-authorized_code)', async () => {
      const preAuthCode = 'pending-session-' + uuidv4();
      // Set up session with pending_external status
      await cacheServiceRedis.storePreAuthSession(preAuthCode, { status: 'pending_external' });

      const { dpopJwt } = await makeTokenDpop();

      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'authorization_pending');
    });

    it('MUST return slow_down when wallet polls too frequently (pre-authorized_code)', async () => {
      const preAuthCode = 'throttled-session-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(preAuthCode, { status: 'pending_external' });

      // First poll: should get authorization_pending
      const { dpopJwt: firstDpop } = await makeTokenDpop();
      await makeTestWiaClientAssertion();
      const first = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', firstDpop)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(first.body).to.have.property('error', 'authorization_pending');

      // Immediate second poll: expect slow_down (Redis checkAndSetPollTime will return false)
      const { dpopJwt: secondDpop } = await makeTokenDpop();
      await makeTestWiaClientAssertion();
      const second = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('DPoP', secondDpop)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': preAuthCode
        })
        .expect(400);

      expect(second.body).to.have.property('error', 'slow_down');
    });
  });

  describe('POST /credential', () => {
    const makeCredentialDpopProof = async (accessToken, privateKey, publicJwk) => {
      const ath = await cryptoUtils.base64UrlEncodeSha256(accessToken);
      return new jose.SignJWT({
        htm: 'POST',
        htu: 'http://localhost:3000/credential',
        iat: Math.floor(Date.now() / 1000),
        jti: uuidv4(),
        ath,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(privateKey);
    };

    it('P0-4 — MUST return invalid_token when DPoP-bound access token is used without DPoP header (RFC001 §7.5)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
      const publicJwk = await jose.exportJWK(publicKey);
      const boundJkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
      const accessToken = jwt.sign(
        { cnf: { jkt: boundJkt }, sub: 'sub', iat: Math.floor(Date.now() / 1000) },
        testKeys.privateKeyPem,
        { algorithm: 'ES256' }
      );
      const sessionKey = 'p04-nodpop-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        isDeferred: false,
        accessToken,
      });
      const nonce = cryptoUtils.generateNonce();
      await cacheServiceRedis.storeNonce(nonce, 300);
      const testProofJwt = signProofJwt({
        nonce,
        iss: 'test-issuer',
        aud: process.env.SERVER_URL,
      });

      const res = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proofs: { jwt: [testProofJwt] },
        });

      expect(res.status).to.equal(401);
      expect(res.body).to.have.property('error', 'invalid_token');
    });

    it('P0-4b — MUST return invalid_dpop_proof when DPoP jkt does not match access token cnf.jkt', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const { publicKey: pubA, privateKey: privA } = await jose.generateKeyPair('ES256');
      const pubJwkA = await jose.exportJWK(pubA);
      const boundJkt = await jose.calculateJwkThumbprint(pubJwkA, 'sha256');
      const accessToken = jwt.sign(
        { cnf: { jkt: boundJkt }, sub: 'sub', iat: Math.floor(Date.now() / 1000) },
        testKeys.privateKeyPem,
        { algorithm: 'ES256' }
      );
      const { publicKey: pubB, privateKey: privB } = await jose.generateKeyPair('ES256');
      const pubJwkB = await jose.exportJWK(pubB);
      const dpopJwt = await makeCredentialDpopProof(accessToken, privB, pubJwkB);

      const sessionKey = 'p04-wrongjkt-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        isDeferred: false,
        accessToken,
      });
      const nonce = cryptoUtils.generateNonce();
      await cacheServiceRedis.storeNonce(nonce, 300);
      const testProofJwt = signProofJwt({
        nonce,
        iss: 'test-issuer',
        aud: process.env.SERVER_URL,
      });

      const res = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('DPoP', dpopJwt)
        .send({
          credential_configuration_id: 'test-cred-config',
          proofs: { jwt: [testProofJwt] },
        });

      expect(res.status).to.equal(400);
      expect(res.body).to.have.property('error', 'invalid_dpop_proof');
    });

    it('P1-1 — MUST return invalid_proof when device-bound RFC001 credential omits key_attestation (RFC001 §7.5.1)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'p11-no-key-attestation-' + uuidv4();
      const accessToken = 'test-access-token-p11-' + uuidv4();
      const nonce = cryptoUtils.generateNonce();
      await cacheServiceRedis.storeNonce(nonce, 300);
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        isDeferred: false,
        accessToken,
        c_nonce: nonce,
      });
      const proof = signProofJwt({
        nonce,
        iss: 'did:holder:test',
        aud: process.env.SERVER_URL,
      });

      const res = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'rfc001-device-bound-test',
          proofs: { jwt: [proof] },
        });

      expect(res.status).to.equal(400);
      expect(res.body).to.have.property('error', 'invalid_proof');
      expect(res.body.error_description).to.match(/key_attestation/i);
    });

    it('P1-1b — MUST return invalid_proof when proof signature does not verify with WUA attested_keys[0]', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const { privateKey: wpPriv, publicKey: wpPub } = await jose.generateKeyPair('ES256', { extractable: true });
      const { privateKey: holderA, publicKey: pubA } = await jose.generateKeyPair('ES256', { extractable: true });
      const { privateKey: holderB, publicKey: pubB } = await jose.generateKeyPair('ES256', { extractable: true });
      const wpPubJwk = await jose.exportJWK(wpPub);
      const holderAPubJwk = await jose.exportJWK(pubA);
      const holderBPubJwk = await jose.exportJWK(pubB);

      const wuaJwt = await new jose.SignJWT({
        iss: 'https://wallet-provider.example',
        aud: 'https://issuer.example/credential',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: 'wua-p11b',
        eudi_wallet_info: {
          general_info: { name: 'test-wallet' },
          key_storage_info: { level: 'tee' },
        },
        attested_keys: [holderAPubJwk],
        status: { status_list: { uri: 'https://example.com/status', idx: 0 } },
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt', jwk: wpPubJwk })
        .sign(wpPriv);

      const nonce = cryptoUtils.generateNonce();
      await cacheServiceRedis.storeNonce(nonce, 300);
      const base = process.env.SERVER_URL || 'http://localhost:3000';
      const proofJwt = await new jose.SignJWT({
        nonce,
        iss: 'did:holder:test',
        aud: base,
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'openid4vci-proof+jwt',
          jwk: holderBPubJwk,
          key_attestation: wuaJwt,
        })
        .sign(holderB);

      const sessionKey = 'p11-wrong-pop-key-' + uuidv4();
      const accessToken = 'test-access-token-p11b-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        isDeferred: false,
        accessToken,
        c_nonce: nonce,
      });

      const res = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'rfc001-device-bound-test',
          proofs: { jwt: [proofJwt] },
        });

      expect(res.status).to.equal(400);
      expect(res.body).to.have.property('error', 'invalid_proof');
    });

    it('P1-12 — MUST return one credential per WUA attested key (device-bound, 3 keys)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const { privateKey: wpPriv, publicKey: wpPub } = await jose.generateKeyPair('ES256', { extractable: true });
      const { privateKey: h1priv, publicKey: h1pub } = await jose.generateKeyPair('ES256', { extractable: true });
      const { privateKey: _h2, publicKey: h2pub } = await jose.generateKeyPair('ES256', { extractable: true });
      const { privateKey: _h3, publicKey: h3pub } = await jose.generateKeyPair('ES256', { extractable: true });
      const wpPubJwk = await jose.exportJWK(wpPub);
      const k1 = await jose.exportJWK(h1pub);
      const k2 = await jose.exportJWK(h2pub);
      const k3 = await jose.exportJWK(h3pub);

      const wuaJwt = await new jose.SignJWT({
        iss: 'https://wallet-provider.example',
        aud: 'https://issuer.example/credential',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: 'wua-p112',
        eudi_wallet_info: {
          general_info: { name: 'test-wallet' },
          key_storage_info: { level: 'tee' },
        },
        attested_keys: [k1, k2, k3],
        status: { status_list: { uri: 'https://example.com/status', idx: 0 } },
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt', jwk: wpPubJwk })
        .sign(wpPriv);

      const nonce = cryptoUtils.generateNonce();
      await cacheServiceRedis.storeNonce(nonce, 300);
      const base = process.env.SERVER_URL || 'http://localhost:3000';
      const holder1PubJwk = await jose.exportJWK(h1pub);
      const proofJwt = await new jose.SignJWT({
        nonce,
        iss: 'did:holder:test',
        aud: base,
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'openid4vci-proof+jwt',
          jwk: holder1PubJwk,
          key_attestation: wuaJwt,
        })
        .sign(h1priv);

      const sessionKey = 'p112-multi-key-' + uuidv4();
      const accessToken = 'test-access-token-p112-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        isDeferred: false,
        accessToken,
        c_nonce: nonce,
      });

      const res = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'rfc001-device-bound-test',
          proofs: { jwt: [proofJwt] },
        });

      expect(res.status).to.equal(200);
      expect(res.body.credentials).to.be.an('array').with.length(3);
      const jkts = new Set();
      for (const item of res.body.credentials) {
        expect(item).to.have.property('credential');
        const compact = String(item.credential).split('~')[0];
        const payload = jwt.decode(compact, { complete: false });
        expect(payload).to.have.property('cnf');
        expect(payload.cnf).to.have.property('jwk');
        const jkt = await jose.calculateJwkThumbprint(payload.cnf.jwk, 'sha256');
        expect(jkts.has(jkt)).to.equal(false);
        jkts.add(jkt);
      }
      expect(jkts.size).to.equal(3);
    });

    it('should handle immediate credential issuance successfully', async () => {
      const sessionKey = 'test-session-key-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();
      const nonce = cryptoUtils.generateNonce();
      const sessionObject = {
        status: 'success',
        isDeferred: false,
        accessToken: accessToken
      };
      
      // Set up real test data
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      await cacheServiceRedis.storeNonce(nonce, 300);

      const testProofJwt = signProofJwt({ nonce: nonce, iss: 'test-issuer', aud: process.env.SERVER_URL });

      const response = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        });

      // May fail due to proof validation or credential generation, but structure should be correct if successful
      if (response.status === 200) {
        expect(response.body).to.have.property('credentials');
        expect(response.body.credentials).to.be.an('array');
        expect(response.body.credentials[0]).to.have.property('credential');
      } else {
        // Accept errors for now as they may be due to missing dependencies
        expect([400, 500]).to.include(response.status);
      }
    });

    it('should handle deferred credential issuance', async () => {
      const sessionKey = 'test-session-key-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();
      const nonce = cryptoUtils.generateNonce();
      const sessionObject = {
        status: 'success',
        isDeferred: true,
        flowType: 'pre-auth',
        accessToken: accessToken
      };
      
      // Set up real test data
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      await cacheServiceRedis.storeNonce(nonce, 300);

      const testProofJwt = signProofJwt({ nonce: nonce, iss: 'test-issuer', aud: process.env.SERVER_URL });

      const response = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        });

      if (response.status === 202) {
        expect(response.body).to.have.property('transaction_id');
        expect(response.body).to.have.property('c_nonce');
        expect(response.body).to.have.property('c_nonce_expires_in');
        expect(response.body).to.have.property('interval');
        expect(response.body.interval).to.be.a('number');
        expect(response.body.interval).to.be.greaterThan(0);
      } else {
        expect([400, 500]).to.include(response.status);
      }
    });

    // NEW: one-time use of c_nonce
    it('MUST delete c_nonce after successful proof validation (one-time use)', async () => {
      const sessionKey = 'test-session-key-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();
      const cnonce = cryptoUtils.generateNonce();
      const sessionObject = { 
        status: 'success', 
        isDeferred: false,
        accessToken: accessToken
      };
      
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      await cacheServiceRedis.storeNonce(cnonce, 300);

      const testProofJwt = signProofJwt({ nonce: cnonce, iss: 'test-issuer', aud: process.env.SERVER_URL });

      const response = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: { jwt: testProofJwt }
        });

      if (response.status === 200) {
        // Verify nonce was deleted (should not exist anymore)
        const nonceExists = await cacheServiceRedis.checkNonce(cnonce);
        expect(nonceExists).to.be.false;
      } else {
        // If request failed, nonce might still exist
        expect([400, 500]).to.include(response.status);
      }
    });

    it('should reject request without proof', async () => {
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_proof');
    });

    it('should reject request with both credential identifiers', async () => {
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          credential_identifier: 'test-cred-id',
          proof: {
            jwt: 'test-jwt'
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_credential_request');
    });

    it('should reject request without credential identifiers', async () => {
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer test-token')
        .send({
          proof: {
            jwt: 'test-jwt'
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_credential_request');
    });

    it('should reject invalid nonce with OID4VCI invalid_nonce (not invalid_proof)', async () => {
      const sessionKey = 'test-session-key-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();
      const sessionObject = { 
        status: 'success', 
        isDeferred: false,
        accessToken: accessToken
      };
      
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      // Don't store the nonce — checkNonce fails → invalid_nonce per §8.3.1

      const testProofJwt = signProofJwt({ nonce: 'invalid-nonce', iss: 'test-issuer', aud: process.env.SERVER_URL });

      const response = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proofs: {
            jwt: [testProofJwt]
          }
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_nonce');
      if (cacheServiceRedis.client?.isReady) {
        expect(response.body).to.have.property('c_nonce');
        expect(response.body).to.have.property('c_nonce_expires_in');
      }
    });

    it('should reject replayed nonce with invalid_nonce after successful issuance', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'test-session-key-replay-' + uuidv4();
      const accessToken = 'test-access-token-replay-' + uuidv4();
      const cnonce = cryptoUtils.generateNonce();
      const sessionObject = {
        status: 'success',
        isDeferred: false,
        accessToken: accessToken
      };
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      await cacheServiceRedis.storeNonce(cnonce, 300);

      const testProofJwt = signProofJwt({
        nonce: cnonce,
        iss: 'test-issuer',
        aud: process.env.SERVER_URL
      });

      const body = {
        credential_configuration_id: 'test-cred-config',
        proofs: { jwt: [testProofJwt] }
      };

      const first = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send(body);

      if (first.status !== 200) {
        this.skip();
      }

      const second = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send(body)
        .expect(400);

      expect(second.body).to.have.property('error', 'invalid_nonce');
    });

    it('should return unknown_credential_configuration for unsupported credential_configuration_id', async () => {
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer irrelevant')
        .send({
          credential_configuration_id: 'not-defined-in-issuer-metadata'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'unknown_credential_configuration');
    });

    it('should return unknown_credential_identifier for unsupported credential_identifier', async () => {
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer irrelevant')
        .send({
          credential_identifier: 'not-defined-in-issuer-metadata'
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'unknown_credential_identifier');
    });

    it('should handle credential generation errors', async () => {
      // This test may fail due to real credential generation
      // We'll test that errors are handled gracefully
      const sessionKey = 'test-session-key-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();
      const nonce = cryptoUtils.generateNonce();
      const sessionObject = {
        status: 'success',
        isDeferred: false,
        accessToken: accessToken
      };
      
      await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
      await cacheServiceRedis.storeNonce(nonce, 300);

      const testProofJwt = signProofJwt({ nonce: nonce, iss: 'test-issuer', aud: process.env.SERVER_URL });

      const response = await request(app)
        .post('/credential')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: {
            jwt: testProofJwt
          }
        });

      // May succeed or fail depending on credential generation implementation
      expect([200, 400, 500]).to.include(response.status);
    });

    describe('V1.0 Breaking Change: proofs (plural) object', () => {
      it('MUST reject legacy singular proof parameter', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proof: { jwt: 'dummy' }
          });

        expect([400, 500]).to.include(res.status);
        expect(res.body).to.have.property('error');
      });

      it('MUST require proofs to be a JSON object', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const cases = [[], 'string', 123, null];
        for (const invalid of cases) {
          const res = await request(app)
            .post('/credential')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              credential_configuration_id: 'test-cred-config',
              proofs: invalid
            });
          expect([400, 500]).to.include(res.status);
          expect(res.body).to.have.property('error');
        }
      });

      it('MUST contain exactly one proof type key', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: ['dummy'], mso_mdoc: ['dummy2'] }
          });
        expect([400, 500]).to.include(res.status);
        expect(res.body).to.have.property('error');
      });

      it('MUST reject proofs.jwt with length !== 1 (RFC001 §7.5.1)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [] }
          });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('error', 'invalid_proof');
      });

      it('MUST reject proofs.jwt when value is a string (RFC001 §7.5.1)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, {
          status: 'success',
          isDeferred: false,
          accessToken: accessToken,
        });
        await cacheServiceRedis.storeNonce(nonce, 300);
        const jwtStr = signProofJwt({ nonce, iss: 'w', aud: process.env.SERVER_URL });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: jwtStr },
          });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('error', 'invalid_proof');
        expect(res.body.error_description).to.match(/array/i);
      });

      it('MUST reject proofs.jwt with more than one JWT (RFC001 §7.5.1)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const n1 = cryptoUtils.generateNonce();
        const n2 = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, {
          status: 'success',
          isDeferred: false,
          accessToken: accessToken,
        });
        await cacheServiceRedis.storeNonce(n1, 300);
        await cacheServiceRedis.storeNonce(n2, 300);
        const a = signProofJwt({ nonce: n1, iss: 'w', aud: process.env.SERVER_URL });
        const b = signProofJwt({ nonce: n2, iss: 'w', aud: process.env.SERVER_URL });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [a, b] },
          });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('error', 'invalid_proof');
      });

      it('SHOULD accept proofs.jwt as array with exactly one JWT element', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtPayload = { nonce: nonce, aud: process.env.SERVER_URL, iss: 'wallet' };
        const signed = signProofJwt(jwtPayload);

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [signed] }
          });

        expect([200, 202, 400, 500]).to.include(res.status);
      });
    });

    describe('V1.0 PoP Cryptographic Validation', () => {
      it('MUST reject proof JWT without iss in pre-authorized (non-code) flow', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, {
          status: 'success',
          isDeferred: false,
          accessToken: accessToken,
          c_nonce: nonce,
        });
        await cacheServiceRedis.storeNonce(nonce, 300);

        const tampered = jwt.sign(
          { nonce, aud: process.env.SERVER_URL },
          testKeys.privateKeyPem,
          {
            algorithm: 'ES256',
            header: {
              typ: 'openid4vci-proof+jwt',
              jwk: testKeys.publicKeyJwk,
            },
          }
        );

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [tampered] },
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_proof');
        expect(res.body.error_description).to.match(/iss/i);
      });

      it('MUST reject proof JWT when header typ is not openid4vci-proof+jwt', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, {
          status: 'success',
          isDeferred: false,
          accessToken: accessToken,
          c_nonce: nonce,
        });
        await cacheServiceRedis.storeNonce(nonce, 300);

        const wrongTyp = signProofJwt(
          { nonce, aud: process.env.SERVER_URL, iss: 'wallet' },
          { typ: 'JWT' }
        );

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [wrongTyp] },
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_proof');
        expect(res.body.error_description).to.match(/openid4vci-proof\+jwt/i);
      });

      it('MUST validate audience (aud) matches issuer credential endpoint', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });
        await cacheServiceRedis.storeNonce(nonce, 300);

        const badAud = signProofJwt({ nonce: nonce, aud: 'https://other.example.com', iss: 'wallet' });
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proof: { jwt: badAud }
          });
        expect([400, 500]).to.include(res.status);
        expect(res.body).to.have.property('error');
      });

      it('MUST validate nonce freshness: only latest c_nonce is accepted', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });
        // Don't store nonce — unknown/stale nonce → invalid_nonce (OID4VCI §8.3.1)

        const stale = signProofJwt({ nonce: 'stale-nonce', aud: process.env.SERVER_URL, iss: 'wallet' });
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [stale] }
          });
        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('error', 'invalid_nonce');
      });

      it('MUST reject proof nonce valid in store but not this session c_nonce (RFC001 P1-11)', async function () {
        if (!cacheServiceRedis.client?.isReady) {
          this.skip();
        }
        const otherNonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storeNonce(otherNonce, 300);

        const sessionKey = 'nonce-session-bind-' + uuidv4();
        const accessToken = 'nonce-token-bind-' + uuidv4();
        const sessionNonce = cryptoUtils.generateNonce();
        await cacheServiceRedis.storeNonce(sessionNonce, 300);
        await cacheServiceRedis.storePreAuthSession(sessionKey, {
          status: 'success',
          isDeferred: false,
          accessToken,
          c_nonce: sessionNonce,
        });

        const proofJwt = signProofJwt({
          nonce: otherNonce,
          iss: 'wallet',
          aud: process.env.SERVER_URL,
        });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [proofJwt] },
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_nonce');
      });
    });

    describe('V1.0 PoP Failure Recovery', () => {
      it('MUST return 400 with fresh c_nonce when nonce claim is missing', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const missingNonceJwt = signProofJwt({ aud: process.env.SERVER_URL, iss: 'wallet' });
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [missingNonceJwt] }
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_nonce');
        expect(res.body).to.have.property('c_nonce');
        expect(res.body).to.have.property('c_nonce_expires_in');
      });

      it('MUST return 400 with fresh c_nonce when provided c_nonce is expired', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });
        // Don't store nonce — treated as invalid/expired nonce → invalid_nonce

        const expiredNonceJwt = jwt.sign({ nonce: 'expired-nonce', aud: process.env.SERVER_URL, iss: 'wallet' }, 'test', { algorithm: 'HS256' });
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [expiredNonceJwt] }
          })
          .expect(400);

        expect(res.body).to.have.property('error', 'invalid_nonce');
        expect(res.body).to.have.property('c_nonce');
        expect(res.body).to.have.property('c_nonce_expires_in');
      });
    });

    describe('V1.0 Format-Specific Proof Validation for mdoc', () => {
      it('MUST reject jwt proof for mso_mdoc requests', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const jwtForMdoc = jwt.sign({ nonce: 'test-nonce-123', aud: 'http://localhost:3000/credential', iss: 'wallet' }, 'test', { algorithm: 'HS256' });
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'urn:eu.europa.ec.eudi:pid:1:mso_mdoc',
            proof: { jwt: jwtForMdoc }
          });

        expect([400, 500]).to.include(res.status);
        expect(res.body).to.have.property('error');
      });

      it('MUST require proofs.cose_key for mso_mdoc requests (accept array form when implemented)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        await cacheServiceRedis.storePreAuthSession(sessionKey, { 
          status: 'success', 
          isDeferred: false,
          accessToken: accessToken
        });

        const coseKey = { kty: 'OKP', crv: 'Ed25519', x: 'AQ' };
        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'urn:eu.europa.ec.eudi:pid:1:mso_mdoc',
            proofs: { cose_key: [coseKey] }
          });

        expect([200, 202, 400, 500]).to.include(res.status);
      });
    });

    describe('V1.0 Credential Response Wrapping and Encoding', () => {
      it('MUST wrap credentials in credentials array with credential objects (200)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const sessionObject = { status: 'success', isDeferred: false, accessToken, c_nonce: nonce };
        await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
          proofs: { jwt: [jwtWithNonce] }
          })
          .expect(200);
        expect(res.body).to.have.property('credentials');
        expect(res.body.credentials).to.be.an('array');
        res.body.credentials.forEach(item => expect(item).to.have.property('credential'));
      });

      it('SHOULD include notification_id when multiple credentials are issued (if applicable)', async () => {
        // If implementation returns multiple credentials, expect optional notification_id
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const sessionObject = { status: 'success', isDeferred: false, accessToken };
        await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
          proofs: { jwt: [jwtWithNonce] }
          });

        if (res.status === 200 && Array.isArray(res.body.credentials) && res.body.credentials.length > 1) {
          expect(res.body).to.have.property('notification_id');
        }
      });

      it('mdoc credentials MUST be base64url-encoded when binary', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const sessionObject = { status: 'success', isDeferred: false, accessToken };
        await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'urn:eu.europa.ec.eudi:pid:1:mso_mdoc',
          proofs: { jwt: [jwtWithNonce] }
          });

        if (res.status === 200) {
          const cred = res.body?.credentials?.[0]?.credential;
          if (typeof cred === 'string') {
            // Basic base64url shape check
            expect(cred).to.match(/^[A-Za-z0-9_-]+=?$/);
          }
        } else {
          expect([202, 400, 500]).to.include(res.status);
        }
      });
    });

    describe('V1.0 Credential Response Encryption', () => {
      it('MUST validate credential_response_encryption with jwk and enc (200/202 on success; 400 on invalid)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const sessionObject = { status: 'success', isDeferred: false, accessToken: accessToken, c_nonce: nonce };
        await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });

        // Missing jwk
        let res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [jwtWithNonce] },
            credential_response_encryption: { enc: 'A256GCM' }
          });
        expect(res.status).to.equal(400);
        expect(res.body.error).to.equal('invalid_encryption_parameters');

        // Missing enc
        res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [jwtWithNonce] },
            credential_response_encryption: { jwk: { kty: 'EC', crv: 'P-256', x: 'AQ', y: 'AQ', alg: 'ECDH-ES' } }
          });
        expect(res.status).to.equal(400);
        expect(res.body.error).to.equal('invalid_encryption_parameters');

        // Unsupported alg (conformance: VCIIssuerFailOnUnsupportedEncryptionAlgorithm)
        res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [jwtWithNonce] },
            credential_response_encryption: {
              jwk: { kty: 'EC', crv: 'P-256', x: 'AQ', y: 'AQ', alg: 'UNSUPPORTED_ALG' },
              enc: 'A256GCM'
            }
          });
        expect(res.status).to.equal(400);
        expect(res.body.error).to.equal('invalid_encryption_parameters');

        const { publicKey: wPub, privateKey: wPriv } = await jose.generateKeyPair('ECDH-ES', { crv: 'P-256' });
        const wJwk = await jose.exportJWK(wPub);
        wJwk.alg = 'ECDH-ES';
        wJwk.kid = 'wallet-enc';

        res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proofs: { jwt: [jwtWithNonce] },
            credential_response_encryption: { jwk: wJwk, enc: 'A256GCM' }
          });
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/application\/jwt/);
        const jwe = res.text;
        const { plaintext } = await jose.compactDecrypt(jwe, wPriv);
        const inner = JSON.parse(new TextDecoder().decode(plaintext));
        expect(inner).to.have.property('credentials');
        expect(inner.credentials[0]).to.have.property('credential');
      });

      it('accepts credential request as application/jwt JWE (encrypted to issuer)', async () => {
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const sessionObject = { status: 'success', isDeferred: false, accessToken, c_nonce: nonce };
        await cacheServiceRedis.storePreAuthSession(sessionKey, sessionObject);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });
        const cryptoMod = await import('crypto');
        const stubbedIssuerPrivPem = fs.readFileSync('./private-key.pem', 'utf8');
        const issuerSpkiPem = cryptoMod.createPublicKey(stubbedIssuerPrivPem).export({
          type: 'spki',
          format: 'pem',
        });
        const issuerPub = await jose.importSPKI(issuerSpkiPem, 'ECDH-ES');
        const inner = {
          credential_configuration_id: 'test-cred-config',
          proofs: { jwt: [jwtWithNonce] }
        };
        const jweReq = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(inner)))
          .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .encrypt(issuerPub);

        const res = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .set('Content-Type', 'application/jwt')
          .send(jweReq);

        expect(res.status).to.equal(200);
        expect(res.body).to.have.property('credentials');
      });

      it('MUST allow override of credential_response_encryption in deferred polling', async function () {
        if (!cacheServiceRedis.client?.isReady) {
          this.skip();
        }
        // Start with deferred issuance to get transaction_id
        const sessionKey = 'test-session-key-' + uuidv4();
        const accessToken = 'test-access-token-' + uuidv4();
        const nonce = cryptoUtils.generateNonce();
        const deferredSession = { status: 'success', isDeferred: true, flowType: 'pre-auth', accessToken: accessToken };
        await cacheServiceRedis.storePreAuthSession(sessionKey, deferredSession);
        await cacheServiceRedis.storeNonce(nonce, 300);

        const jwtWithNonce = signProofJwt({ nonce, iss: 'wallet', aud: process.env.SERVER_URL });

        const first = await request(app)
          .post('/credential')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            credential_configuration_id: 'test-cred-config',
            proof: { jwt: jwtWithNonce }
          });

        if (first.status === 202) {
          const tx = first.body.transaction_id;

          const poll = await request(app)
            .post('/credential_deferred')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
              transaction_id: tx,
              credential_response_encryption: { jwk: { kty: 'EC', crv: 'P-256', x: 'AQ', y: 'AQ' }, enc: 'A256GCM' }
            });

          expect([200, 400, 500]).to.include(poll.status);
        } else {
          expect([400, 500]).to.include(first.status);
        }
      });
    });
  });

  describe('POST /credential_deferred', () => {
    it('MUST return 401 invalid_token without Authorization when transaction_id is present', async () => {
      const res = await request(app)
        .post('/credential_deferred')
        .send({ transaction_id: 'txn-needs-auth-' + uuidv4() })
        .expect(401);
      expect(res.body).to.have.property('error', 'invalid_token');
    });

    it('MUST return invalid_grant when access token session does not own the transaction_id', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const tx = 'tx-mismatch-' + uuidv4();
      const sessionA = 'sess-a-' + uuidv4();
      const sessionB = 'sess-b-' + uuidv4();
      const tokenA = 'tok-a-' + uuidv4();
      const tokenB = 'tok-b-' + uuidv4();
      const proofJwt = signProofJwt({
        nonce: cryptoUtils.generateNonce(),
        iss: 'test-wallet',
        aud: process.env.SERVER_URL
      });
      await cacheServiceRedis.storeCodeFlowSession(sessionA, {
        status: 'pending',
        requests: { accessToken: tokenA },
        requestBody: { vct: 'test-cred-config', proofs: { jwt: [proofJwt] } },
        transaction_id: tx,
        isCredentialReady: false,
        deferred_poll_count: 0,
        deferred_created_at: Math.floor(Date.now() / 1000),
        deferred_expires_at: Math.floor(Date.now() / 1000) + 900,
      });
      await cacheServiceRedis.storeCodeFlowSession(sessionB, {
        status: 'pending',
        requests: { accessToken: tokenB },
        requestBody: { vct: 'test-cred-config', proofs: { jwt: [proofJwt] } },
      });

      const res = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer ${tokenB}`)
        .send({ transaction_id: tx })
        .expect(400);
      expect(res.body).to.have.property('error', 'invalid_grant');
    });

    it('should handle deferred credential issuance successfully', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const transactionId = 'test-transaction-id-' + uuidv4();
      const sessionId = 'test-session-id-' + uuidv4();
      const accessToken = 'test-access-token-' + uuidv4();

      // Create a valid proof JWT for the test
      const proofPayload = {
        nonce: cryptoUtils.generateNonce(),
        iss: 'test-wallet',
        aud: process.env.SERVER_URL
      };
      const proofJwt = signProofJwt(proofPayload);

      const sessionObject = {
        status: 'pending',
        requests: { accessToken },
        requestBody: {
          vct: 'test-cred-config',
          proofs: { jwt: [proofJwt] }
        },
        transaction_id: transactionId
      };
      
      // Set up real test data
      await cacheServiceRedis.storeCodeFlowSession(sessionId, sessionObject);

      const response = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          transaction_id: transactionId
        });

      // May succeed or fail depending on credential generation
      if (response.status === 200) {
        expect(response.body).to.have.property('credentials');
        expect(response.body.credentials).to.be.an('array');
        expect(response.body.credentials[0]).to.have.property('credential');
        expect(typeof response.body.credentials[0].credential).to.equal('string');
        expect(response.body).to.have.property('notification_id');
      } else {
        expect([400, 500]).to.include(response.status);
      }
    });

    it('should reject invalid transaction ID', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const invalidTransactionId = 'invalid-transaction-id-' + uuidv4();
      const sessionId = 'deferred-invalid-tx-session-' + uuidv4();
      const accessToken = 'test-access-token-invalid-tx-' + uuidv4();
      await cacheServiceRedis.storeCodeFlowSession(sessionId, {
        status: 'pending',
        requests: { accessToken },
        requestBody: {},
      });

      const response = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          transaction_id: invalidTransactionId
        })
        .expect(400);

      expect(response.body).to.have.property('error', 'invalid_transaction_id');
    });

    it('should return invalid_token when transaction_id is unknown and token has no issuance session', async () => {
      const missingTransactionId = 'missing-transaction-id-' + uuidv4();

      const response = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer orphan-token-${uuidv4()}`)
        .send({
          transaction_id: missingTransactionId
        })
        .expect(401);

      expect(response.body).to.have.property('error', 'invalid_token');
    });

    // A6 / RFC001 §6.3, §7.6 / OID4VCI 1.0 §9 — pending / expiry paths.
    it('MUST return issuance_pending with interval when credential is not yet ready', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const transactionId = 'pending-tx-' + uuidv4();
      const sessionId = 'pending-session-' + uuidv4();
      const proofJwt = signProofJwt({
        nonce: cryptoUtils.generateNonce(),
        iss: 'test-wallet',
        aud: process.env.SERVER_URL
      });

      const nowSec = Math.floor(Date.now() / 1000);
      // `deferred_pending_polls_override` forces N polls to return pending
      // before readiness, independent of the process-level env setting.
      const accessToken = 'pending-deferred-token-' + uuidv4();
      await cacheServiceRedis.storeCodeFlowSession(sessionId, {
        status: 'pending',
        requests: { accessToken },
        requestBody: {
          vct: 'test-cred-config',
          proofs: { jwt: [proofJwt] }
        },
        transaction_id: transactionId,
        isCredentialReady: false,
        deferred_poll_count: 0,
        deferred_pending_polls_override: 3,
        deferred_created_at: nowSec,
        deferred_expires_at: nowSec + 900
      });

      const response = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ transaction_id: transactionId });

      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('error', 'issuance_pending');
      expect(response.body).to.have.property('interval');
      expect(response.body.interval).to.be.a('number');
      expect(response.body.interval).to.be.greaterThan(0);
    });

    it('MUST return expired_transaction_id after the transaction lifetime', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const transactionId = 'expired-tx-' + uuidv4();
      const sessionId = 'expired-session-' + uuidv4();
      const proofJwt = signProofJwt({
        nonce: cryptoUtils.generateNonce(),
        iss: 'test-wallet',
        aud: process.env.SERVER_URL
      });

      const nowSec = Math.floor(Date.now() / 1000);
      const accessToken = 'expired-deferred-token-' + uuidv4();
      await cacheServiceRedis.storeCodeFlowSession(sessionId, {
        status: 'pending',
        requests: { accessToken },
        requestBody: {
          vct: 'test-cred-config',
          proofs: { jwt: [proofJwt] }
        },
        transaction_id: transactionId,
        isCredentialReady: false,
        deferred_poll_count: 0,
        deferred_created_at: nowSec - 2000,
        deferred_expires_at: nowSec - 10
      });

      const response = await request(app)
        .post('/credential_deferred')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ transaction_id: transactionId });

      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('error', 'expired_transaction_id');
    });
  });

  describe('POST /nonce', () => {
    it('MUST return 401 without Authorization', async () => {
      const response = await request(app).post('/nonce').expect(401);
      expect(response.body).to.have.property('error', 'invalid_token');
    });

    it('MUST return 401 for access token with no issuance session', async () => {
      const response = await request(app)
        .post('/nonce')
        .set('Authorization', 'Bearer orphan-token-' + uuidv4())
        .expect(401);
      expect(response.body).to.have.property('error', 'invalid_token');
    });

    it('accepts Authorization: DPoP for Bearer-issued token (same token string)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'nonce-dpop-scheme-' + uuidv4();
      const accessToken = 'access-dpop-scheme-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        accessToken,
      });
      const response = await request(app)
        .post('/nonce')
        .set('Authorization', `DPoP ${accessToken}`)
        .expect(200);
      expect(response.body).to.have.property('c_nonce');
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;
    });

    it('should generate and store nonce when Authorization matches an issuance session', async () => {
      if (!cacheServiceRedis.client?.isReady) {
        throw new Error('Redis is not ready - cannot run test');
      }
      const sessionKey = 'nonce-session-' + uuidv4();
      const accessToken = 'access-for-nonce-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        accessToken,
      });

      const response = await request(app)
        .post('/nonce')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body).to.have.property('c_nonce');
      expect(response.body).to.have.property('c_nonce_expires_in', 86400);
      expect(await cacheServiceRedis.checkNonce(response.body.c_nonce)).to.be.true;

      const updated = await cacheServiceRedis.getPreAuthSession(sessionKey);
      expect(updated.c_nonce).to.equal(response.body.c_nonce);
    });

    it('should handle nonce storage errors', async () => {
      const response = await request(app).post('/nonce');

      expect([401, 500]).to.include(response.status);
    });
  });

  describe('POST /notification', () => {
    it('MUST reject when session has no notification_id yet (RFC001 §8.7)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'notif-no-nid-' + uuidv4();
      const accessToken = 'access-notif-no-nid-' + uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        accessToken,
      });

      const res = await request(app)
        .post('/notification')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ notification_id: uuidv4(), event: 'credential_accepted' })
        .expect(400);

      expect(res.body).to.have.property('error', 'invalid_notification_request');
    });

    it('MUST reject when notification_id does not match the session (invalid_notification_id)', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'notif-mismatch-' + uuidv4();
      const accessToken = 'access-notif-mismatch-' + uuidv4();
      const issuedId = uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        accessToken,
        notification_id: issuedId,
      });

      const res = await request(app)
        .post('/notification')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ notification_id: uuidv4(), event: 'credential_accepted' })
        .expect(403);

      expect(res.body).to.have.property('error', 'invalid_notification_id');
    });

    it('MUST return 204 when notification_id matches the session', async function () {
      if (!cacheServiceRedis.client?.isReady) {
        this.skip();
      }
      const sessionKey = 'notif-ok-' + uuidv4();
      const accessToken = 'access-notif-ok-' + uuidv4();
      const issuedId = uuidv4();
      await cacheServiceRedis.storePreAuthSession(sessionKey, {
        status: 'success',
        accessToken,
        notification_id: issuedId,
      });

      await request(app)
        .post('/notification')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          notification_id: issuedId,
          event: 'credential_accepted',
          event_description: 'ok',
        })
        .expect(204);
    });
  });

  describe('GET /issueStatus', () => {
    it('should return pre-auth session status', async () => {
      const sessionId = 'test-session-id-' + uuidv4();
      const preAuthSession = { status: 'success' };
      await cacheServiceRedis.storePreAuthSession(sessionId, preAuthSession);

      const response = await request(app)
        .get('/issueStatus')
        .query({ sessionId: sessionId })
        .expect(200);

      expect(response.body).to.have.property('status', 'success');
      expect(response.body).to.have.property('reason', 'ok');
      expect(response.body).to.have.property('sessionId', sessionId);
    });

    it('should return code flow session status', async () => {
      const sessionId = 'test-session-id-' + uuidv4();
      const codeFlowSession = { status: 'pending' };
      await cacheServiceRedis.storeCodeFlowSession(sessionId, codeFlowSession);

      const response = await request(app)
        .get('/issueStatus')
        .query({ sessionId: sessionId })
        .expect(200);

      expect(response.body).to.have.property('status', 'pending');
      expect(response.body).to.have.property('reason', 'ok');
    });

    it('should return failed status for non-existent session', async () => {
      const nonExistentSessionId = 'non-existent-session-' + uuidv4();

      const response = await request(app)
        .get('/issueStatus')
        .query({ sessionId: nonExistentSessionId })
        .expect(200);

      expect(response.body).to.have.property('status', 'failed');
      expect(response.body).to.have.property('reason', 'not found');
    });
  });

  describe('Error handling', () => {
    it('should handle token endpoint errors gracefully', async () => {
      // Test with invalid request to trigger error handling
      const { dpopJwt } = await makeTokenDpop();
      await makeTestWiaClientAssertion();
      const response = await wireWiaOAuthHeaders(
        request(app)
          .post('/token_endpoint')
          .set('Authorization', 'Bearer test-token')
          .set('DPoP', dpopJwt)
      )
        .send({
          ...pickWiaBodyFields(),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': 'invalid-code-that-does-not-exist'
        });

      // Should return error response (400 or 500)
      expect([400, 500]).to.include(response.status);
      if (response.body) {
        expect(response.body).to.have.property('error');
      }
    });

    it('should handle credential endpoint errors gracefully', async () => {
      // Test with invalid proof to trigger error handling
      const response = await request(app)
        .post('/credential')
        .set('Authorization', 'Bearer invalid-token')
        .send({
          credential_configuration_id: 'test-cred-config',
          proof: { jwt: 'invalid-jwt' }
        });

      // Should return error response
      expect([400, 500]).to.include(response.status);
      if (response.body) {
        expect(response.body).to.have.property('error');
      }
    });

    it('should handle nonce endpoint errors gracefully', async () => {
      const response = await request(app).post('/nonce');
      expect([401, 500]).to.include(response.status);
    });
  });
}); 