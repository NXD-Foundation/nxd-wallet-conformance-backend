import { expect } from 'chai';
import request from 'supertest';
import express from 'express';

/**
 * DID Web Routes Tests
 *
 * Tests for /.well-known/did.json, /did.json, /:path/did.json, and /.well-known/jwks.json
 * Validates W3C DID document structure, including:
 * - authentication and assertionMethod MUST reference full DID URLs (verificationMethod.id)
 * - controller in verificationMethod MUST be the full DID
 * - JWKS kid MUST be the full DID URL for resolver compatibility
 */
describe('DID Web Routes', () => {
  let app;
  let didWebRouter;
  let originalServerUrl;
  let originalProxyPath;

  before(async () => {
    originalServerUrl = process.env.SERVER_URL;
    originalProxyPath = process.env.PROXY_PATH;

    process.env.SERVER_URL = 'https://localhost:3000';
    delete process.env.PROXY_PATH;

    const didWebModule = await import('../routes/didweb.js');
    didWebRouter = didWebModule.default;

    app = express();
    app.use(express.json());
    app.use('/', didWebRouter);
  });

  after(() => {
    if (originalServerUrl !== undefined) {
      process.env.SERVER_URL = originalServerUrl;
    } else {
      delete process.env.SERVER_URL;
    }
    if (originalProxyPath !== undefined) {
      process.env.PROXY_PATH = originalProxyPath;
    } else {
      delete process.env.PROXY_PATH;
    }
  });

  describe('GET /.well-known/did.json and /did.json', () => {
    it('should return DID document with correct structure', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const doc = response.body;
      expect(doc).to.have.property('@context', 'https://www.w3.org/ns/did/v1');
      expect(doc).to.have.property('id');
      expect(doc.id).to.match(/^did:web:/);
      expect(doc).to.have.property('verificationMethod').that.is.an('array');
      expect(doc).to.have.property('authentication').that.is.an('array');
      expect(doc).to.have.property('assertionMethod').that.is.an('array');
      expect(doc).to.have.property('service').that.is.an('array');
    });

    it('verificationMethod.id MUST be full DID URL (did:web:...:#keys-1)', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const vm = response.body.verificationMethod[0];
      expect(vm.id).to.match(/^did:web:.*#keys-1$/);
      expect(vm.id).to.equal(response.body.id + '#keys-1');
    });

    it('authentication and assertionMethod MUST reference verificationMethod.id exactly', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const keyId = response.body.verificationMethod[0].id;
      expect(response.body.authentication).to.include(keyId);
      expect(response.body.assertionMethod).to.include(keyId);
    });

    it('verificationMethod.controller MUST be the full DID', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const vm = response.body.verificationMethod[0];
      expect(vm.controller).to.equal(response.body.id);
    });

    it('verificationMethod MUST contain publicKeyJwk', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const vm = response.body.verificationMethod[0];
      expect(vm).to.have.property('publicKeyJwk');
      expect(vm.publicKeyJwk).to.have.property('kty');
      expect(vm.publicKeyJwk).to.have.property('crv');
    });

    it('service MUST point to JWKS endpoint', async () => {
      const response = await request(app)
        .get('/.well-known/did.json')
        .expect(200);

      const svc = response.body.service[0];
      expect(svc.id).to.equal(response.body.id + '#jwks');
      expect(svc.serviceEndpoint).to.include('/.well-known/jwks.json');
    });

    it('/did.json should return same structure as /.well-known/did.json', async () => {
      const wellKnown = await request(app).get('/.well-known/did.json').expect(200);
      const root = await request(app).get('/did.json').expect(200);

      expect(root.body.id).to.equal(wellKnown.body.id);
      expect(root.body.verificationMethod[0].id).to.equal(wellKnown.body.verificationMethod[0].id);
    });
  });

  describe('GET /:path/did.json (path-based DIDs)', () => {
    it('should return DID document for path-based DID', async () => {
      const response = await request(app)
        .get('/rfc-issuer/did.json')
        .expect(200);

      const doc = response.body;
      expect(doc.id).to.match(/^did:web:.*:rfc-issuer$/);
      expect(doc.verificationMethod[0].id).to.equal(doc.id + '#keys-1');
      expect(doc.authentication).to.include(doc.id + '#keys-1');
      expect(doc.assertionMethod).to.include(doc.id + '#keys-1');
    });

    it('path segment MUST be included in DID identifier', async () => {
      const response = await request(app)
        .get('/my-path/did.json')
        .expect(200);

      expect(response.body.id).to.include(':my-path');
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return JWKS with keys array', async () => {
      const response = await request(app)
        .get('/.well-known/jwks.json')
        .expect(200);

      expect(response.body).to.have.property('keys').that.is.an('array');
      expect(response.body.keys).to.have.lengthOf(1);
    });

    it('kid MUST be full DID URL (did:web:...:#keys-1)', async () => {
      const response = await request(app)
        .get('/.well-known/jwks.json')
        .expect(200);

      const key = response.body.keys[0];
      expect(key.kid).to.match(/^did:web:.*#keys-1$/);
    });

    it('kid MUST match verificationMethod.id in DID document', async () => {
      const didResponse = await request(app).get('/.well-known/did.json').expect(200);
      const jwksResponse = await request(app).get('/.well-known/jwks.json').expect(200);

      const expectedKid = didResponse.body.verificationMethod[0].id;
      expect(jwksResponse.body.keys[0].kid).to.equal(expectedKid);
    });

    it('key MUST have use: sig', async () => {
      const response = await request(app)
        .get('/.well-known/jwks.json')
        .expect(200);

      expect(response.body.keys[0].use).to.equal('sig');
    });
  });

});
