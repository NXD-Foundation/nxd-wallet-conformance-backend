import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import fs from 'fs';
import * as jose from 'jose';

import didWebRouter from '../routes/didweb.js';
import { handleCredentialGenerationBasedOnFormat } from '../utils/credGenerationUtils.js';

const originalServerUrl = process.env.SERVER_URL;
const originalIssuerSigType = process.env.ISSUER_SIGNATURE_TYPE;
const originalProxyPath = process.env.PROXY_PATH;

process.env.ALLOW_NO_REDIS = 'true';
process.env.SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
process.env.ISSUER_SIGNATURE_TYPE = 'did:web';
delete process.env.PROXY_PATH;

function restoreEnv() {
  if (originalServerUrl !== undefined) process.env.SERVER_URL = originalServerUrl;
  else delete process.env.SERVER_URL;
  if (originalIssuerSigType !== undefined) process.env.ISSUER_SIGNATURE_TYPE = originalIssuerSigType;
  else delete process.env.ISSUER_SIGNATURE_TYPE;
  if (originalProxyPath !== undefined) process.env.PROXY_PATH = originalProxyPath;
  else delete process.env.PROXY_PATH;
}

function didJwksFilesExist() {
  try {
    fs.accessSync('./didjwks/did_private_pkcs8.key');
    fs.accessSync('./didjwks/did_public.pem');
    return true;
  } catch {
    return false;
  }
}

describe('did:web credential and JWKS alignment', () => {
  let app;

  before(function () {
    if (!didJwksFilesExist()) {
      this.skip();
    }

    app = express();
    app.use(express.json());
    app.use('/', didWebRouter);
  });

  after(() => {
    restoreEnv();
  });

  it('credential iss and JOSE kid MUST align with did:web DID document and /.well-known/jwks.json', async () => {
    // 1. Fetch DID document and JWKS
    const didRes = await request(app).get('/.well-known/did.json').expect(200);
    const jwksRes = await request(app).get('/.well-known/jwks.json').expect(200);

    const didDoc = didRes.body;
    const jwks = jwksRes.body;

    expect(didDoc.id).to.match(/^did:web:/);
    expect(didDoc.verificationMethod).to.be.an('array').with.length.greaterThan(0);
    const vm = didDoc.verificationMethod[0];
    const expectedDid = didDoc.id;
    const expectedKid = vm.id;

    expect(jwks.keys).to.be.an('array').with.length.greaterThan(0);
    const jwkFromJwks = jwks.keys[0];
    expect(jwkFromJwks.kid).to.equal(expectedKid);

    // 2. Build a minimal holder proof JWT with embedded JWK (for cnf.jwk)
    const { publicKey } = await jose.generateKeyPair('ES256');
    const holderJwk = await jose.exportJWK(publicKey);

    const proofHeader = { alg: 'ES256', jwk: holderJwk };
    const proofPayload = {
      iss: 'did:example:holder',
      aud: process.env.SERVER_URL,
      nonce: 'test-nonce-123',
    };
    const proofJwt = [
      Buffer.from(JSON.stringify({ ...proofHeader })).toString('base64url'),
      Buffer.from(JSON.stringify(proofPayload)).toString('base64url'),
      'signature-placeholder',
    ].join('.');

    // 3. Issue a did:web credential using handleCredentialGenerationBasedOnFormat
    const requestBody = {
      vct: 'test-cred-config',
      proofs: { jwt: [proofJwt] },
    };
    const sessionObject = {
      signatureType: 'did:web',
      isHaip: false,
    };

    const credential = await handleCredentialGenerationBasedOnFormat(
      requestBody,
      sessionObject,
      process.env.SERVER_URL,
      'dc+sd-jwt'
    );

    // SD-JWT: first part before '~' is the signed JWT
    const compactJwt = credential.split('~')[0];

    const header = jose.decodeProtectedHeader(compactJwt);
    const payload = jose.decodeJwt(compactJwt);

    // 4. Verify alignment
    expect(header.kid).to.equal(expectedKid);
    expect(payload.iss).to.equal(expectedDid);

    // 5. Verify signature against /.well-known/jwks.json
    const JWKS = jose.createLocalJWKSet(jwks);
    const verified = await jose.jwtVerify(compactJwt, JWKS);
    expect(verified.protectedHeader.kid).to.equal(expectedKid);
    expect(verified.payload.iss).to.equal(expectedDid);
  });
});

