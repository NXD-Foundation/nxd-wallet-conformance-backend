import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import sinon from 'sinon';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';

process.env.ALLOW_NO_REDIS = 'true';
process.env.SERVER_URL = 'http://localhost:3000';

const TX_CODE_OFFER_ROUTES = [
  {
    path: '/offer-tx-code',
    deepLinkScheme: 'openid-credential-offer://',
    credentialOfferPath: '/credential-offer-tx-code/',
  },
  {
    path: '/haip-offer-tx-code',
    deepLinkScheme: 'haip://',
    credentialOfferPath: '/haip-credential-offer-tx-code/',
  },
];

describe('Pre-Auth TX Code Offer Routes (APTITUDE)', () => {
  let app;
  let globalSandbox;
  let cacheServiceRedis;

  before(async () => {
    globalSandbox = sinon.createSandbox();
    const crypto = await import('crypto');
    const { privateKey, publicKey } = crypto.default.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

    globalSandbox.stub(fs, 'readFileSync')
      .withArgs(sinon.match(/private-key\.pem/)).returns(privateKeyPem)
      .withArgs(sinon.match(/public-key\.pem/)).returns(publicKeyPem)
      .withArgs(sinon.match(/x509EC/)).returns(privateKeyPem);

    cacheServiceRedis = await import('../services/cacheServiceRedis.js');
    if (cacheServiceRedis.client) {
      let attempts = 0;
      while (!cacheServiceRedis.client.isReady && attempts < 50) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        attempts += 1;
      }
    }

    const preAuthModule = await import('../routes/issue/preAuthSDjwRoutes.js');
    const vciModule = await import('../routes/issue/vciStandardRoutes.js');

    app = express();
    app.use(express.json());
    app.use('/', preAuthModule.default);
    app.use('/', vciModule.default);
  });

  after(() => {
    globalSandbox.restore();
  });

  function expectTxCodeOfferShape(body, {
    sessionId,
    credentialType,
    deepLinkScheme,
    credentialOfferPath,
  }) {
    expect(body).to.include.keys('qr', 'deepLink', 'sessionId', 'txCode');
    expect(body.sessionId).to.equal(sessionId);
    expect(body.qr).to.match(/^data:image\/PNG;base64,/);
    expect(body.deepLink).to.include(deepLinkScheme);
    expect(body.deepLink).to.include('credential_offer_uri');
    expect(body.deepLink).to.include(encodeURIComponent(`${credentialOfferPath}${sessionId}`));
    expect(body.deepLink).to.include(encodeURIComponent(`type=${credentialType}`));
    expect(body.txCode).to.match(/^\d{4}$/);
  }

  for (const route of TX_CODE_OFFER_ROUTES) {
    describe(`GET ${route.path}`, () => {
      it('returns qr, deepLink, sessionId, and txCode', async () => {
        const sessionId = `tx-offer-${uuidv4()}`;
        const credentialType = 'ETSIRfc001PidVcSdJwt';

        const response = await request(app)
          .get(route.path)
          .query({
            sessionId,
            credentialType,
            signatureType: 'x509',
          })
          .expect(200);

        expectTxCodeOfferShape(response.body, {
          sessionId,
          credentialType,
          deepLinkScheme: route.deepLinkScheme,
          credentialOfferPath: route.credentialOfferPath,
        });
      });

      it('stores expectedTxCode in the session matching the response txCode', async () => {
        const sessionId = `tx-offer-store-${uuidv4()}`;

        const response = await request(app)
          .get(route.path)
          .query({ sessionId, signatureType: 'x509' })
          .expect(200);

        const storedSession = await cacheServiceRedis.getPreAuthSession(sessionId);
        expect(storedSession).to.have.property('requireTxCode', true);
        expect(storedSession).to.have.property('expectedTxCode', response.body.txCode);
      });

      it('returns the existing session txCode when the session already exists', async () => {
        const sessionId = `tx-offer-existing-${uuidv4()}`;
        await cacheServiceRedis.storePreAuthSession(sessionId, {
          status: 'pending',
          flowType: 'pre-auth',
          requireTxCode: true,
          expectedTxCode: '4321',
        });

        const response = await request(app)
          .get(route.path)
          .query({ sessionId, signatureType: 'x509' })
          .expect(200);

        expect(response.body.txCode).to.equal('4321');
      });
    });
  }

  describe('GET /offer-no-code', () => {
    it('returns qr, deepLink, and sessionId without txCode', async () => {
      const sessionId = `no-tx-${uuidv4()}`;

      const response = await request(app)
        .get('/offer-no-code')
        .query({ sessionId, signatureType: 'x509' })
        .expect(200);

      expect(response.body).to.include.keys('qr', 'deepLink', 'sessionId');
      expect(response.body).to.not.have.property('txCode');
    });
  });

  describe('GET /vci/offer', () => {
    it('returns txCode when flow is pre_authorized_code and tx_code_required is true', async () => {
      const sessionId = `vci-tx-${uuidv4()}`;
      const credentialType = 'ETSIRfc001PidVcSdJwt';

      const response = await request(app)
        .get('/vci/offer')
        .query({
          session_id: sessionId,
          flow: 'pre_authorized_code',
          tx_code_required: 'true',
          credential_type: credentialType,
          signature_type: 'x509',
        })
        .expect(200);

      expectTxCodeOfferShape(response.body, {
        sessionId,
        credentialType,
        deepLinkScheme: 'openid-credential-offer://',
        credentialOfferPath: '/credential-offer-tx-code/',
      });
    });

    it('does not return txCode when tx_code_required is false', async () => {
      const sessionId = `vci-no-tx-${uuidv4()}`;

      const response = await request(app)
        .get('/vci/offer')
        .query({
          session_id: sessionId,
          flow: 'pre_authorized_code',
          tx_code_required: 'false',
          credential_type: 'ETSIRfc001PidVcSdJwt',
          signature_type: 'x509',
        })
        .expect(200);

      expect(response.body).to.include.keys('qr', 'deepLink', 'sessionId');
      expect(response.body).to.not.have.property('txCode');
    });
  });
});
