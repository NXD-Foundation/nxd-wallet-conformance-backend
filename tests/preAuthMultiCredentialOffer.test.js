import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

process.env.ALLOW_NO_REDIS = 'true';
process.env.SERVER_URL = 'http://localhost:3000';

describe('Multi-credential pre-auth offer routes', () => {
  let app;
  let cacheServiceRedis;

  before(async () => {
    cacheServiceRedis = await import('../services/cacheServiceRedis.js');

    if (cacheServiceRedis.client) {
      let attempts = 0;
      while (!cacheServiceRedis.client.isReady && attempts < 50) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        attempts++;
      }
    }

    const preAuthModule = await import('../routes/issue/preAuthSDjwRoutes.js');
    const multiCredentialModule = await import('../routes/multiCredentialOfferRoutes.js');

    app = express();
    app.use(express.json());
    app.use('/', preAuthModule.default);
    app.use('/', multiCredentialModule.default);
  });

  const studentPayload = {
    family_name: 'Doe',
    given_name: 'Jane',
    student_id: 'S-123',
  };
  const loyaltyPayload = {
    card_number: 'LC-999',
    tier: 'gold',
  };

  it('POST /offer-no-code-batch stores offered ids and returns deep link without type query', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-offer-${uuidv4()}`;
    const response = await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send({
        credentials: [
          {
            credential_configuration_id: 'VerifiableStudentIDSDJWT',
            payload: studentPayload,
          },
          {
            credential_configuration_id: 'LoyaltyCard',
            payload: loyaltyPayload,
          },
        ],
      })
      .expect(200);

    expect(response.body).to.have.property('qr');
    expect(response.body).to.have.property('deepLink');
    expect(response.body.sessionId).to.equal(sessionId);
    expect(response.body.offeredConfigurationIds).to.deep.equal([
      'VerifiableStudentIDSDJWT',
      'LoyaltyCard',
    ]);
    expect(response.body.deepLink).to.include('credential-offer-no-code-batch');
    expect(response.body.deepLink).to.not.include('type=');

    const stored = await cacheServiceRedis.getPreAuthSession(sessionId);
    expect(stored.offeredConfigurationIds).to.deep.equal([
      'VerifiableStudentIDSDJWT',
      'LoyaltyCard',
    ]);
    expect(stored.credentialPayloads['VerifiableStudentIDSDJWT']).to.deep.equal(
      studentPayload,
    );
    expect(stored.credentialPayloads.LoyaltyCard).to.deep.equal(loyaltyPayload);
  });

  it('GET /credential-offer-no-code-batch/:id resolves dynamic ids from session', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-offer-doc-${uuidv4()}`;
    await cacheServiceRedis.storePreAuthSession(sessionId, {
      status: 'pending',
      flowType: 'pre-auth',
      offeredConfigurationIds: ['VerifiableStudentIDSDJWT', 'LoyaltyCard'],
      credentialPayloads: {
        VerifiableStudentIDSDJWT: studentPayload,
        LoyaltyCard: loyaltyPayload,
      },
      issuedConfigurationIds: [],
    });

    const response = await request(app)
      .get(`/credential-offer-no-code-batch/${sessionId}`)
      .expect(200);

    expect(response.body.credential_configuration_ids).to.deep.equal([
      'VerifiableStudentIDSDJWT',
      'LoyaltyCard',
    ]);
    expect(
      response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    ).to.have.property('pre-authorized_code', sessionId);
    expect(
      response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    ).to.have.property(
      'scope',
      'VerifiableStudentIDSDJWT LoyaltyCard',
    );
  });

  it('GET /credential-offer-no-code-batch/:id falls back to legacy ids when session has no offer state', async function () {
    const sessionId = `legacy-batch-${uuidv4()}`;

    const response = await request(app)
      .get(`/credential-offer-no-code-batch/${sessionId}`)
      .expect(200);

    expect(response.body.credential_configuration_ids).to.deep.equal([
      'urn:eu.europa.ec.eudi:pid:1',
      'PhotoID',
    ]);
  });

  it('POST /offer-no-code-batch rejects conflicting reuse of sessionId', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-conflict-${uuidv4()}`;

    await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send({
        credentials: [
          {
            credential_configuration_id: 'VerifiableStudentIDSDJWT',
            payload: studentPayload,
          },
        ],
      })
      .expect(200);

    const conflict = await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send({
        credentials: [
          {
            credential_configuration_id: 'LoyaltyCard',
            payload: loyaltyPayload,
          },
        ],
      })
      .expect(409);

    expect(conflict.body).to.have.property('error', 'invalid_request');
    expect(conflict.body.error_description).to.match(/different offer data/i);
  });

  it('POST /offer-no-code-batch is idempotent for identical offer data', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-idempotent-${uuidv4()}`;
    const body = {
      credentials: [
        {
          credential_configuration_id: 'VerifiableStudentIDSDJWT',
          payload: studentPayload,
        },
      ],
    };

    await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send(body)
      .expect(200);

    await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send(body)
      .expect(200);

    const stored = await cacheServiceRedis.getPreAuthSession(sessionId);
    expect(stored.offeredConfigurationIds).to.deep.equal([
      'VerifiableStudentIDSDJWT',
    ]);
  });
});
