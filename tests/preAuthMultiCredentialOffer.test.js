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

  const hotelPayload = {
    booking_reference: 'OTA-MS62DP17-VQPSKP',
    hotel_id: '9213',
    hotel_name: 'Test Hotel Rhodes',
    arrival_date: '2026-07-31',
    departure_date: '2026-08-04',
    booking_platform: 'SEDIT-X OTA Booking Portal',
  };
  const airlinePnrPayload = { pnr: 'Q7X2LM' };

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
            credential_configuration_id: 'booking_reference_credential',
            payload: hotelPayload,
          },
          {
            credential_configuration_id: 'airline_pnr_credential',
            payload: airlinePnrPayload,
          },
        ],
      })
      .expect(200);

    expect(response.body).to.have.property('qr');
    expect(response.body).to.have.property('deepLink');
    expect(response.body.sessionId).to.equal(sessionId);
    expect(response.body.offeredConfigurationIds).to.deep.equal([
      'booking_reference_credential',
      'airline_pnr_credential',
    ]);
    expect(response.body.deepLink).to.include('credential-offer-no-code-batch');
    expect(response.body.deepLink).to.not.include('type=');

    const stored = await cacheServiceRedis.getPreAuthSession(sessionId);
    expect(stored.offeredConfigurationIds).to.deep.equal([
      'booking_reference_credential',
      'airline_pnr_credential',
    ]);
    expect(stored.credentialPayloads.booking_reference_credential).to.deep.equal(
      hotelPayload,
    );
    expect(stored.credentialPayloads.airline_pnr_credential).to.deep.equal(airlinePnrPayload);
  });

  it('POST /offer-no-code-batch stores signatureType=x509 from query for issuance', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-offer-x509-${uuidv4()}`;
    const response = await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId, signatureType: 'x509' })
      .send({
        credentials: [
          {
            credential_configuration_id: 'airline_pnr_credential',
            payload: airlinePnrPayload,
          },
        ],
      })
      .expect(200);

    expect(response.body.sessionId).to.equal(sessionId);
    const stored = await cacheServiceRedis.getPreAuthSession(sessionId);
    expect(stored.signatureType).to.equal('x509');
    expect(stored.offeredConfigurationIds).to.deep.equal([
      'airline_pnr_credential',
    ]);
  });

  it('POST /offer-no-code-batch stores signatureType=x509 from JSON body for issuance', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-offer-x509-body-${uuidv4()}`;
    const response = await request(app)
      .post('/offer-no-code-batch')
      .query({ sessionId })
      .send({
        signatureType: 'x509',
        credentials: [
          {
            credential_configuration_id: 'airline_pnr_credential',
            payload: airlinePnrPayload,
          },
        ],
      })
      .expect(200);

    expect(response.body.sessionId).to.equal(sessionId);
    const stored = await cacheServiceRedis.getPreAuthSession(sessionId);
    expect(stored.signatureType).to.equal('x509');
  });

  it('GET /credential-offer-no-code-batch/:id resolves dynamic ids from session', async function () {
    if (!cacheServiceRedis.client?.isReady) {
      this.skip();
    }

    const sessionId = `batch-offer-doc-${uuidv4()}`;
    await cacheServiceRedis.storePreAuthSession(sessionId, {
      status: 'pending',
      flowType: 'pre-auth',
      offeredConfigurationIds: ['booking_reference_credential', 'airline_pnr_credential'],
      credentialPayloads: {
        booking_reference_credential: hotelPayload,
        airline_pnr_credential: airlinePnrPayload,
      },
      issuedConfigurationIds: [],
    });

    const response = await request(app)
      .get(`/credential-offer-no-code-batch/${sessionId}`)
      .expect(200);

    expect(response.body.credential_configuration_ids).to.deep.equal([
      'booking_reference_credential',
      'airline_pnr_credential',
    ]);
    expect(
      response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    ).to.have.property('pre-authorized_code', sessionId);
    expect(
      response.body.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    ).to.have.property(
      'scope',
      'booking_reference_credential airline_pnr_credential',
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
            credential_configuration_id: 'booking_reference_credential',
            payload: hotelPayload,
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
            credential_configuration_id: 'airline_pnr_credential',
            payload: airlinePnrPayload,
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
          credential_configuration_id: 'booking_reference_credential',
          payload: hotelPayload,
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
      'booking_reference_credential',
    ]);
  });
});
