import { strict as assert } from 'assert';
import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import metadataRouter from '../routes/metadataroutes.js';
import {
  buildOpenIdVerifierMetadataDocument,
  loadConfigurationFiles,
  loadVerifierClientMetadataForRequests,
  OPENID_VERIFIER_METADATA_WELL_KNOWN_PATH,
  SERVER_URL,
} from '../utils/routeUtils.js';

describe('OpenID Verifier metadata (RFC002 §8.4)', () => {
  it('GET /.well-known/openid-verifier-metadata returns JSON with verifier_info and merged jwks', async () => {
    const app = express();
    app.use('/', metadataRouter);
    const res = await request(app).get(OPENID_VERIFIER_METADATA_WELL_KNOWN_PATH).expect(200);

    expect(res.headers['content-type']).to.match(/application\/json/);
    const body = res.body;
    expect(body).to.have.property('client_id');
    expect(body).to.have.property('verifier_info');
    expect(body.verifier_info).to.have.property('verifier_id');
    expect(body).to.have.property('jwks');
    expect(body.jwks).to.have.property('keys');
    expect(body.jwks.keys).to.be.an('array');
    expect(body.jwks.keys.length).to.be.at.least(1);

    const hasEnc = body.jwks.keys.some((k) => k.use === 'enc');
    const hasSig = body.jwks.keys.some((k) => k.use === 'sig');
    expect(hasEnc).to.equal(true);
    expect(hasSig).to.equal(true);

    for (const k of body.jwks.keys) {
      assert.ok(!('d' in k), 'JWKS must not expose private key material');
    }
  });

  it('buildOpenIdVerifierMetadataDocument matches merged shape', () => {
    const doc = buildOpenIdVerifierMetadataDocument({ serverURL: SERVER_URL });
    expect(doc.verifier_info?.verifier_id).to.be.a('string');
    expect(doc.jwks?.keys?.length).to.be.at.least(2);
  });

  it('loadVerifierClientMetadataForRequests sets client_metadata_uri', () => {
    const meta = loadVerifierClientMetadataForRequests('https://rp.example.org');
    expect(meta.client_metadata_uri).to.equal(
      `https://rp.example.org${OPENID_VERIFIER_METADATA_WELL_KNOWN_PATH}`,
    );
  });

  it('loadConfigurationFiles attaches client_metadata_uri for verifier-config-mdl.json', () => {
    const { clientMetadata } = loadConfigurationFiles(
      './data/presentation_definition_mdl.json',
      './data/verifier-config-mdl.json',
    );
    expect(clientMetadata.client_metadata_uri).to.equal(
      `${String(SERVER_URL).replace(/\/$/, '')}${OPENID_VERIFIER_METADATA_WELL_KNOWN_PATH}`,
    );
  });
});
