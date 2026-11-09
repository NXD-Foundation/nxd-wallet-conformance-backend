import { X509Certificate } from 'node:crypto';
import { buildCredentialProofRequest } from '../src/lib/credentialProofBinding.js';
import { expect } from 'chai';
import { decodeProtectedHeader, decodeJwt, jwtVerify, importJWK } from 'jose';
import { buildCredentialRequest } from '../src/lib/issuance.js';
import { buildCredentialRequestProofs } from '../src/lib/credentialRequestProofs.js';
import { ensureOrCreateEcKeyPair } from '../src/lib/crypto.js';

describe('credential attestation policy', () => {
  let previousInstanceId;
  before(() => { previousInstanceId = process.env.WALLET_INSTANCE_ID; process.env.WALLET_INSTANCE_ID = '11111111-1111-1111-1111-111111111111'; });
  after(() => { if (previousInstanceId === undefined) delete process.env.WALLET_INSTANCE_ID; else process.env.WALLET_INSTANCE_ID = previousInstanceId; });
  async function request({ metadata, profile = 'compatibility', configurationId = 'selected', builder } = {}) {
    const keys = await ensureOrCreateEcKeyPair(undefined, 'ES256');
    const result = await buildCredentialRequest({
      configurationId, issuerMeta: { credential_configurations_supported: metadata }, profile,
      tokenBody: {}, proofMode: 'jwt', credentialEndpoint: 'https://issuer.example/credential',
      audience: 'https://issuer.example', c_nonce: 'nonce', keyPairs: [keys], selectedAlg: 'ES256',
      clientId: 'wallet', buildCredentialRequestProofs: builder || buildCredentialRequestProofs,
      buildCredentialRequestSelector: id => ({ credential_configuration_id: id }),
      prepareCredentialResponseEncryption: async () => null,
    });
    return { ...result, keys };
  }
  it('sends a verifiable JWT proof with WUA when metadata omits KA', async () => {
    const { proofJwt, keys } = await request({ metadata: { selected: { proof_types_supported: { jwt: {} } } } });
    const wua = decodeProtectedHeader(proofJwt).key_attestation;
    expect(wua).to.be.a('string');
    const header = decodeProtectedHeader(wua);
    expect(header.jwk).to.equal(undefined);
    const certificate = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
    const verifiedWua = await jwtVerify(wua, certificate.publicKey);
    expect(verifiedWua.payload.nonce).to.equal('nonce');
    expect(decodeJwt(wua).attested_keys[0]).to.deep.include({ x: keys.publicJwk.x, y: keys.publicJwk.y });
    const { payload } = await jwtVerify(proofJwt, await importJWK(keys.publicJwk, 'ES256'), { audience: 'https://issuer.example' });
    expect(payload.nonce).to.equal('nonce');
    expect(payload.iss).to.equal('wallet');
  });
  it('authorization-code compatibility binds certificate-backed WUA to holder and nonce', async () => {
    const result = await buildCredentialProofRequest({
      profile: 'compatibility', issuerMeta: {}, apiBase: 'https://issuer.example',
      configurationId: 'selected', credentialIdentifier: 'credential-1', cNonce: 'fresh-nonce',
      credentialEndpoint: 'https://issuer.example/credential', clientId: 'wallet',
    });
    const wua = decodeProtectedHeader(result.proofJwt).key_attestation;
    const header = decodeProtectedHeader(wua);
    expect(header.jwk).to.equal(undefined);
    const certificate = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
    const { payload } = await jwtVerify(wua, certificate.publicKey);
    expect(payload.nonce).to.equal('fresh-nonce');
    expect(payload.attested_keys[0]).to.deep.include({ x: result.subjectKey.publicJwk.x, y: result.subjectKey.publicJwk.y });
    const proof = await jwtVerify(result.proofJwt, await importJWK(result.subjectKey.publicJwk, 'ES256'));
    expect(proof.payload.nonce).to.equal(payload.nonce);
    expect(result.credentialRequest.credential_identifier).to.equal('credential-1');
  });
  for (const [title, metadata, profile] of [
    ['empty required object', { selected: { proof_types_supported: { jwt: { key_attestations_required: {} } } } }, 'compatibility'],
    ['another configuration', { other: { proof_types_supported: { jwt: { key_attestations_required: {} } } } }, 'compatibility'],
    ['another proof type', { selected: { proof_types_supported: { attestation: { key_attestations_required: {} } } } }, 'compatibility'],
    ['strict WE BUILD profile', {}, 'webuild-cs01'],
  ]) {
    it(`includes WUA for ${title}`, async () => {
      const { proofJwt } = await request({ metadata, profile });
      expect(decodeProtectedHeader(proofJwt).key_attestation).to.be.a('string');
    });
  }
});
