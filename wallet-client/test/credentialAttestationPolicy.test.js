import { expect } from 'chai';
import { decodeProtectedHeader, jwtVerify, importJWK } from 'jose';
import { buildCredentialRequest } from '../src/lib/issuance.js';
import { buildCredentialRequestProofs } from '../src/lib/credentialRequestProofs.js';
import { ensureOrCreateEcKeyPair } from '../src/lib/crypto.js';

describe('credential attestation policy', () => {
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
  it('sends a verifiable ordinary JWT proof without requiring provider material when metadata omits KA', async () => {
    const { proofJwt, keys } = await request({ metadata: { selected: { proof_types_supported: { jwt: {} } } } });
    expect(decodeProtectedHeader(proofJwt)).not.to.have.property('key_attestation');
    const { payload } = await jwtVerify(proofJwt, await importJWK(keys.publicJwk, 'ES256'), { audience: 'https://issuer.example' });
    expect(payload.nonce).to.equal('nonce');
    expect(payload.iss).to.equal('wallet');
  });
  for (const [title, metadata, profile, required] of [
    ['empty required object', { selected: { proof_types_supported: { jwt: { key_attestations_required: {} } } } }, 'compatibility', true],
    ['another configuration', { other: { proof_types_supported: { jwt: { key_attestations_required: {} } } } }, 'compatibility', false],
    ['another proof type', { selected: { proof_types_supported: { attestation: { key_attestations_required: {} } } } }, 'compatibility', false],
    ['strict WE BUILD profile', {}, 'webuild-cs01', true],
  ]) {
    it(`selects attestation policy for ${title}`, async () => {
      let actual;
      await request({ metadata, profile, builder: async args => { actual = args.keyAttestationRequired; return { proofs: {}, proofJwt: null }; } });
      expect(actual).to.equal(required);
    });
  }
});
