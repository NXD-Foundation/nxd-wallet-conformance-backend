import { expect } from 'chai';
import { createTs12ScaUserAttestationPayload } from '../utils/credPayloadUtil.js';
import { validateTs12PaymentPresentationResponse } from '../utils/ts12Validation.js';
import { TS12_SCA_USER_VCT, buildTs12PaymentTransactionData, encodeTs12TransactionData, computeTs12TransactionDataHash } from '../utils/ts12PaymentUtils.js';

describe('SCA-User configured RP URL audience regression', () => {
  const previous = process.env.RP_URL;
  afterEach(() => { if (previous === undefined) delete process.env.RP_URL; else process.env.RP_URL = previous; });
  it('issues the RP URL rather than an issuer hostname identifier, without disclosures', () => {
    process.env.RP_URL = 'https://bank.example/service';
    const payload = createTs12ScaUserAttestationPayload('https://issuer.example');
    expect(payload.claims.aud).to.equal(process.env.RP_URL);
    expect(payload.disclosureFrame).to.deep.equal({});
  });
  it('refuses issuance without an explicitly configured HTTPS RP URL', () => {
    for (const value of ['', 'http://bank.example', 'x509_hash:abc', 'https:bank.example', 'https://user:password@bank.example', 'https://bank.example/#fragment']) {
      process.env.RP_URL = value;
      expect(() => createTs12ScaUserAttestationPayload()).to.throw(/RP_URL/);
    }
  });
  for (const responseMode of ['direct_post.jwt', 'dc_api.jwt']) {
    for (const trustFramework of [false, true]) {
      it(`accepts freshly issued URL aud and rejects another RP for ${responseMode}, trust=${trustFramework}`, () => {
        process.env.RP_URL = 'https://bank.example/service';
        const { claims } = createTs12ScaUserAttestationPayload();
        const encoded = encodeTs12TransactionData(buildTs12PaymentTransactionData({}, 'sca_user'));
        const input = {
          kbPayload: { jti: 'fresh-jti', response_mode: responseMode, amr: [{ knowledge: 'pin_6_or_more_digits' }, { inherence: 'fingerprint_device' }], transaction_data_hashes: [computeTs12TransactionDataHash(encoded)], transaction_data_hashes_alg: 'sha-256' },
          extractedClaims: [{ ...claims, vct: TS12_SCA_USER_VCT }],
          vpSession: { client_id: 'x509_hash:certificate', ts12_rp_url: process.env.RP_URL, ts12_expected_vct: TS12_SCA_USER_VCT, response_mode: responseMode, transaction_data: [encoded], trustFramework },
        };
        process.env.RP_URL = 'https://changed.example';
        expect(validateTs12PaymentPresentationResponse(input).ok).to.equal(true);
        input.extractedClaims[0].aud = 'https://other.example';
        expect(validateTs12PaymentPresentationResponse(input).code).to.equal('aud_mismatch');
        input.extractedClaims[0].aud = 'https://bank.example/service';
        delete input.vpSession.ts12_rp_url;
        input.rpClientId = 'https://bank.example/service';
        expect(validateTs12PaymentPresentationResponse(input).ok).to.equal(false);
      });
    }
  }
});
