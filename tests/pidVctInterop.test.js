import { storedCredentialMatchesDcqlQuery } from '../wallet-client/src/lib/dcqlCredentialSelection.js';
import { expect } from 'chai';
import fs from 'fs';
import * as jose from 'jose';
import { handleCredentialGenerationBasedOnFormat, handleCredentialGenerationBasedOnFormatDeferred } from '../utils/credGenerationUtils.js';
import { parseSdJwtClaims } from '../utils/sdJwtClaims.js';
import { PID_SD_JWT_VCTS, DEFAULT_DCQL_QUERY, FULL_PID_DCQL_QUERY, PNR_PID_DCQL_QUERY, BOARDING_PASS_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_EDC_DCQL_QUERY, resolveVciOfferSignatureType } from '../utils/routeUtils.js';

describe('APTITUDE PID VCT interoperability', () => {
  it('advertises both issuance types and defaults both to x509', () => {
    const supported = JSON.parse(fs.readFileSync('./data/issuer-config.json')).credential_configurations_supported;
    for (const vct of PID_SD_JWT_VCTS) {
      expect(supported[vct].vct).to.equal(vct);
      expect(supported[vct].scope).to.equal(vct);
      expect(supported[vct].format).to.equal('dc+sd-jwt');
      expect(resolveVciOfferSignatureType({ query: {} }, vct)).to.equal('x509');
    }
  });

  it('accepts either PID VCT in every PID and combined preset', () => {
    for (const query of [DEFAULT_DCQL_QUERY, FULL_PID_DCQL_QUERY, PNR_PID_DCQL_QUERY, BOARDING_PASS_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_EDC_DCQL_QUERY]) {
      const pid = query.credentials.find(c => c.meta?.vct_values?.includes('urn:eu.europa.ec.eudi:pid:1'));
      expect(pid.meta.vct_values).to.deep.equal(PID_SD_JWT_VCTS);
    }
  });

  it('issues both VCTs with the same mock PID data, including deferred issuance', async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
    const jwk = await jose.exportJWK(publicKey);
    const proof = await new jose.SignJWT({ nonce: 'test', aud: 'https://issuer.example' })
      .setProtectedHeader({ alg: 'ES256', jwk }).sign(privateKey);
    for (const vct of PID_SD_JWT_VCTS) {
      const body = { vct, proofs: { jwt: [proof] } };
      const session = { signatureType: 'kid-jwk', isHaip: false, requestBody: body };
      const issued = await handleCredentialGenerationBasedOnFormat(body, session, 'https://issuer.example', 'dc+sd-jwt');
      const deferred = await handleCredentialGenerationBasedOnFormatDeferred(session, 'https://issuer.example', { jwk });
      for (const token of [issued, deferred]) {
        expect(jose.decodeJwt(token.split('~')[0]).vct).to.equal(vct);
        const { claims } = parseSdJwtClaims(token);
        expect(claims.given_name).to.equal('Hanna');
        expect(claims.family_name).to.equal('Matkalainen');
        expect(claims.birthdate).to.equal('2005-07-01');
        expect(claims.nationalities).to.deep.equal(['FI']);
        for (const query of [DEFAULT_DCQL_QUERY, FULL_PID_DCQL_QUERY, PNR_PID_DCQL_QUERY, BOARDING_PASS_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_DCQL_QUERY, BOOKING_REFERENCE_PID_EDC_DCQL_QUERY]) {
          const pid = query.credentials.find(c => c.meta?.vct_values?.includes(vct));
          expect(storedCredentialMatchesDcqlQuery(pid, token)).to.equal(true);
        }
      }
    }
  });
});
