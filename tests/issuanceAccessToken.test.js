import { strict as assert } from 'node:assert';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { assertIssuanceAccessTokenActive } from '../utils/issuanceAccessToken.js';

describe('issuance access-token lifetime independent of refresh retention', () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuer = 'https://issuer.example';
  const now = 2000000000000;
  const options = { publicKey: keys.publicKey, issuer, now, session: { refreshBinding: {} } };
  const token = claims => jwt.sign({ iss: issuer, aud: issuer, ...claims }, keys.privateKey, { algorithm: 'ES256' });
  const rejects = accessToken => assert.throws(() => assertIssuanceAccessTokenActive({ ...options, accessToken }), { errorCode: 'invalid_token' });

  it('accepts a valid issuer token while rejecting its expired version on a retained session', () => {
    assertIssuanceAccessTokenActive({ ...options, accessToken: token({ exp: now / 1000 + 60 }) });
    rejects(token({ exp: now / 1000 - 1 }));
  });

  it('rejects missing expiry, wrong audience, and a signature from another issuer key', () => {
    rejects(token({}));
    rejects(token({ exp: now / 1000 + 60, aud: 'https://another.example' }));
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    rejects(jwt.sign({ iss: issuer, aud: issuer, exp: now / 1000 + 60 }, other.privateKey, { algorithm: 'ES256' }));
  });

  it('requires an explicit active expiry for opaque tokens on refresh-enabled sessions', () => {
    rejects('opaque');
    assertIssuanceAccessTokenActive({ ...options, accessToken: 'opaque', session: { refreshBinding: {}, accessTokenExpiresAt: now + 60000 } });
    assert.throws(() => assertIssuanceAccessTokenActive({ ...options, accessToken: 'opaque', session: { refreshBinding: {}, accessTokenExpiresAt: now } }), { errorCode: 'invalid_token' });
  });
});
