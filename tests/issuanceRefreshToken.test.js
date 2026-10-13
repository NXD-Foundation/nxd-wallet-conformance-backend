import { expect } from "chai";
import sinon from "sinon";
import * as jose from "jose";
import { v4 as uuidv4 } from "uuid";
import * as cacheServiceRedis from "../services/cacheServiceRedis.js";
import {
  persistRefreshBindingForIssuance,
  handleRefreshTokenGrant,
  commitRefreshTokenRotation,
  resolveTokenSessionPersistence,
  mapIssuanceTokenError,
  resolveIssuanceCredentialConfigurationIds,
} from "../utils/issuanceRefreshToken.js";
import { loadCryptographicKeys } from "../utils/routeUtils.js";

const PRE_AUTHORIZED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

describe("issuance refresh token lifetime and persistence", () => {
  it("binds the selected offered configuration and rejects unoffered configurations", () => {
    const session = { credentialConfigurationId: 'primary', requestedCredentialConfigurationIds: ['primary', 'selected'] };
    expect(resolveIssuanceCredentialConfigurationIds(session, [{ credential_configuration_id: 'selected' }])).to.deep.equal(['selected']);
    expect(() => resolveIssuanceCredentialConfigurationIds(session, [{ credential_configuration_id: 'other' }])).to.throw();
    expect(resolveIssuanceCredentialConfigurationIds(session)).to.deep.equal(['primary', 'selected']);
  });

  it("maps a rejected stale token-session save to invalid_grant", () => {
    expect(mapIssuanceTokenError(Object.assign(new Error('stale'), { errorCode: 'stale_issuance_session' }))).to.deep.equal({ status: 400, body: { error: 'invalid_grant', error_description: 'stale' } });
  });
  it("keeps the issuance session alive for the refresh-token lifetime", function () {
    if (process.env.ISSUANCE_REFRESH_SESSION_TTL_SECONDS || process.env.ISSUANCE_REFRESH_TOKEN_TTL_SECONDS) {
      this.skip();
    }
    expect(cacheServiceRedis.issuanceRefreshSessionTtlSeconds()).to.equal(
      cacheServiceRedis.issuanceRefreshTokenTtlSeconds(),
    );
    expect(cacheServiceRedis.issuanceRefreshSessionTtlSeconds()).to.equal(86400 * 30);
  });

  it("keeps the old binding when atomic storage fails", async () => {
    const session = { refreshBinding: { token: "old", dpopJkt: "jkt", clientId: "wallet-client" } };
    const original = { ...session.refreshBinding };
    try {
      await commitRefreshTokenRotation({ refreshTokenValue: "old", newRefreshToken: "new", session,
        mapping: { sessionKey: "session-1", flowType: "pre-auth" }, boundClientId: "wallet-client",
        rotate: async () => { throw new Error("storage failed"); },
      });
      expect.fail("expected storage failure");
    } catch (error) { expect(error.message).to.equal("storage failed"); }
    expect(session.refreshBinding).to.deep.equal(original);
  });

  it("rejects a competing rotation instead of returning an unusable new token", async () => {
    const session = { refreshBinding: { token: "old", dpopJkt: "jkt", clientId: "wallet-client" } };
    try {
      await commitRefreshTokenRotation({ refreshTokenValue: "old", newRefreshToken: "new", session,
        mapping: { sessionKey: "session-1", flowType: "pre-auth" }, boundClientId: "wallet-client",
        rotate: async () => false,
      });
      expect.fail("expected invalid_grant");
    } catch (error) { expect(error.errorCode).to.equal("invalid_grant"); }
    expect(session.refreshBinding.token).to.equal("old");
  });

  it("preserves the remaining refresh lifetime on ordinary session saves", () => {
    const clock = sinon.useFakeTimers({ now: 1000000, toFake: ["Date"] });
    try {
      expect(cacheServiceRedis.resolveIssuanceSessionTtl({ refreshBinding: { expiresAt: Date.now() + 900000 } })).to.equal(900);
      expect(cacheServiceRedis.resolveIssuanceSessionTtl({}, {}, 180)).to.equal(180);
    } finally { clock.restore(); }
  });

  it("writes a pre-authorized refresh back to the pre-auth session key", () => {
    const persistence = resolveTokenSessionPersistence({
      grantType: "refresh_token",
      preAuthorizedCode: undefined,
      refreshMapping: { sessionKey: "pre-auth-session", flowType: "pre-auth" },
    });
    expect(persistence).to.deep.equal({
      namespace: "pre-auth",
      preAuthSessionKey: "pre-auth-session",
    });
    expect(
      resolveTokenSessionPersistence({
        grantType: PRE_AUTHORIZED_GRANT_TYPE,
        preAuthorizedCode: "offer-code",
        refreshMapping: null,
      }).namespace,
    ).to.equal("pre-auth");
    expect(
      resolveTokenSessionPersistence({
        grantType: "refresh_token",
        refreshMapping: { sessionKey: "code-session", flowType: "code" },
      }).namespace,
    ).to.equal("code");
  });

  it("maps a refresh client mismatch to invalid_client instead of a server error", () => {
    const mapped = mapIssuanceTokenError(
      Object.assign(new Error("Refresh token client identity does not match the original issuance session"), {
        errorCode: "invalid_client",
      }),
    );
    expect(mapped.status).to.equal(401);
    expect(mapped.body.error).to.equal("invalid_client");
    expect(mapIssuanceTokenError(Object.assign(new Error("boom"), { errorCode: "server_error" }))).to.equal(null);
  });
});

describe("issuance refresh token grant", () => {
  before(async function () {
    if (process.env.REDIS) {
      await new Promise((resolve) => cacheServiceRedis.client.isReady ? resolve() : cacheServiceRedis.client.once("ready", resolve));
    }
    if (!cacheServiceRedis.client.isReady) {
      this.skip();
    }
  });

  it("rotates refresh token and preserves DPoP binding on successful refresh", async () => {
    const sessionKey = `refresh-test-${uuidv4()}`;
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const publicJwk = await jose.exportJWK(publicKey);
    const dpopJkt = await jose.calculateJwkThumbprint(publicJwk, "sha256");
    const initialRefresh = `rt-${uuidv4()}`;
    const session = {
      status: "pending",
      accessToken: null,
      tokenClientId: "wallet-client",
    };
    await persistRefreshBindingForIssuance({
      session,
      sessionKey,
      flowType: "pre-auth",
      refreshToken: initialRefresh,
      dpopCnf: { jkt: dpopJkt },
      tokenClientBinding: { tokenClientId: "wallet-client", anonymousAccess: false },
    });

    const dpopJwt = await new jose.SignJWT({
      htu: "http://localhost:3000/token_endpoint",
      htm: "POST",
      iat: Math.floor(Date.now() / 1000),
      jti: uuidv4(),
    })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
      .sign(privateKey);

    const { payload } = await jose.jwtVerify(dpopJwt, await jose.importJWK(publicJwk, "ES256"));
    expect(payload.htm).to.equal("POST");

    const keys = loadCryptographicKeys();
    const tokenResponse = await handleRefreshTokenGrant({
      refreshTokenValue: initialRefresh,
      dpopCnf: { jkt: dpopJkt },
      tokenClientBinding: { tokenClientId: "wallet-client", anonymousAccess: false },
      serverUrl: "http://localhost:3000",
      signingPrivateKey: keys.privateKey,
      tokenExpiresIn: 3600,
    });

    expect(tokenResponse.token_type).to.equal("DPoP");
    expect(tokenResponse.refresh_token).to.be.a("string").and.not.equal(initialRefresh);
    expect(await cacheServiceRedis.lookupIssuanceRefreshToken(initialRefresh)).to.equal(null);
    expect(await cacheServiceRedis.lookupIssuanceRefreshToken(tokenResponse.refresh_token)).to.have.property(
      "sessionKey",
      sessionKey,
    );

    const stored = await cacheServiceRedis.getPreAuthSession(sessionKey);
    expect(stored.refreshBinding.token).to.equal(tokenResponse.refresh_token);
    expect(stored.c_nonce).to.be.a("string");
    expect(await cacheServiceRedis.checkNonce(tokenResponse.c_nonce)).to.equal(true);
  });

  it("does not consume refresh token when DPoP key mismatches", async () => {
    const sessionKey = `refresh-mismatch-${uuidv4()}`;
    const { publicKey: keyA } = await jose.generateKeyPair("ES256");
    const { publicKey: keyB } = await jose.generateKeyPair("ES256");
    const jktA = await jose.calculateJwkThumbprint(await jose.exportJWK(keyA), "sha256");
    const refresh = `rt-${uuidv4()}`;
    const session = { status: "pending", tokenClientId: "wallet-client" };
    await persistRefreshBindingForIssuance({
      session,
      sessionKey,
      flowType: "pre-auth",
      refreshToken: refresh,
      dpopCnf: { jkt: jktA },
      tokenClientBinding: { tokenClientId: "wallet-client", anonymousAccess: false },
    });

    try {
      await handleRefreshTokenGrant({
        refreshTokenValue: refresh,
        dpopCnf: { jkt: await jose.calculateJwkThumbprint(await jose.exportJWK(keyB), "sha256") },
        tokenClientBinding: { tokenClientId: "wallet-client", anonymousAccess: false },
        serverUrl: "http://localhost:3000",
        signingPrivateKey: loadCryptographicKeys().privateKey,
        tokenExpiresIn: 3600,
      });
      expect.fail("expected mismatch rejection");
    } catch (error) {
      expect(error.errorCode).to.equal("invalid_dpop_proof");
    }
    expect(await cacheServiceRedis.lookupIssuanceRefreshToken(refresh)).to.have.property("sessionKey", sessionKey);
  });
  for (const flowType of ["code", "pre-auth"]) {
    it(`retains refresh lifetime after ${flowType} credential/status saves`, async () => {
      const sessionKey = `refresh-ttl-${uuidv4()}`;
      const session = { status: "pending", tokenClientId: "wallet-client" };
      await persistRefreshBindingForIssuance({ session, sessionKey, flowType, refreshToken: uuidv4(),
        dpopCnf: { jkt: "key" }, tokenClientBinding: { tokenClientId: "wallet-client" } });
      session.status = "success";
      await (flowType === "code" ? cacheServiceRedis.storeCodeFlowSession : cacheServiceRedis.storePreAuthSession)(sessionKey, session);
      const key = `${flowType === "code" ? "code-flow" : "pre-auth"}-sessions:${sessionKey}`;
      expect(await cacheServiceRedis.client.ttl(key)).to.be.greaterThan(86400 * 29);
    });
  }

  it("allows only one concurrent redemption of the same refresh token", async () => {
    const sessionKey = `refresh-race-${uuidv4()}`;
    const token = uuidv4();
    await persistRefreshBindingForIssuance({ session: { tokenClientId: "wallet-client" }, sessionKey,
      flowType: "code", refreshToken: token, dpopCnf: { jkt: "key" },
      tokenClientBinding: { tokenClientId: "wallet-client" } });
    const options = { refreshTokenValue: token, dpopCnf: { jkt: "key" },
      tokenClientBinding: { tokenClientId: "wallet-client" }, serverUrl: "http://localhost:3000",
      signingPrivateKey: loadCryptographicKeys().privateKey, tokenExpiresIn: 3600 };
    const results = await Promise.allSettled([handleRefreshTokenGrant(options), handleRefreshTokenGrant(options)]);
    const success = results.filter(r => r.status === "fulfilled");
    expect(success).to.have.length(1);
    expect(results.find(r => r.status === "rejected").reason.errorCode).to.equal("invalid_grant");
    const saved = await cacheServiceRedis.getCodeFlowSession(sessionKey);
    expect(saved.refreshBinding.token).to.equal(success[0].value.refresh_token);
    expect(await cacheServiceRedis.lookupIssuanceRefreshToken(token)).to.equal(null);
  });

  it("propagates code session storage failures instead of silently succeeding", async () => {
    const stub = sinon.stub(cacheServiceRedis.client, "eval").rejects(new Error("write failed"));
    try {
      await cacheServiceRedis.storeCodeFlowSession("failing-write", {});
      expect.fail("expected failure");
    } catch (error) { expect(error.message).to.equal("write failed"); }
    finally { stub.restore(); }
  });

  it("rejects an expired binding even if the Redis mapping has not expired yet", async () => {
    const sessionKey = `expired-binding-${uuidv4()}`;
    const refreshToken = uuidv4();
    await persistRefreshBindingForIssuance({ session: { tokenClientId: "wallet-client" }, sessionKey,
      flowType: "pre-auth", refreshToken, dpopCnf: { jkt: "key" }, tokenClientBinding: { tokenClientId: "wallet-client" } });
    const session = await cacheServiceRedis.getPreAuthSession(sessionKey);
    session.refreshBinding.expiresAt = Date.now() - 1000;
    await cacheServiceRedis.storePreAuthSession(sessionKey, session);
    try {
      await handleRefreshTokenGrant({ refreshTokenValue: refreshToken, dpopCnf: { jkt: "key" }, tokenClientBinding: { tokenClientId: "wallet-client" } });
      expect.fail("expected invalid_grant");
    } catch (error) { expect(error.errorCode).to.equal("invalid_grant"); }
  });

  for (const flowType of ['code', 'pre-auth']) {
    it(`does not let a stale ${flowType} credential save restore a rotated binding`, async () => {
      const sessionKey = `stale-write-${uuidv4()}`;
      const initial = uuidv4();
      await persistRefreshBindingForIssuance({ session: { status: 'pending', tokenClientId: 'wallet' }, sessionKey,
        flowType, refreshToken: initial, dpopCnf: { jkt: 'key' }, tokenClientBinding: { tokenClientId: 'wallet' } });
      const load = flowType === 'code' ? cacheServiceRedis.getCodeFlowSession : cacheServiceRedis.getPreAuthSession;
      const save = flowType === 'code' ? cacheServiceRedis.storeCodeFlowSession : cacheServiceRedis.storePreAuthSession;
      const stale = await load(sessionKey);
      const options = { dpopCnf: { jkt: 'key' }, tokenClientBinding: { tokenClientId: 'wallet' },
        serverUrl: 'http://localhost:3000', signingPrivateKey: loadCryptographicKeys().privateKey, tokenExpiresIn: 3600 };
      const refreshed = await handleRefreshTokenGrant({ ...options, refreshTokenValue: initial });
      for (const snapshot of [stale, { ...stale, refreshBinding: undefined }]) {
        try { await save(sessionKey, snapshot); expect.fail('expected stale write rejection'); }
        catch (error) { expect(error.errorCode).to.equal('stale_issuance_session'); }
        expect((await load(sessionKey)).refreshBinding.token).to.equal(refreshed.refresh_token);
      }
      const next = await handleRefreshTokenGrant({ ...options, refreshTokenValue: refreshed.refresh_token });
      expect(next.refresh_token).not.to.equal(refreshed.refresh_token);
    });
  }

});
