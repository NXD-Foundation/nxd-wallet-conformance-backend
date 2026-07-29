import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { ATTESTATION_CHALLENGE_HEADER } from "../src/lib/attestationChallenge.js";
import { exchangeToken } from "../src/lib/issuance.js";
import { resolveWiaForParOrToken } from "../src/lib/walletProviderIdentity.js";
import { ensureOrCreateEcKeyPair, createDPoP } from "../src/lib/crypto.js";
import { createAttestationChallengeState } from "../src/lib/attestationChallenge.js";
import { decodeJwt } from "jose";

describe("issuance attestation challenge retry (RFC001)", () => {
  let tmpKey;
  let tmpDeviceKey;
  const saved = {};

  beforeEach(() => {
    for (const k of ["WALLET_PROVIDER_KEY_PATH", "WALLET_PROVIDER_ID", "WALLET_INSTANCE_ID"]) {
      saved[k] = process.env[k];
    }
    tmpKey = path.join(os.tmpdir(), `wp-ec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    tmpDeviceKey = path.join(os.tmpdir(), `dev-ec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    process.env.WALLET_PROVIDER_KEY_PATH = tmpKey;
    process.env.WALLET_PROVIDER_ID = "did:example:wallet-provider";
    process.env.WALLET_INSTANCE_ID = "11111111-1111-1111-1111-111111111111";
  });

  afterEach(() => {
    for (const f of [tmpKey, tmpDeviceKey]) {
      try {
        fs.unlinkSync(f);
      } catch {
        // ignore
      }
    }
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("exchangeToken retries token request with challenge-bound WIA PoP", async () => {
    let postCount = 0;
    const dpopProofs = [];
    const challengeState = createAttestationChallengeState("initial-challenge");
    const result = await exchangeToken({
      tokenEndpoint: "https://as.example/token",
      tokenPayload: {
        grant_type: "authorization_code",
        code: "abc",
        client_id: "11111111-1111-1111-1111-111111111111",
      },
      authorizationServerIssuer: "https://as.example",
      ensureOrCreateEcKeyPair,
      createDPoP,
      resolveWiaForParOrToken,
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey: () => false,
      rotateWalletProviderKeyPair: async () => false,
      challengeState,
      postForm: async (_url, _params, dpopProof) => {
        postCount += 1;
        dpopProofs.push(dpopProof);
        if (postCount === 1) {
          return {
            ok: false,
            status: 400,
            headers: new Headers({
              [ATTESTATION_CHALLENGE_HEADER]: "retry-challenge-value",
            }),
            text: async () =>
              JSON.stringify({ error: "use_attestation_challenge", error_description: "retry" }),
          };
        }
        return {
          ok: true,
          status: 200,
          headers: new Headers(),
          text: async () => JSON.stringify({ access_token: "token-123", token_type: "DPoP" }),
        };
      },
      deviceKeyPath: tmpDeviceKey,
    });

    expect(postCount).to.equal(2);
    expect(dpopProofs).to.have.length(2);
    expect(dpopProofs[0]).to.be.a("string");
    expect(dpopProofs[1]).to.be.a("string");
    expect(dpopProofs[1]).to.not.equal(dpopProofs[0]);
    expect(decodeJwt(dpopProofs[1]).jti).to.not.equal(decodeJwt(dpopProofs[0]).jti);
    expect(result.tokenBody.access_token).to.equal("token-123");
    expect(challengeState.current).to.equal("retry-challenge-value");
  });

  it("exchangeToken does not crash when challengeState is omitted on attestation retry", async () => {
    let postCount = 0;
    try {
      await exchangeToken({
        tokenEndpoint: "https://as.example/token",
        tokenPayload: {
          grant_type: "authorization_code",
          code: "abc",
          client_id: "11111111-1111-1111-1111-111111111111",
        },
        authorizationServerIssuer: "https://as.example",
        ensureOrCreateEcKeyPair,
        createDPoP,
        resolveWiaForParOrToken,
        shouldRetryTokenExchangeAfterRotatingWalletProviderKey: () => false,
        rotateWalletProviderKeyPair: async () => false,
        postForm: async () => {
          postCount += 1;
          return {
            ok: false,
            status: 400,
            headers: new Headers({
              [ATTESTATION_CHALLENGE_HEADER]: "retry-challenge-value",
            }),
            text: async () =>
              JSON.stringify({ error: "use_attestation_challenge", error_description: "retry" }),
          };
        },
        deviceKeyPath: tmpDeviceKey,
      });
      expect.fail("expected exchangeToken to reject");
    } catch (error) {
      expect(error.message).to.match(/token_error 400/);
    }
    expect(postCount).to.equal(1);
  });

  it("resolveWiaForParOrToken embeds challenge in WIA PoP JWT", async () => {
    const wia = await resolveWiaForParOrToken({
      endpointAudience: "https://as.example/par",
      authorizationServerIssuer: "https://as.example",
      clientId: "11111111-1111-1111-1111-111111111111",
      challenge: "bound-challenge",
    });
    const popPayload = decodeJwt(wia.wiaPopJwt);
    expect(popPayload.challenge).to.equal("bound-challenge");
  });

  it("resolveWiaForParOrToken rejects external attestation with challenge", async () => {
    const savedExternal = process.env.WALLET_USE_EXTERNAL_ATTESTATION;
    const savedHeader = process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION;
    const savedPop = process.env.WALLET_EXTERNAL_OAUTH_POP;
    process.env.WALLET_USE_EXTERNAL_ATTESTATION = "1";
    process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION = "external.wia.jwt";
    process.env.WALLET_EXTERNAL_OAUTH_POP = "external.pop.jwt";
    try {
      await resolveWiaForParOrToken({
        endpointAudience: "https://as.example/token",
        authorizationServerIssuer: "https://as.example",
        clientId: "11111111-1111-1111-1111-111111111111",
        challenge: "retry-challenge",
      });
      expect.fail("expected resolveWiaForParOrToken to reject external WIA with challenge");
    } catch (error) {
      expect(error.message).to.match(/not supported with WALLET_USE_EXTERNAL_ATTESTATION/i);
    } finally {
      if (savedExternal === undefined) delete process.env.WALLET_USE_EXTERNAL_ATTESTATION;
      else process.env.WALLET_USE_EXTERNAL_ATTESTATION = savedExternal;
      if (savedHeader === undefined) delete process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION;
      else process.env.WALLET_EXTERNAL_OAUTH_ATTESTATION = savedHeader;
      if (savedPop === undefined) delete process.env.WALLET_EXTERNAL_OAUTH_POP;
      else process.env.WALLET_EXTERNAL_OAUTH_POP = savedPop;
    }
  });
});
