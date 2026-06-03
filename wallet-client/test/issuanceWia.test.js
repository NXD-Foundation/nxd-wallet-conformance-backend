import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { exchangeToken } from "../src/lib/issuance.js";
import { resolveWiaForParOrToken } from "../src/lib/walletProviderIdentity.js";
import { ensureOrCreateEcKeyPair, createDPoP } from "../src/lib/crypto.js";

describe("issuance WIA request shape (RFC001 Phase 2)", () => {
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

  it("exchangeToken MUST NOT send client_assertion; MUST send validated WIA headers", async () => {
    const captured = [];
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
      postForm: async (url, params, dpopHeader, extraHeaders) => {
        captured.push({ url, params, dpopHeader, extraHeaders });
        return {
          ok: false,
          status: 400,
          text: async () => JSON.stringify({ error: "invalid_grant" }),
        };
      },
      deviceKeyPath: tmpDeviceKey,
    }).catch(() => {});

    expect(captured).to.have.length(1);
    expect(captured[0].params).to.not.have.property("client_assertion");
    expect(captured[0].params).to.not.have.property("client_assertion_type");
    expect(captured[0].extraHeaders["OAuth-Client-Attestation"]).to.be.a("string");
    expect(captured[0].extraHeaders["OAuth-Client-Attestation-PoP"]).to.be.a("string");
  });
});
