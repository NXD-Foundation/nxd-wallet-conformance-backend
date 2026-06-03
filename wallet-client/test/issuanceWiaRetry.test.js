import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { exchangeToken } from "../src/lib/issuance.js";
import {
  resolveWiaForParOrToken,
  rotateWalletProviderKeyPair,
  shouldRetryTokenExchangeAfterRotatingWalletProviderKey,
} from "../src/lib/walletProviderIdentity.js";
import { ensureOrCreateEcKeyPair, createDPoP } from "../src/lib/crypto.js";

describe("issuance WIA retry (RFC001 Phase 3)", () => {
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

  it("token retry after WP rotation regenerates WIA (resolveWia called twice)", async () => {
    let wiaResolveCount = 0;
    const wiaJwts = [];

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
      resolveWiaForParOrToken: async (opts) => {
        wiaResolveCount += 1;
        const wia = await resolveWiaForParOrToken(opts);
        wiaJwts.push(wia.wiaJwt);
        return wia;
      },
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey,
      rotateWalletProviderKeyPair,
      postForm: async () => ({
        ok: false,
        status: 400,
        text: async () =>
          JSON.stringify({
            error: "invalid_client",
            error_description: "WIA JWT has expired",
          }),
      }),
      deviceKeyPath: tmpDeviceKey,
    }).catch(() => {});

    expect(wiaResolveCount).to.equal(2);
    expect(wiaJwts).to.have.length(2);
    expect(wiaJwts[0]).to.not.equal(wiaJwts[1]);
  });
});
