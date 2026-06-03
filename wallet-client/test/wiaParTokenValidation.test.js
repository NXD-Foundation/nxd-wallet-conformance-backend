import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { decodeJwt } from "jose";
import { createWiaJwt, createWiaPopJwt, ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { validateWiaMaterialForParOrToken } from "../src/lib/wiaParTokenValidation.js";
import { resolveWiaForParOrToken } from "../src/lib/walletProviderIdentity.js";

describe("WIA local validation (RFC001 Phase 3)", () => {
  let tmpKey;
  const saved = {};

  beforeEach(async () => {
    for (const k of ["WALLET_PROVIDER_KEY_PATH", "WALLET_PROVIDER_ID", "WALLET_INSTANCE_ID"]) {
      saved[k] = process.env[k];
    }
    tmpKey = path.join(os.tmpdir(), `wp-ec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    process.env.WALLET_PROVIDER_KEY_PATH = tmpKey;
    process.env.WALLET_PROVIDER_ID = "did:example:wallet-provider";
    process.env.WALLET_INSTANCE_ID = "11111111-1111-1111-1111-111111111111";
  });

  afterEach(() => {
    try {
      fs.unlinkSync(tmpKey);
    } catch {
      // ignore
    }
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  async function mintWiaPair({ endpointAudience, authorizationServerIssuer, instanceId }) {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(tmpKey, "ES256");
    const wiaJwt = await createWiaJwt({
      privateJwk,
      publicJwk,
      issuer: "did:example:wallet-provider",
      subject: instanceId,
      audience: endpointAudience,
      cnfJwk: publicJwk,
    });
    const wiaPopJwt = await createWiaPopJwt({
      privateJwk,
      publicJwk,
      issuer: instanceId,
      audience: authorizationServerIssuer,
    });
    return { wiaJwt, wiaPopJwt };
  }

  it("validateWiaMaterialForParOrToken accepts matching aud, PoP aud, and client_id", async () => {
    const endpoint = "https://as.example/par";
    const asIssuer = "https://as.example";
    const instanceId = "11111111-1111-1111-1111-111111111111";
    const { wiaJwt, wiaPopJwt } = await mintWiaPair({
      endpointAudience: endpoint,
      authorizationServerIssuer: asIssuer,
      instanceId,
    });
    const result = await validateWiaMaterialForParOrToken({
      wiaJwt,
      wiaPopJwt,
      endpointAudience: endpoint,
      authorizationServerIssuer: asIssuer,
      clientId: instanceId,
    });
    expect(result.walletInstanceId).to.equal(instanceId);
    expect(result.walletProviderId).to.equal("did:example:wallet-provider");
  });

  it("rejects WIA aud mismatch with endpoint audience", async () => {
    const { wiaJwt, wiaPopJwt } = await mintWiaPair({
      endpointAudience: "https://as.example/token",
      authorizationServerIssuer: "https://as.example",
      instanceId: "11111111-1111-1111-1111-111111111111",
    });
    let err = null;
    try {
      await validateWiaMaterialForParOrToken({
        wiaJwt,
        wiaPopJwt,
        endpointAudience: "https://as.example/par",
        authorizationServerIssuer: "https://as.example",
        clientId: "11111111-1111-1111-1111-111111111111",
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect(String(err.message)).to.match(/wia_aud_mismatch/);
  });

  it("rejects client_id that does not match WIA sub", async () => {
    const endpoint = "https://as.example/token";
    const { wiaJwt, wiaPopJwt } = await mintWiaPair({
      endpointAudience: endpoint,
      authorizationServerIssuer: "https://as.example",
      instanceId: "11111111-1111-1111-1111-111111111111",
    });
    let err = null;
    try {
      await validateWiaMaterialForParOrToken({
        wiaJwt,
        wiaPopJwt,
        endpointAudience: endpoint,
        authorizationServerIssuer: "https://as.example",
        clientId: "other-client-id",
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect(String(err.message)).to.match(/wia_client_id_mismatch/);
  });

  it("rejects PoP iss that does not match WIA sub", async () => {
    const endpoint = "https://as.example/token";
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(tmpKey, "ES256");
    const wiaJwt = await createWiaJwt({
      privateJwk,
      publicJwk,
      issuer: "did:example:wallet-provider",
      subject: "11111111-1111-1111-1111-111111111111",
      audience: endpoint,
      cnfJwk: publicJwk,
    });
    const wiaPopJwt = await createWiaPopJwt({
      privateJwk,
      publicJwk,
      issuer: "wrong-instance-id",
      audience: "https://as.example",
    });
    let err = null;
    try {
      await validateWiaMaterialForParOrToken({
        wiaJwt,
        wiaPopJwt,
        endpointAudience: endpoint,
        authorizationServerIssuer: "https://as.example",
        clientId: "11111111-1111-1111-1111-111111111111",
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect(String(err.message)).to.match(/wia_pop_iss_mismatch/);
  });

  it("resolveWiaForParOrToken validates before returning headers", async () => {
    const wia = await resolveWiaForParOrToken({
      endpointAudience: "https://as.example/token",
      authorizationServerIssuer: "https://as.example",
      clientId: "11111111-1111-1111-1111-111111111111",
    });
    expect(wia.wiaHeaders["OAuth-Client-Attestation"]).to.be.a("string");
    expect(wia.wiaHeaders["OAuth-Client-Attestation-PoP"]).to.be.a("string");
    const p = decodeJwt(wia.wiaJwt);
    expect(p.sub).to.equal("11111111-1111-1111-1111-111111111111");
    expect(p.aud).to.equal("https://as.example/token");
  });
});
