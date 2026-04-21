import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { decodeProtectedHeader, decodeJwt } from "jose";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import {
  resolveAttestationForEndpoint,
  buildWalletUnitAttestationJwt,
  shouldRetryTokenExchangeAfterRotatingWalletProviderKey,
  rotateWalletProviderKeyPair,
} from "../src/lib/walletProviderIdentity.js";

describe("wallet provider identity (RFC001 iss / OAuth attestation)", () => {
  let tmpKey;
  const saved = {};

  beforeEach(() => {
    for (const k of [
      "WALLET_PROVIDER_KEY_PATH",
      "WALLET_PROVIDER_ID",
      "WALLET_INSTANCE_ID",
      "WALLET_USE_EXTERNAL_ATTESTATION",
      "WALLET_PROVIDER_CONFIG",
    ]) {
      saved[k] = process.env[k];
    }
    tmpKey = path.join(os.tmpdir(), `wp-ec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    process.env.WALLET_PROVIDER_KEY_PATH = tmpKey;
    process.env.WALLET_PROVIDER_ID = "did:example:wallet-provider";
    process.env.WALLET_INSTANCE_ID = "11111111-1111-1111-1111-111111111111";
    delete process.env.WALLET_USE_EXTERNAL_ATTESTATION;
    delete process.env.WALLET_PROVIDER_CONFIG;
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

  it("resolveAttestationForEndpoint: client_assertion uses typ oauth-client-attestation+jwt (token/PAR)", async () => {
    const { clientAssertionJwt, oauthHeaders } = await resolveAttestationForEndpoint({
      endpointAudience: "https://as.example/token",
      authorizationServerIssuer: "https://as.example",
    });
    const h = decodeProtectedHeader(clientAssertionJwt);
    const p = decodeJwt(clientAssertionJwt);
    expect(h.typ).to.equal("oauth-client-attestation+jwt");
    expect(p.sub).to.equal("11111111-1111-1111-1111-111111111111");
    expect(p.iss).to.equal("did:example:wallet-provider");
    expect(oauthHeaders["OAuth-Client-Attestation"]).to.be.a("string");
    expect(oauthHeaders["OAuth-Client-Attestation-PoP"]).to.be.a("string");
    const popH = decodeProtectedHeader(oauthHeaders["OAuth-Client-Attestation-PoP"]);
    expect(popH.typ).to.equal("oauth-client-attestation-pop+jwt");
  });

  it("buildWalletUnitAttestationJwt: typ key-attestation+jwt; iss = Wallet Provider; sub = instance id", async () => {
    const { publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const jwt = await buildWalletUnitAttestationJwt({
      credentialEndpoint: "https://issuer/credential",
      proofPublicJwk: publicJwk,
      eudiWalletInfo: {
        general_info: { name: "t", version: "1" },
        key_storage_info: { storage_type: "software", protection_level: "software" },
      },
    });
    const h = decodeProtectedHeader(jwt);
    const p = decodeJwt(jwt);
    expect(h.typ).to.equal("key-attestation+jwt");
    expect(p.iss).to.equal("did:example:wallet-provider");
    expect(p.sub).to.equal("11111111-1111-1111-1111-111111111111");
  });

  it("shouldRetryTokenExchangeAfterRotatingWalletProviderKey: true for invalid_client + expired WIA description", () => {
    expect(
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(400, {
        error: "invalid_client",
        error_description: "WIA JWT has expired. See spec.",
      }),
    ).to.equal(true);
    expect(
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(400, {
        error: "invalid_dpop_proof",
        error_description: "OAuth pop jwt expired",
      }),
    ).to.equal(true);
  });

  it("shouldRetryTokenExchangeAfterRotatingWalletProviderKey: false for non-matching errors", () => {
    expect(
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(401, {
        error: "invalid_client",
        error_description: "WIA JWT has expired",
      }),
    ).to.equal(false);
    expect(
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(400, {
        error: "invalid_grant",
        error_description: "WIA JWT has expired",
      }),
    ).to.equal(false);
    expect(
      shouldRetryTokenExchangeAfterRotatingWalletProviderKey(400, {
        error: "invalid_client",
        error_description: "client_id does not match attestation sub",
      }),
    ).to.equal(false);
  });

  it("rotateWalletProviderKeyPair replaces persisted key material", async () => {
    await resolveAttestationForEndpoint({
      endpointAudience: "https://as.example/token",
      authorizationServerIssuer: "https://as.example",
    });
    const j1 = JSON.parse(fs.readFileSync(tmpKey, "utf8"));
    const rotated = await rotateWalletProviderKeyPair();
    expect(rotated).to.equal(true);
    const j2 = JSON.parse(fs.readFileSync(tmpKey, "utf8"));
    expect(j2.privateJwk.x).to.not.equal(j1.privateJwk.x);
  });

  it("buildWalletUnitAttestationJwt: proofPublicJwks yields multiple attested_keys", async () => {
    const a = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const b = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const jwt = await buildWalletUnitAttestationJwt({
      credentialEndpoint: "https://issuer/credential",
      proofPublicJwks: [a.publicJwk, b.publicJwk],
      eudiWalletInfo: {
        general_info: { name: "t", version: "1" },
        key_storage_info: { storage_type: "software", protection_level: "software" },
      },
    });
    const p = decodeJwt(jwt);
    expect(p.attested_keys).to.be.an("array");
    expect(p.attested_keys).to.have.length(2);
  });
});
