import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { compactVerify, decodeProtectedHeader, exportJWK, generateKeyPair } from "jose";
import { resolveWiaForParOrToken, buildWalletUnitAttestationJwt } from "../src/lib/walletProviderIdentity.js";
import { validateWalletProviderCertificatePath } from "../../utils/keyAttestationX5cVerification.js";

const caPath = new URL("../x509EC/wallet_provider_ca.crt", import.meta.url);

function leafFromHeader(header) {
  assert.equal(header.jwk, undefined);
  assert.equal(header.x5c.length, 1);
  return new X509Certificate(Buffer.from(header.x5c[0], "base64"));
}

describe("Wallet Provider certificate chain for WIA and KA", () => {
  const saved = {};
  let deviceKeyPath;

  beforeEach(() => {
    for (const key of ["WALLET_PROVIDER_KEY_PATH", "WALLET_PROVIDER_ID", "WALLET_INSTANCE_ID", "WALLET_USE_EXTERNAL_ATTESTATION"]) {
      saved[key] = process.env[key];
    }
    deviceKeyPath = path.join(os.tmpdir(), `wp-chain-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    process.env.WALLET_PROVIDER_KEY_PATH = deviceKeyPath;
    process.env.WALLET_PROVIDER_ID = "did:example:wallet-provider";
    process.env.WALLET_INSTANCE_ID = "11111111-1111-1111-1111-111111111111";
    delete process.env.WALLET_USE_EXTERNAL_ATTESTATION;
  });

  afterEach(() => {
    fs.rmSync(deviceKeyPath, { force: true });
    for (const key of Object.keys(saved)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });

  it("signs WIA and KA with the leaf and leaves the CA for the issuer to anchor", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const deviceJwk = await exportJWK(publicKey);
    const devicePrivateJwk = await exportJWK(privateKey);
    const audience = "https://issuer.example/par";
    const wia = await resolveWiaForParOrToken({
      endpointAudience: audience,
      authorizationServerIssuer: "https://issuer.example",
      clientId: process.env.WALLET_INSTANCE_ID,
      cnfKeyPair: { publicJwk: deviceJwk, privateJwk: devicePrivateJwk },
    });
    const ka = await buildWalletUnitAttestationJwt({
      credentialEndpoint: "https://issuer.example/credential",
      proofPublicJwk: deviceJwk,
    });

    const ca = new X509Certificate(fs.readFileSync(caPath));
    for (const [label, jwt] of [["WIA", wia.wiaJwt], ["KA", ka]]) {
      const header = decodeProtectedHeader(jwt);
      const leaf = leafFromHeader(header);
      assert.equal(leaf.verify(ca.publicKey), true, `${label} leaf must be issued by the published CA`);
      assert.equal(header.x5c.includes(ca.raw.toString("base64")), false);
      await compactVerify(jwt, leaf.publicKey);
      validateWalletProviderCertificatePath({
        certificateChain: [leaf.toString()],
        anchorCertificates: [ca.toString()],
      });
    }
  });
});
