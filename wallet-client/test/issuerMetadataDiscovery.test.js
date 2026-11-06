import { expect } from "chai";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import forge from "node-forge";
import { SignJWT, importPKCS8 } from "jose";

// Prevent importing the Express app from starting its listener in this unit test.
process.env.NODE_ENV = "test";
const { discoverIssuerMetadata, isDirectWalletTrustEnabled } = await import("../src/server.js");

async function signedIssuerMetadata(payload) {
  const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../tests/fixtures/trust/webuild-wp4/keys");
  const certificate = forge.pki.certificateFromPem(await fs.readFile(path.join(dir, "pid.crt"), "utf8"));
  const privateKey = forge.pki.privateKeyFromPem(await fs.readFile(path.join(dir, "pid.key"), "utf8"));
  const leaf = forge.pki.certificateToPem(certificate).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await importPKCS8(forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(privateKey))), "RS256");
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "openidvci-issuer-metadata+jwt", x5c: [leaf] })
    .setIssuedAt()
    .sign(key);
}

describe("wallet issuer metadata discovery", () => {
  it("does not enable direct-route trust setup for string false", () => {
    expect(isDirectWalletTrustEnabled("false")).to.equal(false);
    expect(isDirectWalletTrustEnabled(false)).to.equal(false);
    expect(isDirectWalletTrustEnabled("true")).to.equal(true);
  });

  it("retries JSON metadata when signed metadata is unavailable", async () => {
    const accepts = [];
    const metadata = {
      credential_issuer: "https://issuer.example",
      credential_endpoint: "https://issuer.example/credential",
    };
    const result = await discoverIssuerMetadata("https://issuer.example", null, async (_url, options) => {
      accepts.push(options.headers.Accept);
      if (options.headers.Accept.includes("application/jwt")) {
        return { ok: false, status: 503, headers: { get: () => "application/problem+json" } };
      }
      return {
        ok: true,
        status: 200,
        headers: { get: () => "application/json" },
        json: async () => metadata,
      };
    });
    expect(accepts).to.deep.equal(["application/jwt, application/json", "application/json"]);
    expect(result).to.deep.equal(metadata);
  });

  it("does not downgrade to JSON when trust-enabled signed metadata is unavailable", async () => {
    const accepts = [];
    let error;
    try {
      await discoverIssuerMetadata("https://issuer.example", null, async (_url, options) => {
        accepts.push(options.headers.Accept);
        return { ok: false, status: 503, headers: { get: () => "application/json" } };
      }, { trustSession: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } } });
    } catch (e) { error = e; }
    expect(error).to.be.instanceOf(Error);
    expect(accepts).to.deep.equal(["application/jwt"]);
  });

  it("rejects an unsigned response even when a server ignores the JWT accept header", async () => {
    let error;
    try {
      await discoverIssuerMetadata("https://issuer.example", null, async () => ({
        ok: true, status: 200, headers: { get: () => "application/json" },
        json: async () => ({ credential_issuer: "https://issuer.example" }),
      }), { trustSession: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } } });
    } catch (e) { error = e; }
    expect(error?.message).to.include("signed issuer metadata is required");
  });

  it("accepts a credential_issuer mismatch when the session is not trust-enabled", async () => {
    const metadata = {
      credential_issuer: "https://other.example",
      credential_endpoint: "https://issuer.example/credential",
    };
    const result = await discoverIssuerMetadata("https://issuer.example", null, async () => ({
      ok: true,
      status: 200,
      headers: { get: () => "application/json" },
      json: async () => metadata,
    }));
    expect(result.credential_issuer).to.equal("https://other.example");
  });

  it("rejects a signed credential_issuer mismatch only for a trust-enabled session", async () => {
    const token = await signedIssuerMetadata({
      sub: "https://issuer.example",
      credential_issuer: "https://other.example",
      credential_endpoint: "https://issuer.example/credential",
    });
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => "application/jwt" },
      text: async () => token,
    });
    const compatibility = await discoverIssuerMetadata("https://issuer.example", null, fetchImpl);
    expect(compatibility.credential_issuer).to.equal("https://other.example");

    let error;
    try {
      await discoverIssuerMetadata("https://issuer.example", null, fetchImpl, {
        trustSession: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      });
    } catch (e) { error = e; }
    expect(error?.message).to.include("credential_issuer does not match");
  });
});
