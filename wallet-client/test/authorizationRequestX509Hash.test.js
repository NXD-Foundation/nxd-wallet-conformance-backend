import { expect } from "chai";
import crypto from "node:crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { SignJWT, importPKCS8, decodeProtectedHeader } from "jose";
import {
  computeX509HashClientIdFromLeafX5c,
  verifyAuthorizationRequestJwt,
} from "../src/lib/presentation.js";

import { buildVpRequestJWT } from "../../utils/cryptoUtils.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoWalletRoot = path.join(__dirname, "..");
const x509CertPath = path.join(repoWalletRoot, "x509", "client_certificate.crt");
const x509KeyPath = path.join(repoWalletRoot, "x509", "client_private_pkcs8.key");

function certToX5c0() {
  const certPem = fs.readFileSync(x509CertPath, "utf8");
  return certPem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");
}

describe("authorization request JWT (RFC002 x509_hash)", () => {
  it("signs the RFC002 Request Object with protected-header iat", async () => {
    const cert = fs.readFileSync("x509/client_certificate.crt", "utf8")
      .replace(/-----[^-]+-----|\s/g, "");
    const jwt = await buildVpRequestJWT(
      computeX509HashClientIdFromLeafX5c(cert), "https://rp.example/response",
      null, null, {}, null, "https://rp.example", "vp_token", "nonce-1",
      null, null, "direct_post.jwt",
    );
    expect(decodeProtectedHeader(jwt).iat).to.be.a("number");
  });

  for (const [name, invocationProtocol, responseMode] of [
    ["encrypted OpenID4VP", "openid4vp:", "direct_post.jwt"],
    ["eu-eaap", "eu-eaap:", "direct_post"],
  ]) {
    it(`requires protected-header iat and checks expiry for ${name}`, async () => {
      const x5c0 = certToX5c0();
      const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
      const key = await importPKCS8(fs.readFileSync(x509KeyPath, "utf8"), "RS256");
      const now = Math.floor(Date.now() / 1000);
      const options = { expectedClientId: client_id, invocationProtocol };
      const sign = (claims, header = {}) => new SignJWT({ client_id, response_mode: responseMode, ...claims })
        .setProtectedHeader({ alg: "RS256", x5c: [x5c0], ...header })
        .sign(key);

      const valid = await verifyAuthorizationRequestJwt(await sign({ exp: now + 120 }, { iat: now }), options);
      expect(valid.header.iat).to.equal(now);
      expect(valid.payload).not.to.have.property("iat");

      for (const [claims, header, message] of [
        [{ iat: now, exp: now + 120 }, {}, /protected header/],
        [{ exp: now + 120 }, { iat: String(now) }, /protected header/],
        [{ exp: now - 600 }, { iat: now - 900 }, /exp/],
      ]) {
        let failure;
        try { await verifyAuthorizationRequestJwt(await sign(claims, header), options); }
        catch (error) { failure = error; }
        expect(failure?.message).to.match(message);
      }
    });
  }

  it("rejects an unsigned authorization request before trust resolution", async () => {
    const unsigned = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ client_id: "x509_hash:test" })).toString("base64url")}.`;
    try {
      await verifyAuthorizationRequestJwt(unsigned, { expectedClientId: null });
      expect.fail("expected unsigned request rejection");
    } catch (error) {
      expect(error.message).to.include("Authorization request JWT must be signed");
    }
  });

  it("rejects a signed request whose client_id differs from the deep-link client_id", async () => {
    const x5c0 = certToX5c0();
    const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");
    const requestJwt = await new SignJWT({ client_id })
      .setProtectedHeader({ alg: "RS256", typ: "oauth-authz-req+jwt", x5c: [x5c0] })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: "x509_hash:other" });
      expect.fail("expected client_id mismatch rejection");
    } catch (error) {
      expect(error.message).to.include("does not match deep link client_id");
    }
  });

  it("computeX509HashClientIdFromLeafX5c matches verifier computeX509HashClientId (SHA-256 DER, base64url)", () => {
    const x5c0 = certToX5c0();
    const got = computeX509HashClientIdFromLeafX5c(x5c0);
    expect(got).to.match(/^x509_hash:[A-Za-z0-9_-]+$/);
    const der = Buffer.from(x5c0, "base64");
    const manual = `x509_hash:${crypto.createHash("sha256").update(der).digest("base64url")}`;
    expect(got).to.equal(manual);
  });

  it("verifyAuthorizationRequestJwt accepts x509_hash JAR signed with leaf x5c", async () => {
    const x5c0 = certToX5c0();
    const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id,
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
      state: "s1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    const { payload } = await verifyAuthorizationRequestJwt(requestJwt, {
      expectedClientId: client_id,
    });
    expect(payload.client_id).to.equal(client_id);
    const originalTrustMode = process.env.WALLET_TRUST_MODE;
    process.env.WALLET_TRUST_MODE = "strict";
    try {
      let failure;
      try { await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: client_id }); }
      catch (error) { failure = error; }
      expect(failure?.message).to.match(/framework trust is not established/);
    } finally {
      if (originalTrustMode === undefined) delete process.env.WALLET_TRUST_MODE;
      else process.env.WALLET_TRUST_MODE = originalTrustMode;
    }

  });

  it("verifyAuthorizationRequestJwt rejects x509_hash when client_id does not match leaf hash", async () => {
    const x5c0 = certToX5c0();
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id: "x509_hash:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
      state: "s1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: null });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.include("x509_hash client_id does not match");
    }
  });

  it("verifyAuthorizationRequestJwt rejects x509_hash without x5c header", async () => {
    const x5c0 = certToX5c0();
    const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      client_id,
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: client_id });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.match(/x5c/i);
    }
  });

  it("verifyAuthorizationRequestJwt rejects unknown client_id_scheme (non-DID)", async () => {
    const x5c0 = certToX5c0();
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id: "x509_san_dns:example.com",
      client_id_scheme: "verifiable_credential",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: null });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.include("unsupported client_id_scheme");
    }
  });
});
