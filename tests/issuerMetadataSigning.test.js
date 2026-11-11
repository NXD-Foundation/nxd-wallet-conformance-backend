import { expect } from "chai";
import crypto from "crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as jose from "jose";
import express from "express";
import request from "supertest";
import metadataRouter from "../routes/metadataroutes.js";
import {
  SIGNED_ISSUER_METADATA_TYP,
  signCredentialIssuerMetadata,
} from "../utils/issuerMetadataSigning.js";

describe("signed Credential Issuer metadata", () => {
  const metadata = {
    credential_issuer: "https://issuer.example.com",
    credential_endpoint: "https://issuer.example.com/credential",
    credential_configurations_supported: {},
  };

  it("creates a verifiable ES256 metadata JWT with required claims", async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const privateKeyPkcs8 = privateKey.export({ type: "pkcs8", format: "pem" });
    const jwt = await signCredentialIssuerMetadata(metadata, {
      privateKeyPkcs8,
      certChain: ["leaf-certificate", "issuing-ca-certificate"],
    });

    const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey, {
      typ: SIGNED_ISSUER_METADATA_TYP,
    });
    expect(protectedHeader).to.include({ alg: "ES256", typ: SIGNED_ISSUER_METADATA_TYP });
    expect(protectedHeader.x5c).to.deep.equal(["leaf-certificate", "issuing-ca-certificate"]);
    expect(payload.sub).to.equal(metadata.credential_issuer);
    expect(payload.iat).to.be.a("number");
    expect(payload.credential_endpoint).to.equal(metadata.credential_endpoint);
  });

  it("retains JSON discovery for JSON-only callers", async () => {
    const app = express();
    app.use("/", metadataRouter);
    const response = await request(app)
      .get("/.well-known/openid-credential-issuer")
      .set("Accept", "application/json")
      .expect(200);
    expect(response.headers["content-type"]).to.include("application/json");
    expect(response.body.credential_issuer).to.be.a("string");
  });

  it("publishes the configured metadata WRPAC without adding the legacy verifier CA", async () => {
    const directory = mkdtempSync(join(tmpdir(), "issuer-metadata-wrpac-"));
    const p12Path = join(directory, "metadata.p12");
    const leafPath = join(directory, "leaf.pem");
    const originalPath = process.env.ISSUER_METADATA_SIGNING_P12_PATH;
    const app = express();
    app.use("/", metadataRouter);

    try {
      const certificate = new crypto.X509Certificate(readFileSync("certs/we-build-wrpac.pem"));
      writeFileSync(leafPath, certificate.toString());
      execFileSync("openssl", ["pkcs12", "-export", "-in", leafPath,
        "-inkey", "certs/dev-i4mlab.aegean.gr.key.pem", "-out", p12Path,
        "-passout", "env:WEBUILD_P12_PASS"], {
        env: { ...process.env, WEBUILD_P12_PASS: process.env.WEBUILD_P12_PASSWORD || "webuild" },
      });
      process.env.ISSUER_METADATA_SIGNING_P12_PATH = p12Path;
      const response = await request(app)
        .get("/.well-known/openid-credential-issuer")
        .set("Accept", "application/jwt")
        .expect(200);
      const { protectedHeader, payload } = await jose.jwtVerify(response.text, certificate.publicKey);
      expect(protectedHeader.x5c).to.deep.equal([certificate.raw.toString("base64")]);
      expect(payload.sub).to.equal(payload.credential_issuer);
    } finally {
      if (originalPath === undefined) delete process.env.ISSUER_METADATA_SIGNING_P12_PATH;
      else process.env.ISSUER_METADATA_SIGNING_P12_PATH = originalPath;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("does not downgrade JWT metadata requests when signing is unavailable", async () => {
    const originalPath = process.env.ISSUER_METADATA_SIGNING_P12_PATH;
    process.env.ISSUER_METADATA_SIGNING_P12_PATH = "certs/does-not-exist.p12";
    const app = express();
    app.use("/", metadataRouter);

    try {
      const response = await request(app)
        .get("/.well-known/openid-credential-issuer")
        .set("Accept", "application/jwt")
        .expect(503);
      expect(response.headers["content-type"]).to.include("application/json");
      expect(response.body.error).to.equal("temporarily_unavailable");
    } finally {
      if (originalPath === undefined) delete process.env.ISSUER_METADATA_SIGNING_P12_PATH;
      else process.env.ISSUER_METADATA_SIGNING_P12_PATH = originalPath;
    }
  });
});
