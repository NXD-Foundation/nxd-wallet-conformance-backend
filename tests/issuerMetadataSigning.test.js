import { expect } from "chai";
import crypto from "crypto";
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
