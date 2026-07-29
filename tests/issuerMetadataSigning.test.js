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
import { loadAptitudeIssuerSigningMaterial } from "../utils/aptitudeIssuerSigningMaterial.js";

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
      certChain: ["leaf-certificate"],
    });

    const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey, {
      typ: SIGNED_ISSUER_METADATA_TYP,
    });
    expect(protectedHeader).to.include({ alg: "ES256", typ: SIGNED_ISSUER_METADATA_TYP });
    expect(protectedHeader.x5c).to.deep.equal(["leaf-certificate"]);
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

  it("returns signed JWT when client requests application/jwt", async () => {
    const app = express();
    app.use("/", metadataRouter);
    const response = await request(app)
      .get("/.well-known/openid-credential-issuer")
      .set("Accept", "application/jwt")
      .expect(200);
    expect(response.headers["content-type"]).to.include("application/jwt");
    expect(response.text).to.include(".");
    const protectedHeader = jose.decodeProtectedHeader(response.text);
    const material = loadAptitudeIssuerSigningMaterial();
    expect(protectedHeader.typ).to.equal(SIGNED_ISSUER_METADATA_TYP);
    expect(protectedHeader.x5c).to.deep.equal(material.certChain);

    const verifyKey = await jose.importX509(material.leafCertificatePem, "ES256");
    const { payload } = await jose.jwtVerify(response.text, verifyKey, {
      typ: SIGNED_ISSUER_METADATA_TYP,
    });
    expect(payload.issuer_info.registration_certificate).to.equal(material.certChain[0]);
  });
});
