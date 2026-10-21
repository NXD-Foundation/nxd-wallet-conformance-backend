import { expect } from "chai";
import express from "express";
import request from "supertest";
import metadataRouter from "../routes/metadataroutes.js";

describe("issuer JWK use publication regression", () => {
  const app = express();
  app.use(metadataRouter);

  for (const path of [
    "/",
    "/jwks",
    "/.well-known/jwt-vc-issuer",
    "/.well-known/jwt-vc-issuer/rfc-issuer",
    "/jwt-vc-issuer/rfc-issuer",
  ]) {
    it(`${path} publishes agreement keys as enc instead of keyAgreement`, async () => {
      const response = await request(app).get(path).expect(200);
      const keys = (response.body.jwks || response.body).keys;
      expect(keys).to.have.length(2);
      const signingKey = keys.find((key) => key.use === "sig");
      expect(signingKey).to.be.an("object");
      const agreementKey = keys.find((key) => key.kid === `${signingKey.kid}-agreement`);
      expect(agreementKey).to.include({ use: "enc" });

      const issuerMetadata = await request(app)
        .get("/.well-known/openid-credential-issuer")
        .set("Accept", "application/json")
        .expect(200);
      const encryptionKey = issuerMetadata.body.credential_request_encryption.jwks.keys
        .find((key) => key.kid === agreementKey.kid);
      expect(encryptionKey).to.be.an("object");
      // The encryption metadata additionally constrains alg to ECDH-ES.
      const { alg, ...publishedEncryptionKey } = encryptionKey;
      expect(agreementKey).to.deep.equal(publishedEncryptionKey);
    });
  }
});
