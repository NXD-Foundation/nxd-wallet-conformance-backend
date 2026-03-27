import { expect } from "chai";
import * as jose from "jose";
import {
  validateCredentialResponseEncryptionParams,
  encryptCredentialResponseToJwe,
  encryptionParametersError,
  INVALID_ENCRYPTION_PARAMETERS,
} from "../utils/credentialResponseEncryption.js";

describe("credentialResponseEncryption", () => {
  const issuerMeta = {
    alg_values_supported: ["ECDH-ES", "RSA-OAEP-256"],
    enc_values_supported: ["A256GCM"],
  };

  it("validateCredentialResponseEncryptionParams rejects unsupported jwk.alg", () => {
    const cre = {
      jwk: { kty: "EC", crv: "P-256", x: "AQ", y: "AQ", alg: "UNSUPPORTED_ALG" },
      enc: "A256GCM",
    };
    try {
      validateCredentialResponseEncryptionParams(cre, issuerMeta);
      expect.fail("expected error");
    } catch (e) {
      expect(e.errorCode).to.equal(INVALID_ENCRYPTION_PARAMETERS);
      expect(e.message).to.include("Unsupported");
    }
  });

  it("validateCredentialResponseEncryptionParams rejects unsupported enc", () => {
    const cre = {
      jwk: { kty: "EC", crv: "P-256", x: "AQ", y: "AQ", alg: "ECDH-ES" },
      enc: "A128CBC-HS256",
    };
    try {
      validateCredentialResponseEncryptionParams(cre, issuerMeta);
      expect.fail("expected error");
    } catch (e) {
      expect(e.errorCode).to.equal(INVALID_ENCRYPTION_PARAMETERS);
    }
  });

  it("encryptCredentialResponseToJwe produces decryptable JWE (ECDH-ES + A256GCM)", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ECDH-ES", { crv: "P-256" });
    const jwk = await jose.exportJWK(publicKey);
    jwk.alg = "ECDH-ES";
    jwk.kid = "enc-key-1";

    const cre = { jwk, enc: "A256GCM" };
    const issuerConfig = {
      credential_response_encryption: issuerMeta,
    };

    const payload = { credentials: [{ credential: "abc" }], notification_id: "nid" };
    const jwe = await encryptCredentialResponseToJwe(payload, cre, issuerConfig);

    const parts = jwe.split(".");
    expect(parts.length).to.equal(5);

    const { plaintext } = await jose.compactDecrypt(jwe, privateKey);
    const roundTrip = JSON.parse(new TextDecoder().decode(plaintext));
    expect(roundTrip).to.deep.equal(payload);
  });

  it("encryptionParametersError carries errorCode", () => {
    const e = encryptionParametersError("test");
    expect(e.errorCode).to.equal(INVALID_ENCRYPTION_PARAMETERS);
  });
});
