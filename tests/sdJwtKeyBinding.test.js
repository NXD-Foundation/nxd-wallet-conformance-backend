import { expect } from "chai";
import * as jose from "jose";
import {
  extractCredentialCnfJwkFromSdJwt,
  extractKeyBindingJwtFromSdJwt,
  jwkPublicEquals,
  validateSdJwtKeyBindingMatchesCredential,
} from "../utils/sdJwtKeyBinding.js";

function b64Json(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sdJwtIssuerJwt(payload) {
  return `${b64Json({ alg: "ES256", typ: "dc+sd-jwt" })}.${b64Json(payload)}.sig`;
}

async function keyPairJwks() {
  const { privateKey, publicKey } = await jose.generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    privateJwk: await jose.exportJWK(privateKey),
    publicJwk: await jose.exportJWK(publicKey),
  };
}

async function signKbJwt({ privateJwk, publicJwk, payload = {} }) {
  const signingKey = await jose.importJWK(privateJwk, "ES256");
  return new jose.SignJWT({
    nonce: "nonce-123",
    aud: "did:example:verifier",
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt", jwk: publicJwk })
    .sign(signingKey);
}

describe("sdJwtKeyBinding", () => {
  it("accepts a KB-JWT signed by the key in the credential cnf.jwk", async () => {
    const holder = await keyPairJwks();
    const kbJwt = await signKbJwt(holder);
    const sdJwt = `${sdJwtIssuerJwt({ cnf: { jwk: holder.publicJwk } })}~${kbJwt}`;

    const result = await validateSdJwtKeyBindingMatchesCredential({ sdJwt });

    expect(result.ok).to.equal(true);
    expect(jwkPublicEquals(result.cnfJwk, holder.publicJwk)).to.equal(true);
  });

  it("rejects when the KB-JWT header key differs from credential cnf.jwk", async () => {
    const holder = await keyPairJwks();
    const other = await keyPairJwks();
    const kbJwt = await signKbJwt(other);
    const sdJwt = `${sdJwtIssuerJwt({ cnf: { jwk: holder.publicJwk } })}~${kbJwt}`;

    try {
      await validateSdJwtKeyBindingMatchesCredential({ sdJwt });
      expect.fail("expected key binding cnf mismatch");
    } catch (error) {
      expect(error.message).to.equal("key_binding_cnf_mismatch");
    }
  });

  it("rejects when the KB-JWT signature does not verify with its header jwk", async () => {
    const holder = await keyPairJwks();
    const other = await keyPairJwks();
    const kbJwt = await signKbJwt({
      privateJwk: other.privateJwk,
      publicJwk: holder.publicJwk,
    });
    const sdJwt = `${sdJwtIssuerJwt({ cnf: { jwk: holder.publicJwk } })}~${kbJwt}`;

    try {
      await validateSdJwtKeyBindingMatchesCredential({ sdJwt });
      expect.fail("expected invalid key binding signature");
    } catch (error) {
      expect(error.message).to.equal("key_binding_signature_invalid");
    }
  });

  it("rejects when the credential does not contain cnf.jwk", async () => {
    const holder = await keyPairJwks();
    const kbJwt = await signKbJwt(holder);
    const sdJwt = `${sdJwtIssuerJwt({ sub: "holder" })}~${kbJwt}`;

    try {
      await validateSdJwtKeyBindingMatchesCredential({ sdJwt });
      expect.fail("expected missing credential cnf.jwk");
    } catch (error) {
      expect(error.message).to.equal("credential_cnf_jwk_missing");
    }
  });

  it("rejects when the KB-JWT header is missing jwk", async () => {
    const holder = await keyPairJwks();
    const signingKey = await jose.importJWK(holder.privateJwk, "ES256");
    const kbJwt = await new jose.SignJWT({
      nonce: "nonce-123",
      aud: "did:example:verifier",
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .sign(signingKey);
    const sdJwt = `${sdJwtIssuerJwt({ cnf: { jwk: holder.publicJwk } })}~${kbJwt}`;

    try {
      await validateSdJwtKeyBindingMatchesCredential({ sdJwt });
      expect.fail("expected missing key binding jwk");
    } catch (error) {
      expect(error.message).to.equal("key_binding_jwk_missing");
    }
  });

  it("extracts the credential cnf and KB-JWT from an SD-JWT presentation", async () => {
    const holder = await keyPairJwks();
    const kbJwt = await signKbJwt(holder);
    const sdJwt = `${sdJwtIssuerJwt({ cnf: { jwk: holder.publicJwk } })}~disclosure~${kbJwt}`;

    expect(extractKeyBindingJwtFromSdJwt(sdJwt)).to.equal(kbJwt);
    expect(jwkPublicEquals(extractCredentialCnfJwkFromSdJwt(sdJwt), holder.publicJwk)).to.equal(
      true,
    );
  });
});
