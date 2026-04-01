import { expect } from "chai";
import * as jose from "jose";
import fs from "fs";
import path from "path";
import {
  resolveProofJwtPublicJwk,
  resolveDidWebPublicKey,
} from "../utils/proofJwtResolver.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

const ERR = {
  INVALID_PROOF_PUBLIC_KEY:
    "Public key for proof verification not found in JWT header.",
  INVALID_PROOF: "No proof information found",
};

const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");

describe("resolveProofJwtPublicJwk", () => {
  let x5cDerB64;
  let ecPrivateKey;
  let ecPublicJwk;

  before(async () => {
    if (!fs.existsSync(certPath)) {
      return;
    }
    const pemCert = fs.readFileSync(certPath, "utf8");
    x5cDerB64 = pemToBase64Der(pemCert);
    const keyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");
    const pkcs8 = fs.readFileSync(keyPath, "utf8");
    ecPrivateKey = await jose.importPKCS8(pkcs8, "ES256");
    const pub = await jose.exportJWK(ecPrivateKey);
    delete pub.d;
    ecPublicJwk = pub;
  });

  it("resolves jwk from header.jwk", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const out = await resolveProofJwtPublicJwk(
      { alg: "ES256", jwk },
      { messages: ERR, specRefVciProof: "" }
    );
    expect(out.x).to.equal(jwk.x);
    expect(out.y).to.equal(jwk.y);
  });

  it("resolves JWK from x5c only (no kid, no jwk)", async function () {
    if (!x5cDerB64) {
      this.skip();
    }
    const out = await resolveProofJwtPublicJwk(
      { alg: "ES256", x5c: [x5cDerB64] },
      { messages: ERR, specRefVciProof: "" }
    );
    expect(out.kty).to.equal("EC");
    expect(out.x).to.equal(ecPublicJwk.x);
    expect(out.y).to.equal(ecPublicJwk.y);
  });

  it("rejects x5c together with jwk", async () => {
    try {
      await resolveProofJwtPublicJwk(
        {
          alg: "ES256",
          x5c: ["abc"],
          jwk: ecPublicJwk || { kty: "EC", crv: "P-256", x: "a", y: "b" },
        },
        { messages: ERR, specRefVciProof: "urn:test" }
      );
      expect.fail("expected throw");
    } catch (e) {
      expect(e.message).to.include("x5c MUST NOT be present");
    }
  });

  it("rejects x5c together with kid", async () => {
    try {
      await resolveProofJwtPublicJwk(
        { alg: "ES256", x5c: ["abc"], kid: "did:jwk:eyJrdHkiOiJFQyJ9" },
        { messages: ERR, specRefVciProof: "" }
      );
      expect.fail("expected throw");
    } catch (e) {
      expect(e.message).to.include("x5c MUST NOT be present");
    }
  });

  it("resolves did:jwk kid to embedded JWK", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const kid =
      "did:jwk:" +
      Buffer.from(JSON.stringify(jwk), "utf8").toString("base64url");
    const out = await resolveProofJwtPublicJwk(
      { alg: "ES256", kid },
      { messages: ERR }
    );
    expect(out.x).to.equal(jwk.x);
    expect(out.y).to.equal(jwk.y);
  });

  it("resolves did:jwk kid with encoded fragment to embedded JWK", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const kid =
      "did:jwk:" +
      Buffer.from(JSON.stringify(jwk), "utf8").toString("base64url") +
      "%230";
    const out = await resolveProofJwtPublicJwk(
      { alg: "ES256", kid },
      { messages: ERR }
    );
    expect(out.x).to.equal(jwk.x);
    expect(out.y).to.equal(jwk.y);
  });

  it("throws when no jwk, x5c, or supported kid", async () => {
    try {
      await resolveProofJwtPublicJwk(
        { alg: "ES256" },
        { messages: ERR }
      );
      expect.fail("expected throw");
    } catch (e) {
      expect(e.message).to.include(ERR.INVALID_PROOF_PUBLIC_KEY);
    }
  });

  it("throws for unsupported kid scheme", async () => {
    try {
      await resolveProofJwtPublicJwk(
        { alg: "ES256", kid: "https://issuer.example/key-1" },
        { messages: ERR }
      );
      expect.fail("expected throw");
    } catch (e) {
      expect(e.message).to.include(ERR.INVALID_PROOF_PUBLIC_KEY);
    }
  });

  describe("did:web via resolveDidWebPublicKey (mock fetch)", () => {
    let originalFetch;

    before(() => {
      originalFetch = globalThis.fetch;
    });

    after(() => {
      globalThis.fetch = originalFetch;
    });

    it("resolves did:web kid using mocked DID document", async () => {
      const holderJwk = {
        kty: "EC",
        crv: "P-256",
        x: "testXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        y: "testYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      };
      const kid = "did:web:example.com#keys-1";
      globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({
          id: "did:web:example.com",
          verificationMethod: [
            {
              id: "did:web:example.com#keys-1",
              publicKeyJwk: holderJwk,
            },
          ],
        }),
      });

      const out = await resolveProofJwtPublicJwk(
        { alg: "ES256", kid },
        { messages: ERR }
      );
      expect(out.x).to.equal(holderJwk.x);
      globalThis.fetch = originalFetch;
    });
  });
});

describe("resolveDidWebPublicKey (delegates to same fetch path)", () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns publicKeyJwk from DID document", async () => {
    const jwk = { kty: "EC", crv: "P-256", x: "ax", y: "ay" };
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        id: "did:web:test.local",
        verificationMethod: [
          { id: "did:web:test.local#k1", publicKeyJwk: jwk },
        ],
      }),
    });
    const out = await resolveDidWebPublicKey("did:web:test.local#k1", null);
    expect(out).to.deep.equal(jwk);
  });
});
