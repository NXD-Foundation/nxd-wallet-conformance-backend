import assert from "assert";
import * as jose from "jose";
import {
  handleCredentialGenerationBasedOnFormat,
  handleCredentialGenerationBasedOnFormatDeferred,
} from "../utils/credGenerationUtils.js";
import { convertPemToJwk } from "../utils/didjwks.js";

function extractIssuedJws(credential) {
  return credential.split("~")[0];
}

function x5cToPem(x5cEntry) {
  return `-----BEGIN CERTIFICATE-----\n${x5cEntry
    .replace(/(.{64})/g, "$1\n")
    .trim()}\n-----END CERTIFICATE-----\n`;
}

async function createHolderProofJwt() {
  const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
  const jwk = await jose.exportJWK(publicKey);

  return new jose.SignJWT({ nonce: "test-nonce" })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk,
    })
    .setIssuedAt()
    .sign(privateKey);
}

async function issueCredential(signatureType) {
  return handleCredentialGenerationBasedOnFormat(
    {
      vct: "test-cred-config",
      proofs: { jwt: [await createHolderProofJwt()] },
    },
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
    },
    "http://localhost:3000",
    "dc+sd-jwt",
  );
}

async function issueDeferredCredential(signatureType) {
  return handleCredentialGenerationBasedOnFormatDeferred(
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
      requestBody: {
        vct: "test-cred-config",
        proofs: { jwt: [await createHolderProofJwt()] },
      },
    },
    "http://localhost:3000",
  );
}

describe("issuer signing alignment", () => {
  it("did:jwk issuance signs with the key embedded in the issued kid", async () => {
    const credential = await issueCredential("did:jwk");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);
    const verifyKey = await jose.importJWK(
      JSON.parse(
        Buffer.from(header.kid.replace(/^did:jwk:/, "").replace(/#0$/, ""), "base64url").toString("utf8"),
      ),
      "ES256",
    );

    assert.ok(header.kid.startsWith("did:jwk:"));
    assert.ok(header.kid.endsWith("#0"));

    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, header.kid.split("#")[0]);
  });

  it("x509 issuance signs with the private key matching the x5c certificate in the header", async () => {
    const credential = await issueCredential("x509");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);

    assert.ok(Array.isArray(header.x5c));
    assert.strictEqual(header.x5c.length, 1);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "http://localhost:3000");
  });

  it("did:web deferred issuance signs with the key published in the DID document", async () => {
    const credential = await issueDeferredCredential("did:web");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);
    const verifyKey = await jose.importJWK(await convertPemToJwk(), "ES256");

    assert.strictEqual(header.kid, "did:web:localhost:3000#keys-1");

    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "did:web:localhost:3000");
  });

  it("did:jwk deferred issuance signs with the key embedded in the issued kid", async () => {
    const credential = await issueDeferredCredential("did:jwk");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);
    const verifyKey = await jose.importJWK(
      JSON.parse(
        Buffer.from(header.kid.replace(/^did:jwk:/, "").replace(/#0$/, ""), "base64url").toString("utf8"),
      ),
      "ES256",
    );

    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, header.kid.split("#")[0]);
  });

  it("x509 deferred issuance signs with the private key matching the x5c certificate in the header", async () => {
    const credential = await issueDeferredCredential("x509");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);

    assert.ok(Array.isArray(header.x5c));
    assert.strictEqual(header.x5c.length, 1);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "http://localhost:3000");
  });
});
