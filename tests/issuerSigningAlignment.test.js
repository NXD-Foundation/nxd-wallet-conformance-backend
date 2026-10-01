import assert from "assert";
import fs from "fs";
import { X509Certificate } from "node:crypto";
import * as jose from "jose";
import {
  handleCredentialGenerationBasedOnFormat,
  handleCredentialGenerationBasedOnFormatDeferred,
} from "../utils/credGenerationUtils.js";
import { convertPemToJwk } from "../utils/didjwks.js";

const TRUST_FRAMEWORK_SESSION = {
  trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
};

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

function leafSubject(x5cEntry) {
  return new X509Certificate(x5cToPem(x5cEntry)).subject;
}

function firstCertificateDer(pemPath) {
  const pem = fs.readFileSync(pemPath, "utf8");
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  return match[1].replace(/\s+/g, "");
}

const PID_ISSUER_LEAF_DER = firstCertificateDer("certs/id-union-pid-certificate.pem");
const WRPAC_LEAF_DER = firstCertificateDer("certs/we-build-wrpac.pem");

async function issueCredential(signatureType, sessionExtras = {}) {
  return handleCredentialGenerationBasedOnFormat(
    {
      vct: "test-cred-config",
      proofs: { jwt: [await createHolderProofJwt()] },
    },
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
      ...sessionExtras,
    },
    "http://localhost:3000",
    "dc+sd-jwt",
  );
}

async function issueDeferredCredential(signatureType, sessionExtras = {}) {
  return handleCredentialGenerationBasedOnFormatDeferred(
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
      ...sessionExtras,
      requestBody: {
        vct: "test-cred-config",
        proofs: { jwt: [await createHolderProofJwt()] },
      },
    },
    "http://localhost:3000",
  );
}

async function issueHaipDeferredCredential(signatureType) {
  return issueDeferredCredential(signatureType, { isHaip: true });
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
    assert.match(leafSubject(header.x5c[0]), /CN=uaegean\.gr/);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "http://localhost:3000");
  });

  it("trust-framework x509 issuance signs with the IDunion PID certificate instead of the local x509EC certificate", async () => {
    const credential = await issueCredential("x509", TRUST_FRAMEWORK_SESSION);
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);

    assert.ok(header.x5c.length > 1);
    assert.strictEqual(header.x5c[0], PID_ISSUER_LEAF_DER);
    assert.notStrictEqual(header.x5c[0], WRPAC_LEAF_DER);
    assert.match(leafSubject(header.x5c[0]), /CN=dev-i4mlab\.aegean\.gr/);

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

  it("trust-framework HAIP did:web deferred issuance does not require WRPAC material", async () => {
    const certPathEnv = process.env.TRUST_WRPAC_CERT_PATH;
    const keyPathEnv = process.env.TRUST_WRPAC_KEY_PATH;
    process.env.TRUST_WRPAC_CERT_PATH = "/missing/wrpac-cert.pem";
    process.env.TRUST_WRPAC_KEY_PATH = "/missing/wrpac-key.pem";
    let credential;
    try {
      credential = await issueHaipDeferredCredential("did:web", TRUST_FRAMEWORK_SESSION);
    } finally {
      if (certPathEnv === undefined) delete process.env.TRUST_WRPAC_CERT_PATH;
      else process.env.TRUST_WRPAC_CERT_PATH = certPathEnv;
      if (keyPathEnv === undefined) delete process.env.TRUST_WRPAC_KEY_PATH;
      else process.env.TRUST_WRPAC_KEY_PATH = keyPathEnv;
    }
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
    assert.match(leafSubject(header.x5c[0]), /CN=uaegean\.gr/);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "http://localhost:3000");
  });

  it("trust-framework x509 deferred issuance signs with the IDunion PID certificate instead of the local x509EC certificate", async () => {
    const credential = await issueDeferredCredential("x509", TRUST_FRAMEWORK_SESSION);
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);

    assert.ok(header.x5c.length > 1);
    assert.strictEqual(header.x5c[0], PID_ISSUER_LEAF_DER);
    assert.notStrictEqual(header.x5c[0], WRPAC_LEAF_DER);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "http://localhost:3000");
  });
});
