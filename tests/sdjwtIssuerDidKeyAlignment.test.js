import assert from "assert";
import fs from "fs";
import { createPrivateKey, createPublicKey, X509Certificate } from "crypto";
import * as jose from "jose";
import { convertPemToJwk } from "../utils/didjwks.js";
import {
  computeDidJwkIssuerDidAndKidFromDidKeys,
  getIssuerJwkPairAlignedWithDidDocument,
  getIssuerPublicJwkForDidJwkDid,
  loadDidIssuerPems,
} from "../utils/issuerDidKeys.js";
import {
  createSignerVerifier,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../utils/sdjwtUtils.js";
import { parseDidJwk } from "../utils/cryptoUtils.js";
import {
  handleVcSdJwtFormat,
  handleVcSdJwtFormatDeferred,
} from "../utils/credGenerationUtils.js";
import {
  certToBase64,
  signStatusListToken,
} from "../utils/statusListSigning.js";

/** Same paths as utils/credGenerationUtils.js (HAIP / x509 issuance). */
const X509_PRIVATE = "./x509EC/ec_private_pkcs8.key";
const X509_CERT = "./x509EC/client_certificate.crt";

function assertSameEcPublicJwk(a, b) {
  assert.strictEqual(a.kty, b.kty);
  assert.strictEqual(a.crv, b.crv);
  assert.strictEqual(a.x, b.x);
  assert.strictEqual(a.y, b.y);
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
  return handleVcSdJwtFormat(
    {
      vct: "urn:eu.europa.ec.eudi:pid:1",
      proof: { jwt: await createHolderProofJwt() },
    },
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
    },
    "http://localhost:3000",
    "dc+sd-jwt"
  );
}

async function issueDeferredCredential(signatureType) {
  return handleVcSdJwtFormatDeferred(
    {
      signatureType,
      isHaip: false,
      credentialPayload: {},
      requestBody: {
        vct: "urn:eu.europa.ec.eudi:pid:1",
        proof: { jwt: await createHolderProofJwt() },
      },
    },
    "http://localhost:3000"
  );
}

function extractIssuedJws(credential) {
  return credential.split("~")[0];
}

function x5cToPem(x5cEntry) {
  return `-----BEGIN CERTIFICATE-----\n${x5cEntry
    .replace(/(.{64})/g, "$1\n")
    .trim()}\n-----END CERTIFICATE-----\n`;
}

describe("SD-JWT issuer key alignment with DID documents", () => {
  it("did:web: JWKS in DID document matches issuer signing public JWK (x,y)", async () => {
    const jwkFromDidWebDoc = await convertPemToJwk();
    const { publicJwk: jwkFromSigningPair } = getIssuerJwkPairAlignedWithDidDocument();
    assertSameEcPublicJwk(jwkFromDidWebDoc, jwkFromSigningPair);
  });

  it("did:web: ES256 JWS signed with issuer private key verifies with DID document JWK", async () => {
    const { privatePem } = loadDidIssuerPems();
    const privateKey = await jose.importPKCS8(privatePem, "ES256");
    const didDocJwk = await convertPemToJwk();
    const verifyKey = await jose.importJWK(didDocJwk, "ES256");

    const token = await new jose.SignJWT({ claim: "test" })
      .setProtectedHeader({
        alg: "ES256",
        kid: "did:web:example.com#keys-1",
        typ: "test+jwt",
      })
      .setIssuedAt()
      .sign(privateKey);

    const { payload } = await jose.jwtVerify(token, verifyKey);
    assert.strictEqual(payload.claim, "test");
  });

  it("did:jwk: embedded JWK matches issuer public key used for did:jwk kid", () => {
    const { did } = computeDidJwkIssuerDidAndKidFromDidKeys();
    const jwkFromDid = parseDidJwk(did);
    const jwkFromKeyMaterial = getIssuerPublicJwkForDidJwkDid();
    assertSameEcPublicJwk(jwkFromDid, jwkFromKeyMaterial);
  });

  it("did:jwk: SD-JWT-style signer/verifier uses keys consistent with did:jwk identifier", async () => {
    const { privateJwk, publicJwk } = getIssuerJwkPairAlignedWithDidDocument();
    const { signer, verifier } = await createSignerVerifier(privateJwk, publicJwk);
    const { did } = computeDidJwkIssuerDidAndKidFromDidKeys();
    const jwkFromDid = parseDidJwk(did);
    assertSameEcPublicJwk(jwkFromDid, publicJwk);

    const testPayload = new TextEncoder().encode("sd-jwt-signing-check");
    const sig = await signer(testPayload);
    const ok = await verifier(testPayload, sig);
    assert.strictEqual(ok, true);
  });
});

describe("SD-JWT issuer key alignment for x509 (x5c)", () => {
  it("signing private key matches the public key in client_certificate.crt", () => {
    const privatePem = fs.readFileSync(X509_PRIVATE, "utf8");
    const certPem = fs.readFileSync(X509_CERT, "utf8");

    const pubFromPrivate = createPublicKey(createPrivateKey(privatePem)).export({
      type: "spki",
      format: "pem",
    });
    const pubFromCert = createPublicKey(certPem).export({
      type: "spki",
      format: "pem",
    });

    assert.strictEqual(
      pubFromPrivate,
      pubFromCert,
      "ec_private_pkcs8.key must pair with the cert in client_certificate.crt"
    );
  });

  it("createSignerVerifierX509 uses a cert and key that verify each other", async () => {
    const privatePem = fs.readFileSync(X509_PRIVATE, "utf8");
    const certPem = fs.readFileSync(X509_CERT, "utf8");
    const { signer, verifier } = await createSignerVerifierX509(privatePem, certPem);

    const payload = new TextEncoder().encode("x509-sd-jwt-signing-check");
    const sig = await signer(payload);
    const ok = await verifier(payload, sig);
    assert.strictEqual(ok, true);
  });

  it("JWS header x5c[0] (pemToBase64Der) is the same certificate bytes as the PEM file", () => {
    const certPem = fs.readFileSync(X509_CERT, "utf8");
    const derB64 = pemToBase64Der(certPem);
    const certFromPemFile = new X509Certificate(certPem);
    const certFromX5cDer = new X509Certificate(Buffer.from(derB64, "base64"));
    assert.ok(
      certFromPemFile.raw.equals(certFromX5cDer.raw),
      "x5c must embed the issuer cert actually used for signing"
    );
  });

  it("ES256 JWS signed with x509 private key verifies with public key from x5c certificate", async () => {
    const privatePem = fs.readFileSync(X509_PRIVATE, "utf8");
    const certPem = fs.readFileSync(X509_CERT, "utf8");
    const derB64 = pemToBase64Der(certPem);
    const certFromHeader = `-----BEGIN CERTIFICATE-----\n${derB64.replace(/(.{64})/g, "$1\n").trim()}\n-----END CERTIFICATE-----\n`;

    const signKey = await jose.importPKCS8(privatePem, "ES256");
    const verifyKey = await jose.importX509(certFromHeader, "ES256");

    const token = await new jose.SignJWT({ x509: "aligned" })
      .setProtectedHeader({
        alg: "ES256",
        typ: "vc+sd-jwt",
        x5c: [derB64],
      })
      .setIssuedAt()
      .sign(signKey);

    const { payload } = await jose.jwtVerify(token, verifyKey);
    assert.strictEqual(payload.x509, "aligned");
  });
});

describe("SD-JWT issuance flow key alignment", () => {
  it("did:web issuance signs with the key published in the DID document", async () => {
    const credential = await issueCredential("did:web");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);
    const didDocJwk = await convertPemToJwk();
    const verifyKey = await jose.importJWK(didDocJwk, "ES256");

    assert.strictEqual(header.kid, "did:web:localhost:3000#keys-1");

    const { payload } = await jose.jwtVerify(issuedJws, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "did:web:localhost:3000");
  });

  it("did:jwk issuance signs with the key embedded in the issued kid", async () => {
    const credential = await issueCredential("did:jwk");
    const issuedJws = extractIssuedJws(credential);
    const header = jose.decodeProtectedHeader(issuedJws);
    const verifyKey = await jose.importJWK(parseDidJwk(header.kid), "ES256");

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
});

describe("Deferred SD-JWT issuance flow key alignment", () => {
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
    const verifyKey = await jose.importJWK(parseDidJwk(header.kid), "ES256");

    assert.ok(header.kid.startsWith("did:jwk:"));
    assert.ok(header.kid.endsWith("#0"));

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

describe("Status list token signing alignment", () => {
  function buildStatusList() {
    return {
      bits: 1,
      statuses: [0, 1, 0, 0, 1, 0, 0, 0],
      updated_at: Math.floor(Date.now() / 1000),
    };
  }

  it("did:web status list tokens sign with the DID document key", async () => {
    const token = await signStatusListToken(
      "status-list-did-web",
      buildStatusList(),
      { signatureType: "did:web", isHaip: false },
      "http://localhost:3000"
    );
    const header = jose.decodeProtectedHeader(token);
    const verifyKey = await jose.importJWK(await convertPemToJwk(), "ES256");

    assert.strictEqual(header.kid, "did:web:localhost:3000#keys-1");

    const { payload } = await jose.jwtVerify(token, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, "did:web:localhost:3000");
    assert.strictEqual(payload.sub, "http://localhost:3000/status-list/status-list-did-web");
  });

  it("did:jwk status list tokens sign with the key embedded in the issued kid", async () => {
    const token = await signStatusListToken(
      "status-list-did-jwk",
      buildStatusList(),
      { signatureType: "did:jwk", isHaip: false },
      "http://localhost:3000"
    );
    const header = jose.decodeProtectedHeader(token);
    const verifyKey = await jose.importJWK(parseDidJwk(header.kid), "ES256");

    assert.ok(header.kid.startsWith("did:jwk:"));

    const { payload } = await jose.jwtVerify(token, verifyKey, {
      algorithms: ["ES256"],
    });
    assert.strictEqual(payload.iss, header.kid.split("#")[0]);
  });

  it("x509 status list tokens sign with the private key matching the x5c certificate in the header", async () => {
    const token = await signStatusListToken(
      "status-list-x509",
      buildStatusList(),
      { signatureType: "x509", isHaip: false },
      "http://localhost:3000"
    );
    const header = jose.decodeProtectedHeader(token);

    assert.deepStrictEqual(header.x5c, [certToBase64(fs.readFileSync(X509_CERT, "utf8"))]);

    const verifyKey = await jose.importX509(x5cToPem(header.x5c[0]), "ES256");
    const { payload } = await jose.jwtVerify(token, verifyKey, {
      algorithms: ["ES256"],
    });

    assert.strictEqual(payload.iss, "http://localhost:3000");
    assert.strictEqual(payload.sub, "http://localhost:3000/status-list/status-list-x509");
  });
});

/*
  Other issuance paths (not covered here, or covered elsewhere):

  - mDL (@auth0/mdl): uses the same x509EC files in x509 mode; in "jwk" mode it still uses
    ./private-key.pem — a separate alignment concern if you publish DIDs for mDL.
  - OAuth / PAR / token endpoint JWTs: often use ./private-key.pem and fixed kids; distinct
    from SD-JWT credential signing.
  - Deferred credentials: now covered for did:web, did:jwk, and x509.
  - Status list JWTs: now covered for did:web, did:jwk, and x509 via the shared
    pure signing helper used by statusListUtils.js.
*/
