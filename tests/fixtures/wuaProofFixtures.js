import fs from "fs";
import path from "path";
import * as jose from "jose";
import { pemToBase64Der } from "../../utils/sdjwtUtils.js";

const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
const keyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");
// sharedIssuanceFlows stubs fs.readFileSync after importing this fixture. Keep
// the real readers so the fixture always signs with the private key matching
// its advertised x5c leaf certificate.
const readFixtureFile = fs.readFileSync.bind(fs);
const fixtureFilesExist = fs.existsSync.bind(fs);

export function buildTs3WuaPayload({ attestedKeys, iss = "https://wallet-provider.example" } = {}) {
  return {
    iss,
    aud: "https://issuer.example/credential",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: `wua-${Math.random().toString(36).slice(2, 10)}`,
    eudi_wallet_info: {
      general_info: { name: "test-wallet" },
      key_storage_info: { level: "tee" },
    },
    attested_keys: attestedKeys,
    status: { status_list: { uri: "https://example.com/status", idx: 0 } },
  };
}

/**
 * Sign a WUA with header.jwk (dev/self-contained).
 */
export async function signWuaWithJwk({ wpPrivateKey, wpPublicJwk, attestedKeys, payloadExtras = {} }) {
  const payload = { ...buildTs3WuaPayload({ attestedKeys }), ...payloadExtras };
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", jwk: wpPublicJwk })
    .sign(wpPrivateKey);
}

/**
 * Sign a WUA with x5c-only header using repo x509EC test certificate (no jwk in header).
 */
export async function signWuaWithX5cOnly({ attestedKeys, payloadExtras = {} } = {}) {
  if (!fixtureFilesExist(certPath) || !fixtureFilesExist(keyPath)) {
    return null;
  }
  const pemCert = readFixtureFile(certPath, "utf8");
  const pemKey = readFixtureFile(keyPath, "utf8");
  const x5cDerB64 = pemToBase64Der(pemCert);
  const privateKey = await jose.importPKCS8(pemKey, "ES256");
  const payload = { ...buildTs3WuaPayload({ attestedKeys }), ...payloadExtras };
  return new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "key-attestation+jwt",
      x5c: [x5cDerB64],
    })
    .sign(privateKey);
}

export async function signProofJwtWithKeyAttestation({
  holderPrivateKey,
  holderPublicJwk,
  wuaJwt,
  nonce,
  aud,
  iss = "did:holder:test",
}) {
  return new jose.SignJWT({ nonce, iss, aud })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: holderPublicJwk,
      key_attestation: wuaJwt,
    })
    .sign(holderPrivateKey);
}

export function x509EcFixturesAvailable() {
  return fixtureFilesExist(certPath) && fixtureFilesExist(keyPath);
}
