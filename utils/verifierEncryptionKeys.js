import fs from "fs";
import crypto from "crypto";
import { KEY_MATERIAL_PATHS } from "./keyMaterialPaths.js";

const RFC002_JWE_ALGS = new Set(["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"]);

function publicJwkFromPrivate(privateKeyPem) {
  return crypto.createPublicKey(privateKeyPem).export({ format: "jwk" });
}

/**
 * Select the EC P-256 encryption JWK advertised in verifier metadata (RFC002 §8.3.2).
 */
export function selectVerifierEncryptionJwk(clientMetadata = {}) {
  const keys = Array.isArray(clientMetadata?.jwks?.keys) ? clientMetadata.jwks.keys : [];
  return keys.find(
    (key) =>
      key?.use === "enc" &&
      key?.kty === "EC" &&
      key?.crv === "P-256" &&
      typeof key.kid === "string" &&
      key.kid.length > 0 &&
      typeof key.alg === "string" &&
      RFC002_JWE_ALGS.has(key.alg),
  ) || null;
}

export function assertVerifierEncryptionKeyPair({ publicJwk, privateKeyPem } = {}) {
  if (!publicJwk || publicJwk.kty !== "EC" || publicJwk.crv !== "P-256") {
    throw new Error("Verifier encryption metadata must advertise an EC P-256 public key");
  }
  const derived = publicJwkFromPrivate(privateKeyPem);
  if (derived.kty !== publicJwk.kty || derived.crv !== publicJwk.crv ||
      derived.x !== publicJwk.x || derived.y !== publicJwk.y) {
    throw new Error(`Verifier encryption key mismatch for kid "${publicJwk.kid || "unknown"}"`);
  }
  return { kid: publicJwk.kid, alg: publicJwk.alg, publicJwk, derivedPublicJwk: derived };
}

export function loadVerifierEncryptionKey({
  metadataPath = "./data/verifier-config.json",
  privateKeyPath = KEY_MATERIAL_PATHS.verifierEncryptionPrivateKey,
} = {}) {
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  const publicJwk = selectVerifierEncryptionJwk(metadata);
  if (!publicJwk) {
    throw new Error("Verifier metadata has no supported encryption JWK");
  }
  const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
  return {
    ...assertVerifierEncryptionKeyPair({ publicJwk, privateKeyPem }),
    privateKeyPem,
  };
}
