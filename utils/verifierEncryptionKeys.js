import fs from "fs";
import crypto from "crypto";
import { selectCs02VerifierEncryptionJwk } from "./cs02TrustPolicy.js";

function publicJwkFromPrivate(privateKeyPem) {
  return crypto.createPublicKey(privateKeyPem).export({ format: "jwk" });
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
  privateKeyPath = "./x509EC/ec_private_pkcs8.key",
} = {}) {
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  const publicJwk = selectCs02VerifierEncryptionJwk(metadata);
  if (!publicJwk) throw new Error("Verifier metadata has no supported encryption JWK");
  const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
  return {
    ...assertVerifierEncryptionKeyPair({ publicJwk, privateKeyPem }),
    privateKeyPem,
  };
}

