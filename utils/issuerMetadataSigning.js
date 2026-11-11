import * as jose from "jose";
import { loadVerifierP12 } from "./cryptoUtils.js";

export const SIGNED_ISSUER_METADATA_TYP = "openidvci-issuer-metadata+jwt";

function requireEs256Material({ privateKeyPkcs8, certChain }) {
  if (typeof privateKeyPkcs8 !== "string" || !privateKeyPkcs8.includes("PRIVATE KEY")) {
    throw new Error("Issuer metadata signing material does not contain a PKCS#8 private key");
  }
  if (!Array.isArray(certChain) || certChain.length < 1 || certChain.some((cert) => !cert)) {
    throw new Error(
      "Issuer metadata signing requires an x5c chain with a leaf certificate"
    );
  }
}

/**
 * Produce OpenID4VCI signed Credential Issuer metadata.
 * The wallet validates the `sub`, `iat`, JOSE type, signature, and x5c chain.
 */
export async function signCredentialIssuerMetadata(metadata, signingMaterial) {
  const issuer = metadata?.credential_issuer;
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new Error("Credential Issuer metadata must contain credential_issuer before signing");
  }
  requireEs256Material(signingMaterial);

  const { privateKeyPkcs8, certChain } = signingMaterial;
  const payload = {
    ...metadata,
    sub: issuer,
    iat: Math.floor(Date.now() / 1000),
  };

  return new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: SIGNED_ISSUER_METADATA_TYP,
      x5c: certChain,
    })
    .sign(await jose.importPKCS8(privateKeyPkcs8, "ES256"));
}

export async function signCredentialIssuerMetadataFromConfiguredP12(metadata) {
  const p12Path = process.env.ISSUER_METADATA_SIGNING_P12_PATH;
  return signCredentialIssuerMetadata(
    metadata,
    // An explicit metadata bundle supplies its own chain. The implicit legacy
    // bundle still uses the verifier CA configuration.
    loadVerifierP12({ p12Path, appendVerifierCa: !p12Path })
  );
}
